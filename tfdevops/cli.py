# Copyright Stacklet, Inc.
# SPDX-License-Identifier: Apache-2.0
#
import json
import logging
import os
import subprocess
from urllib import parse

import boto3
import click
import jmespath
import jsonschema
from botocore.exceptions import ClientError, WaiterError
from botocore.waiter import WaiterModel, create_waiter_with_client

__author__ = "Kapil Thangavelu <https://twitter.com/kapilvt>"

log = logging.getLogger("tfdevops")

DEFAULT_STACK_NAME = "GuruStack"
DEFAULT_CHANGESET_NAME = "GuruImport"
DEFAULT_S3_ENCRYPT = os.environ.get("TFDEVOPS_S3_ENCRYPT", "AES256")

# manually construct waiter models for change sets since the service
# team didn't bother to publish one in their smithy models, perhaps
# understandbly since one only needs these for unhappy paths.
# re smithy https://awslabs.github.io/smithy/

ChangeSetWaiters = {
    "version": 2,
    "waiters": {
        "ChangeSetDeleteComplete": {
            "operation": "DescribeChangeSet",
            "delay": 10,
            "maxAttempts": 40,
            "acceptors": [
                {
                    "expected": "DELETE_FAILED",
                    "matcher": "path",
                    "state": "failure",
                    "argument": "Status",
                },
                {
                    "expected": "DELETE_COMPLETE",
                    "matcher": "path",
                    "argument": "Status",
                    "state": "success",
                },
            ],
        },
        "ChangeSetExecuteComplete": {
            "operation": "DescribeChangeSet",
            "delay": 10,
            "maxAttempts": 40,
            "acceptors": [
                {
                    "expected": "EXECUTE_FAILED",
                    "matcher": "path",
                    "state": "failure",
                    "argument": "ExecutionStatus",
                },
                {
                    "expected": "EXECUTE_COMPLETE",
                    "matcher": "path",
                    "argument": "ExecutionStatus",
                    "state": "success",
                },
            ],
        },
    },
}


@click.group()
@click.option("-v", "--verbose", is_flag=True)
def cli(verbose):
    """Terraform to Cloudformation and AWS DevOps Guru"""
    logging.basicConfig(level=verbose and logging.DEBUG or logging.INFO)
    if verbose:
        logging.getLogger("botocore").setLevel(logging.INFO)
        logging.getLogger("urllib3").setLevel(logging.INFO)


@cli.command()
@click.option("-t", "--template", type=click.File("r"))
@click.option("-r", "--resources", type=click.File("r"), required=True)
@click.option("-u", "--template-url", help="s3 path to template")
@click.option("-s", "--stack-name", default=DEFAULT_STACK_NAME)
@click.option("--change-name", default=DEFAULT_CHANGESET_NAME)
@click.option("--guru", is_flag=True, default=False)
def deploy(template, resources, stack_name, guru, template_url, change_name):
    """Deploy a cloudformation stack with imported resources

    Imports terraform resources into a cloudformation stack.

    Consumes outputs of cfn generation subcommand.

    Specify --guru flag to automatically enable Amazon DevOps Guru.
    """
    if not template and not template_url:
        raise SyntaxError("Either template or template_url parameter must be passed")
    if template:
        stack_content = json.load(template)
    import_resources = json.load(resources)
    client = boto3.client("cloudformation")

    try:
        stack_info = client.describe_stacks(StackName=stack_name)["Stacks"][0]
        log.info("Found existing stack, state:%s", stack_info["StackStatus"])
    except ClientError:
        # somewhat annoying the service team hasn't put a proper customized
        # exception in place for a common error issue. ala they have one for
        # client.exceptions.StackNotFoundException but didn't bother
        # to actually use it for this, or its histerical raison compatibility.
        # This unfortunately means we have to catch a very generic client error.
        # ie. we're trying to catch errors like this.
        #  botocore.exceptions.ClientError: An error occurred (ValidationError) when
        #  calling the DescribeStacks operation: Stack with id GuruStack does not exist
        stack_info = None

    # so for each stack and each resource we have to deal with the complexity
    # of cfn's underlying state workflow for each, as outlined by the internal state
    # machine complexity.
    #
    # This is a great example of why terraform represent's sanity, as well how
    # customer feedback driven product development (aka we want rollback) can lead
    # to a worse experience for customers, if one doesn't keep the bigger picture in mind.
    #
    # It also leads to brittleness and complexity for any tool building on
    # cloudformation, exhibit A being the unusability of stacksets in the
    # real world.
    #
    # Its gets worse when you consider the compatibility complexity matrix
    # on the various versions and bugs, like the lack of a proper error code
    # for stack not found above.
    #
    # Nonetheless, we persevere and try to present a humane interface.
    #
    # Stack State Enumeration:
    # CREATE_COMPLETE
    # CREATE_FAILED
    # CREATE_IN_PROGRESS
    # DELETE_COMPLETE
    # DELETE_FAILED
    # DELETE_IN_PROGRESS
    # IMPORT_COMPLETE
    # IMPORT_IN_PROGRESS
    # IMPORT_ROLLBACK_COMPLETE
    # IMPORT_ROLLBACK_FAILED
    # IMPORT_ROLLBACK_IN_PROGRESS
    # REVIEW_IN_PROGRESS
    # ROLLBACK_COMPLETE
    # ROLLBACK_FAILED
    # ROLLBACK_IN_PROGRESS
    # UPDATE_COMPLETE
    # UPDATE_COMPLETE_CLEANUP_IN_PROGRESS
    # UPDATE_IN_PROGRESS
    # UPDATE_ROLLBACK_COMPLETE
    # UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS
    # UPDATE_ROLLBACK_FAILED
    # UPDATE_ROLLBACK_IN_PROGRESS

    if stack_info and stack_info["StackStatus"] == "ROLLBACK_COMPLETE":
        log.info("Deleting failed stack")
        client.delete_stack(StackName=stack_name)
        waiter = client.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name)
        stack_info = None
    elif stack_info and stack_info["StackStatus"] == "REVIEW_IN_PROGRESS":
        pass
    elif stack_info and stack_info["StackStatus"].endswith("IN_PROGRESS"):
        log.info(
            "Cloudformation stack undergoing change %s, please try again later",
            stack_info["StackStatus"],
        )
        return
    elif stack_info and stack_info["StackStatus"] == "DELETE_COMPLETE":
        stack_info = None
    elif stack_info:
        stack_resources = {
            sr["LogicalResourceId"]
            for sr in client.describe_stack_resources(StackName=stack_name).get(
                "StackResources", []
            )
        }
        import_resources = [
            i for i in import_resources if i["LogicalResourceId"] not in stack_resources
        ]
        if not import_resources:
            log.info("All resources have already been imported")
            return

    # Check for an extant change set
    try:
        cinfo = client.describe_change_set(
            StackName=stack_name, ChangeSetName=change_name
        )
    except (client.exceptions.ChangeSetNotFoundException, ClientError):
        cinfo = None

    if cinfo and cinfo["Status"] == "FAILED":
        log.warning(
            "Previous change set failed with reason %s", cinfo.get("StatusReason", "")
        )
        client.delete_change_set(StackName=stack_name, ChangeSetName=change_name)
        waiter = create_waiter_with_client(
            "ChangeSetDeleteComplete", WaiterModel(ChangeSetWaiters), client
        )
        try:
            waiter.wait(
                StackName=stack_name,
                ChangeSetName=change_name,
                WaiterConfig={"Delay": 10, "MaxAttempts": 60},
            )
        except WaiterError as e:
            if (
                "Error" in e.last_response
                and e.last_response["Error"]["Code"] == "ChangeSetNotFound"
            ):
                # happy path instant delete
                pass
            else:
                raise

    log.info(
        "Creating import change set, %d resources to import", len(import_resources)
    )
    params = dict(
        StackName=stack_name,
        ChangeSetType="IMPORT",
        Capabilities=["CAPABILITY_NAMED_IAM"],
        ChangeSetName=change_name,
        ResourcesToImport=import_resources,
    )
    if template_url:
        params["TemplateURL"] = template_url
    elif template:
        params["TemplateBody"] = json.dumps(stack_content)

    # returns ids which are mostly useless, because we have to use unique at moment names in the api
    client.create_change_set(**params)

    # Change Set States
    # CREATE_COMPLETE
    # CREATE_IN_PROGRESS
    # CREATE_PENDING
    # DELETE_COMPLETE
    # DELETE_FAILED
    # DELETE_IN_PROGRESS
    # DELETE_PENDING
    # FAILED

    waiter = client.get_waiter("change_set_create_complete")
    try:
        waiter.wait(
            StackName=stack_name,
            ChangeSetName=change_name,
            WaiterConfig={"Delay": 10, "MaxAtempts": 60},
        )
    except WaiterError as e:
        log.error(
            "Changeset creation failed status: %s reason: %s",
            e.last_response["Status"],
            e.last_response["StatusReason"],
        )
        return

    log.info("Executing change set to import resources")
    client.execute_change_set(ChangeSetName=change_name, StackName=stack_name)

    # Aha changesets have another state workflow representing execution progress
    # AVAILABLE
    # EXECUTE_COMPLETE
    # EXECUTE_FAILED
    # EXECUTE_IN_PROGRESS
    # OBSOLETE
    # UNAVAILABLE

    waiter = create_waiter_with_client(
        "ChangeSetExecuteComplete", WaiterModel(ChangeSetWaiters), client
    )
    try:
        waiter.wait(
            StackName=stack_name,
            ChangeSetName=change_name,
            WaiterConfig={"Delay": 10, "MaxAttempts": 60},
        )
    except WaiterError as e:
        # the happy path is a changeset executes really quickly and disappears while the status of
        # stack itself reflects the actual async progress. lulz, we do a waiter because
        # who knows the other 1% of the times, because the cfn exposed model of change set
        # suggests it may have other states, rather than instantly disappearing on execution.
        if (
            "Error" in e.last_response
            and e.last_response["Error"]["Code"] == "ChangeSetNotFound"
        ):
            # common happy path, change set disappears before change is complete :/
            pass
        else:
            raise

    # but now we have to wait for the stack status to reflect back on steady state
    waiter = client.get_waiter("stack_import_complete")
    log.info("Waiting for import to complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 15, "MaxAttempts": 100})

    log.info("Cloudformation Stack Deployed - Terraform resources imported")
    if guru:
        log.info("Enrolling terraform stack into devops guru")
        guru = boto3.client("devops-guru")
        guru.update_resource_collection(
            Action="ADD",
            ResourceCollection={"CloudFormation": {"StackNames": [stack_name]}},
        )


@cli.command()
@click.option("-t", "--template", type=click.File("r"))
def validate(template):
    """validate resources in a template per their jsonschema def"""
    data = json.load(template)
    rtypes = set()
    for logical_id, resource in data.get("Resources", {}).items():
        rtypes.add(resource["Type"])

    type_schema_map = {}
    client = boto3.client("cloudformation")
    for r in rtypes:
        rinfo = client.describe_type(TypeName=r, Type="RESOURCE")
        schema = json.loads(rinfo["Schema"])
        type_schema_map[r] = {
            "validator": jsonschema.Draft7Validator(schema),
            "schema": schema,
        }

    template_error = False
    for logical_id, resource in data.get("Resources", {}).items():
        rmeta = type_schema_map[resource["Type"]]
        props = set(resource["Properties"])
        sprops = set(rmeta["schema"]["properties"].keys())
        unknown = props.difference(sprops)
        if unknown:
            log.warning(
                "%s -> %s unknown props %s" % (logical_id, resource["Type"], unknown)
            )

        errors = list(rmeta["validator"].iter_errors(resource["Properties"]))
        if errors:
            log.warning(
                "%s -> %s errors %d" % (logical_id, resource["Type"], len(errors))
            )
            template_error = True
        for e in errors:
            log.warning("Resource %s error:\n %s" % (logical_id, str(e)))
    if template_error is False:
        log.info("Congratulations! - the template validates")


@cli.command()
@click.option("-d", "--module", help="Terraform root module directory")
@click.option(
    "-t",
    "--template",
    type=click.File("w"),
    default="-",
    help="Cloudformation template output path",
)
@click.option(
    "-r",
    "--resources",
    type=click.File("w"),
    help="Output file for resources to import",
)
@click.option(
    "--s3-path",
    help="S3 Bucket and Prefix (s3://bucket/pre/fix) for oversized templates and resources",
)
@click.option(
    "--state-file",
    help="Terraform state file - output of terraform show -json",
)
@click.option("--types", multiple=True, help="Only consider these terraform types")
def cfn(module, template, resources, types, s3_path, state_file):
    """Export a cloudformation template and importable resources

    s3 path only needs to be specified when handling resources with verbose
    definitions (step functions) or a large cardinality of resources which would
    overflow cloudformation's api limits on templates (50k).
    """
    state = get_state_resources(module, state_file)
    type_map = TF_CFN_MAP

    ctemplate = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "TF to CFN Guru Meditation Ops",
        "Resources": {},
    }
    translators = Translator.get_translator_map()
    ids = []

    s3_client = s3_path and boto3.client("s3")
    for k, v in state.items():
        provider, k = k.split("_", 1)
        if types and k not in types:
            continue
        if k not in type_map:
            log.debug("no cfn type for tf %s" % k)
            continue
        cfn_type = type_map[k]
        translator_class = translators.get(k)
        if not translator_class:
            log.debug("no translator for %s" % k)
            continue
        else:
            translator = translator_class({"s3_path": s3_path, "s3": s3_client})

        for r in v:
            rname = translator.get_name(r)
            if rname in ctemplate["Resources"]:
                log.debug("resource override %s" % rname)
                rname = "%s%s" % (rname, cfn_type.split("::")[-1])
            props = translator.get_properties(r)
            if props is None:
                continue
            ctemplate["Resources"][rname] = {
                "Type": cfn_type,
                "DeletionPolicy": "Retain",
                "Properties": props,
            }
            if resources:
                ids.append(
                    {
                        "ResourceType": cfn_type,
                        "LogicalResourceId": rname,
                        "ResourceIdentifier": translator.get_identity(r),
                    }
                )

    # overflow to s3 for actual deployment on large templates
    serialized_template = json.dumps(ctemplate).encode("utf8")

    if s3_path:  # and len(serialized_template) > 49000:
        s3_url = format_template_url(
            s3_client,
            format_s3_path(
                write_s3_key(
                    s3_client, s3_path, "%s.json" % DEFAULT_STACK_NAME, ctemplate
                )
            ),
        )
        log.info("wrote s3 template url: %s", s3_url)
    elif len(serialized_template) > 49000:
        log.warning(
            "template too large for local deploy, pass --s3-path to deploy from s3"
        )

    template.write(json.dumps(ctemplate, indent=2))

    if resources:
        resources.write(json.dumps(ids, indent=2))


def get_state_resources(tf_dir, tf_state):
    if tf_dir:
        output = subprocess.check_output(["terraform", "show", "-json"], cwd=tf_dir)
        state = json.loads(output)
    elif tf_state:
        state = json.load(open(tf_state))
    else:
        raise SyntaxError("either --module or --state-file needs to be passed")

    state_resources = {}

    resources = jmespath.search("values.root_module.resources", state) or []
    mod_resources = (
        jmespath.search("values.root_module.child_modules[].resources[]", state) or ()
    )
    resources.extend(mod_resources)

    if not resources:
        log.info("empty state")

    for r in resources:
        if r["mode"] != "managed":
            continue
        tresources = state_resources.setdefault(r["type"], [])
        tresources.append(r)
    return state_resources


def write_s3_key(client, s3_path, key, content):
    kinfo = {}
    parsed = parse.urlparse(s3_path)
    kinfo["Bucket"] = parsed.netloc
    prefix = parsed.path.strip("/")
    kinfo["Key"] = "%s/%s" % (prefix, key)
    if not isinstance(content, str):
        content = json.dumps(content)
    result = client.put_object(
        Bucket=kinfo["Bucket"],
        Key=kinfo["Key"],
        # this is the default but i've seen some orgs try to force this via request policy checks
        ACL="private",
        ServerSideEncryption=DEFAULT_S3_ENCRYPT,
        Body=content,
    )
    if result.get("VersionId"):
        kinfo["Version"] = result["VersionId"]
    return kinfo


def format_s3_path(kinfo):
    t = "s3://{Bucket}/{Key}"
    if "Version" in kinfo:
        t += "?versionId={Version}"
    return t.format(**kinfo)


def format_template_url(client, s3_path):
    parsed = parse.urlparse(s3_path)
    bucket = parsed.netloc
    key = parsed.path.strip("/")
    version_id = None
    if parsed.query:
        query = parse.parse_qs(parsed.query)
        version_id = query.get("versionId", (None,))
    region = (
        client.get_bucket_location(Bucket=bucket).get("LocationConstraint")
        or "us-east-1"
    )
    url = "https://{bucket}.s3.{region}.amazonaws.com/{key}"
    if version_id:
        url += "?versionId={version_id}"
    return url.format(bucket=bucket, key=key, version_id=version_id, region=region)


TF_CFN_MAP = {
    "cloudwatch_event_rule": "AWS::Events::Rule",
    "db_instance": "AWS::RDS::DBInstance",
    "sns_topic": "AWS::SNS::Topic",
    "sqs_queue": "AWS::SQS::Queue",
    "lambda_function": "AWS::Lambda::Function",
    "sfn_state_machine": "AWS::StepFunctions::StateMachine",
    "cloudwatch_event_rule": "AWS::Events::Rule",
    "ecs_service": "AWS::ECS::Service",
    "dynamodb_table": "AWS::DynamoDB::Table",
}


class Translator:

    id = None
    tf_type = None
    strip = ()
    rename = {}
    flatten = ()

    def __init__(self, config):
        self.config = config

    @classmethod
    def get_translator_map(cls):
        d = {}
        for scls in cls.__subclasses__():
            if scls.tf_type:
                d[scls.tf_type] = scls
        return d

    def get_name(self, r):
        return self._camel_str(r["name"])

    def get_identity(self, r):
        return {self.id: r["values"]["name"]}

    def get_properties(self, tf):
        tfv = self.filter_empty(tf["values"])
        tfv.pop("id", None)
        tfv.pop("arn", None)
        tfv.pop("tags_all", None)
        for s in self.strip:
            tfv.pop(s, None)

        for f in self.flatten:
            if f in tfv and isinstance(tfv[f], list) and len(tfv[f]) >= 1:
                tfv[f] = tfv[f][0]

        renamed = {}
        for src, tgt in self.rename.items():
            if src not in tfv:
                continue
            v = tfv.pop(src)
            renamed[tgt] = v
        cf = self.camel(tfv)
        cf.update(renamed)
        return cf

    def filter_empty(self, d):
        r = {}
        for k, v in d.items():
            if v:
                r[k] = v
        return r

    def _camel_str(self, k):
        parts = [p.capitalize() for p in k.split("_")]
        return "".join(parts)

    def camel(self, d):
        r = {}

        for k, v in d.items():
            if isinstance(v, dict):
                v = self.camel(v)
            if isinstance(v, list) and v and isinstance(v[0], dict):
                v = [self.camel(i) for i in v]
            r[self._camel_str(k)] = v
        return r


class EventRuleTranslator(Translator):

    tf_type = "cloudwatch_event_rule"
    id = "Name"

    def get_properties(self, r):
        cfr = super().get_properties(r)
        cfr["State"] = cfr.pop("IsEnabled") is True and "ENABLED" or "DISABLED"

        if cfr.get("EventBusName") != "Default":
            return None

        return cfr


class DbInstance(Translator):

    tf_type = "db_instance"
    id = "DBInstanceIdentifier"
    strip = (
        "hosted_zone_id",
        "apply_immediately",
        "skip_final_snapshot",
        "backup_window",
        "maintenance_window",
        "resource_id",
        "address",
        "ca_cert_identifier",
        "status",
        "latest_restorable_time",
        "endpoint",
        "performance_insights_kms_key_id",  # tf allows key set when insights false
        "monitoring_interval",  # tf allows 0 value cfn does not
        "monitoring_role_arn",
        "timeouts",
        "engine_version_actual",
    )
    rename = {
        "username": "MasterUsername",
        "name": "DBName",
        "multi_az": "MultiAZ",
        "identifier": "DBInstanceIdentifier",
        "password": "MasterUserPassword",
        "instance_class": "DBInstanceClass",
        "vpc_security_group_ids": "VPCSecurityGroups",
        "db_subnet_group_name": "DBSubnetGroupName",
        "parameter_group_name": "DBParameterGroupName",
        "iam_database_authentication_enabled": "EnableIAMDatabaseAuthentication",
    }

    def get_identity(self, r):
        return {self.id: r["values"]["identifier"]}

    def get_properties(self, tf):
        cfr = super().get_properties(tf)
        cfr["Port"] = str(cfr["Port"])
        cfr["AllocatedStorage"] = str(cfr["AllocatedStorage"])
        return cfr


class EcsService(Translator):

    tf_type = "ecs_service"
    id = "ServiceName"
    flatten = ("network_configuration", "deployment_controller")
    rename = {"iam_role": "Role", "enable_ecs_managed_tags": "EnableECSManagedTags"}
    strip = (
        "deployment_circuit_breaker",
        "propagate_tags",
        "cluster",
        "deployment_maximum_percent",
        "deployment_minimum_healthy_percent",
    )

    def get_identity(self, r):
        return {"ServiceArn": r["values"]["id"], "Cluster": r["values"]["cluster"]}

    def get_properties(self, tf):
        cfr = super().get_properties(tf)
        network = cfr.pop("NetworkConfiguration")
        network["AssignPublicIp"] = (
            network.pop("AssignPublicIp") is True and "ENABLED" or "DISABLED"
        )
        cfr["NetworkConfiguration"] = {"AwsvpcConfiguration": network}
        return cfr


class Sqs(Translator):

    tf_type = "sqs_queue"
    id = "QueueUrl"
    strip = ("url", "policy", "fifo_throughput_limit", "deduplication_scope")
    rename = {
        "max_message_size": "MaximumMessageSize",
        "name": "QueueName",
        "message_retention_seconds": "MessageRetentionPeriod",
        "visibility_timeout_seconds": "VisibilityTimeout",
        "receive_wait_time_seconds": "ReceiveMessageWaitTimeSeconds",
    }

    def get_identity(self, r):
        return {self.id: r["values"]["url"]}

    def get_properties(self, tf):
        cfr = super().get_properties(tf)
        if "RedrivePolicy" in cfr:
            cfr["RedrivePolicy"] = json.loads(cfr["RedrivePolicy"])
        return cfr


class Topic(Translator):

    tf_type = "sns_topic"
    id = "TopicArn"
    strip = ("policy", "owner")
    rename = {"name": "TopicName"}

    def get_identity(self, r):
        return {self.id: r["values"]["arn"]}


class Lambda(Translator):

    tf_type = "lambda_function"
    id = "FunctionName"
    flatten = ("environment", "tracing_config", "vpc_config")
    strip = (
        "version",
        "policy",
        "source_code_size",
        "source_code_hash",
        "qualified_arn",
        "filename",
        "invoke_arn",
        "last_modified",
        "timeouts",
    )

    def get_identity(self, r):
        return {self.id: r["values"]["function_name"]}

    def get_properties(self, tfr):
        cfr = super().get_properties(tfr)
        if cfr["ReservedConcurrentExecutions"] == -1:
            cfr.pop("ReservedConcurrentExecutions")
        if tfr["values"].get("environment"):
            cfr["Environment"]["Variables"] = tfr["values"]["environment"][0][
                "variables"
            ]
        cfr["Code"] = {"ZipFile": tfr["values"]["filename"]}
        cfr["Tags"] = [
            {"Key": k, "Value": v} for k, v in tfr["values"].get("Tags", {}).items()
        ]
        if "VpcConfig" in cfr:
            cfr["VpcConfig"].pop("VpcId")
        return cfr


class StateMachine(Translator):

    tf_type = "sfn_state_machine"
    id = "Arn"
    strip = (
        "definition",
        "creation_date",
        "status",
        "logging_configuration",
        "tracing_configuration",
    )
    rename = {
        "name": "StateMachineName",
        "definition": "DefinitionString",
        "type": "StateMachineType",
    }

    def get_identity(self, r):
        return {self.id: r["values"]["arn"]}

    def get_properties(self, tf):
        cfr = super().get_properties(tf)
        if self.config["s3_path"]:
            kinfo = write_s3_key(
                self.config["s3"],
                self.config["s3_path"],
                "%s.json" % tf["name"],
                tf["values"]["definition"],
            )
            cfr["DefinitionS3Location"] = loc = {
                "Bucket": kinfo["Bucket"],
                "Key": kinfo["Key"],
            }
            if kinfo.get("Version"):
                loc["Version"] = kinfo["Version"]
        else:
            cfr["Definition"] = json.loads(tf["values"]["definition"])
        return cfr


class DynamodbTable(Translator):

    tf_type = "dynamodb_table"
    id = "TableName"
    rename = {"name": "TableName"}
    strip = (
        "ttl",
        "point_in_time_recovery",
        "stream_enabled",
        "server_side_encryption",
        "hash_key",
        "range_key",
        "stream_arn",
        "stream_label",
        "attribute",
        "timeouts",
    )

    def get_properties(self, tf):
        cfr = super().get_properties(tf)
        if tf["values"]["hash_key"]:
            cfr.setdefault("KeySchema", []).append(
                {"AttributeName": tf["values"]["hash_key"], "KeyType": "HASH"}
            )
        if tf["values"]["range_key"]:
            cfr.setdefault("KeySchema", []).append(
                {"AttributeName": tf["values"]["range_key"], "KeyType": "RANGE"}
            )
        if cfr.get("GlobalSecondaryIndex"):
            idxs = []
            for idx in cfr.pop("GlobalSecondaryIndex"):
                cidx = {"IndexName": idx["Name"]}
                cidx["Projection"] = {
                    "NonKeyAttributes": idx["NonKeyAttributes"],
                    "ProjectionType": idx["ProjectionType"],
                }
                cidx["KeySchema"] = [
                    {"KeyType": "RANGE", "AttributeName": idx["RangeKey"]},
                    {"KeyType": "HASH", "AttributeName": idx["HashKey"]},
                ]

                idxs.append(cidx)
            cfr["GlobalSecondaryIndexes"] = idxs
        attrs = []
        for a in tf["values"]["attribute"]:
            attrs.append({"AttributeName": a["name"], "AttributeType": a["type"]})
        cfr["AttributeDefinitions"] = attrs
        if cfr.get("StreamViewType"):
            cfr["StreamSpecification"] = {"StreamViewType": cfr.pop("StreamViewType")}

        if tf["values"].get("server_side_encryption"):
            sse = tf["values"]["server_side_encryption"][0]
            cfr["SSESpecification"] = {
                "SSEEnabled": sse["enabled"],
                "KMSMasterKeyId": sse["kms_key_arn"],
            }
        return cfr


if __name__ == "__main__":
    cli()
