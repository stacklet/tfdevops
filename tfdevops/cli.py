import boto3
import click
import json
import jsonschema
import jmespath
import logging
from pathlib import Path
import subprocess
import hcl2


log = logging.getLogger("tfdevops")


@click.group()
def cli():
    """Terraform to AWS DevOps Guru"""
    logging.basicConfig(level=logging.INFO)


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

    for logical_id, resource in data.get("Resources", {}).items():
        rmeta = type_schema_map[resource["Type"]]
        props = set(resource["Properties"])
        sprops = set(rmeta["schema"]["properties"].keys())
        unknown = props.difference(sprops)
        if unknown:
            log.warning(
                "%s -> %s unknown props %s" % (logical_id, resource["Type"], unknown)
            )
            # continue

        errors = list(rmeta["validator"].iter_errors(resource["Properties"]))
        if errors:
            log.warning(
                "%s -> %s errors %d" % (logical_id, resource["Type"], len(errors))
            )
        for e in errors:
            log.warning(str(e))
            break


@cli.command()
@click.option("-d", "--module", required=True)
@click.option("-o", "--output", type=click.File("w"), default="-")
@click.option("-r", "--resources", type=click.File("w"))
@click.option("-t", "--types", multiple=True)
def cfn(module, output, resources, types):
    """Export a cloudformation template"""
    state = get_state_resources(module)
    type_map = get_type_mapping()

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "TF to CFN Guru Meditation Ops",
        "Resources": {},
    }
    translators = Translator.get_translator_map()
    ids = []

    for k, v in state.items():
        provider, k = k.split("_", 1)
        if types and k not in types:
            continue
        if k not in type_map:
            log.warning("no cfn type for tf %s" % k)
            continue
        cfn_type = type_map[k]
        translator_class = translators.get(k)
        if not translator_class:
            log.info("no translator for %s" % k)
            continue
        else:
            translator = translator_class()

        for r in v:
            rname = translator.get_name(r)
            if rname in template["Resources"]:
                log.warning("resource override %s" % rname)
                rname = "%s%s" % (rname, cfn_type.split("::")[-1])
            props = translator.get_properties(r)
            if props is None:
                continue
            template["Resources"][rname] = {
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

    output.write(json.dumps(template))

    if resources:
        resources.write(json.dumps(ids, indent=2))


def get_type_mapping():
    with open(Path(__file__).parent / "type_map.json") as fh:
        return json.load(fh)


def get_state_resources(tf_dir):
    output = subprocess.check_output(["terraform", "show", "-json"], cwd=tf_dir)
    state = json.loads(output)
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


class Translator:

    id = None
    tf_type = None
    strip = ()
    rename = {}
    flatten = ()

    @classmethod
    def get_translator_map(cls):
        d = {}
        for scls in cls.__subclasses__():
            if scls.tf_type:
                d[scls.tf_type] = scls
        return d

    def get_name(self, r):
        return self._camel_str(r["name"])

    def get_sub_resources(self, r):
        return

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
    }

    def get_identity(self, r):
        return {self.id: r["values"]["identifier"]}

    def get_properties(self, tf):
        cfr = super().get_properties(tf)
        cfr["Port"] = str(cfr["Port"])


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


class Sqs(Translator):

    tf_type = "sqs_queue"
    id = "QueueUrl"
    strip = ("url", "policy", "fifo_throughput_limit", "deduplication_scope")
    rename = {
        "max_message_size": "MaximumMessageSize",
        "name": "QueueName",
        "message_retention_seconds": "MessageRetentionPeriod",
        "visibility_timeout_seconds": "VisibilityTimeout",
    }

    def get_identity(self, r):
        return {self.id: r["values"]["url"]}

    def get_properties(self, tf):
        cfr = super().get_properties(tf)
        if "RedrivePolicy" in cfr:
            cfr["RedrivePolicy"] = json.loads(cfr["RedrivePolicy"])
        return cfr

    def get_sub_resources(self, tfr):
        p = tfr["values"].get("policy")
        if not p:
            return
        return {
            "%sPolicy"
            % self._camel_str(tfr["name"]): {
                "Type": "AWS::SQS::QueuePolicy",
                "Queues": [tfr["values"]["url"]],
                "PolicyDocument": p,
            }
        }


class Topic(Translator):

    tf_type = "sns_topic"
    id = "TopicArn"
    strip = ("policy", "owner")
    rename = {"name": "TopicName"}

    def get_sub_resources(self, tfr):
        p = tfr["values"].get("policy")
        if not p:
            return
        return {
            "%sPolicy"
            % self._camel_str(tfr["name"]): {
                "Type": "AWS::SNS::TopicPolicy",
                "Topics": [tfr["values"]["arn"]],
                "PolicyDocument": p,
            }
        }

    def get_identity(self, r):
        return {self.id: r["values"]["arn"]}


class Lambda(Translator):

    tf_type = "lambda_function"
    id = "FunctionName"
    flatten = ("environment", "tracing_config")
    strip = (
        "version",
        "policy",
        "source_code_size",
        "source_code_hash",
        "qualified_arn",
        "filename",
        "invoke_arn",
        "last_modified",
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
        return cfr


class StateMachine(Translator):

    # tf_type = "sfn_state_machine"
    id = "Arn"
    strip = (
        # "definition",
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
    try:
        cli()
    except SystemExit:
        raise
    except Exception:
        import traceback, pdb, sys

        traceback.print_exc()
        pdb.post_mortem(sys.exc_info()[-1])
