import json

import boto3
from botocore.exceptions import ClientError, WaiterError
from botocore.waiter import WaiterModel, create_waiter_with_client

from .resource import Translator
from .utils import filter_empty, get_state_resources, log

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


def get_cfn_template(s3_client, s3_path, module, state_file, types):
    state = get_state_resources(module, state_file)

    ctemplate = {
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
        if k not in translators:
            log.debug("no cfn type for tf %s" % k)
            continue

        translator_class = translators.get(k)
        cfn_type = translator_class.cfn_type
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
            props = filter_empty(props)
            ctemplate["Resources"][rname] = {
                "Type": cfn_type,
                "DeletionPolicy": "Retain",
                "Properties": props,
            }

            ids.append(
                {
                    "ResourceType": cfn_type,
                    "LogicalResourceId": rname,
                    "ResourceIdentifier": translator.get_identity(r),
                }
            )
    return ctemplate, ids


def deploy(
    stack_name, stack_content, template_url, import_resources, change_name, guru=True
):
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
    elif stack_content:
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
