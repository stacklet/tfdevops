import json

from .utils import write_s3_key


class Translator:

    id = None
    tf_type = None
    strip = ()
    rename = {}
    flatten = ()

    def __init__(self, config=None):
        self.config = config

    @classmethod
    def get_translator(cls, tf_type):
        return cls.get_translator_map()[tf_type]

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

    def get_tags(self, tag_map):
        return [{"Key": k, "Value": v} for k, v in tag_map.items()]

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
    cfn_type = "AWS::Events::Rule"

    id = "Name"

    def get_properties(self, r):
        cfr = super().get_properties(r)
        cfr["State"] = cfr.pop("IsEnabled") is True and "ENABLED" or "DISABLED"

        if cfr.get("EventBusName") != "Default":
            return None

        return cfr


class DbInstance(Translator):

    tf_type = "db_instance"
    cfn_type = "AWS::RDS::DBInstance"
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


class ElasticacheReplicationGroup(Translator):

    tf_type = "elasticache_replication_group"
    cfn_type = "AWS::ElastiCache::ReplicationGroup"

    id = "ReplicationGroupId"
    rename = {
        "subnet_group_name": "CacheSubnetGroupName",
        "maintenance_window": "PreferredMaintenanceWindow",
        "number_cache_clusters": "NumCacheClusters",
        "node_type": "CacheNodeType",
        "parameter_group_name": "CacheParameterGroupName",
    }
    strip = (
        "primary_endpoint_address",
        "reader_endpoint_address",
        "member_clusters",
        "engine_version_actual",
        "apply_immediately",
        "cluster_mode",
    )


class EcsService(Translator):

    tf_type = "ecs_service"
    cfn_type = "AWS::ECS::Service"

    id = "ServiceName"
    flatten = ("network_configuration", "deployment_controller")
    rename = {
        "iam_role": "Role",
        "enable_ecs_managed_tags": "EnableECSManagedTags",
        "cluster": "Cluster",
    }
    strip = (
        "deployment_circuit_breaker",
        "propagate_tags",
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
    cfn_type = "AWS::SQS::Queue"

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
    cfn_type = "AWS::SNS::Topic"

    id = "TopicArn"
    strip = ("policy", "owner")
    rename = {"name": "TopicName"}

    def get_identity(self, r):
        return {self.id: r["values"]["arn"]}


class KinesisStream(Translator):

    tf_type = "kinesis_stream"
    cfn_type = "AWS::Kinesis::Stream"
    id = "Name"
    strip = ("shard_level_metrics", "encryption_type")
    rename = {"retention_period": "RetentionPeriodHours"}

    def get_properties(self, tfr):
        cfr = super().get_properties(tfr)
        cfr["Tags"] = self.get_tags(cfr.get("Tags", {}))
        return cfr


class Lambda(Translator):

    tf_type = "lambda_function"
    cfn_type = "AWS::Lambda::Function"

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
        cfr["Tags"] = self.get_tags(tfr["values"].get("Tags", {}))
        if "VpcConfig" in cfr:
            cfr["VpcConfig"].pop("VpcId")
        return cfr


class Elbv2(Translator):

    tf_type = "lb"
    cfn_type = "AWS::ElasticLoadBalancingV2::LoadBalancer"
    id = "LoadBalancerArn"
    rename = {"subnet_mapping": "SubnetMappings", "load_balancer_type": "Type"}
    strip = ("dns_name", "arn_suffix", "access_logs", "vpc_id", "zone_id")

    attributes = {
        "IdleTimeout": "idle_timeout.timeout_seconds",
        "EnableHttp2": "routing.http2.enabled",
    }

    def get_identity(self, r):
        return {self.id: r["values"]["id"]}

    def get_properties(self, tfr):
        cfr = super().get_properties(tfr)
        for k, v in self.attributes.items():
            cv = cfr.pop(k)
            if cv is None:
                continue
            cfr.setdefault("LoadBalancerAttributes", []).append(
                {"Key": v, "Value": cv and "true" or "false"}
            )

        subs = []
        for sub in cfr.get("SubnetMappings", ()):
            sub = self.filter_empty(sub)
            subs.append(self.camel(sub))
        cfr["SubnetMappings"] = subs
        return cfr


class StateMachine(Translator):

    tf_type = "sfn_state_machine"
    cfn_type = "AWS::StepFunctions::StateMachine"

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
    cfn_type = "AWS::DynamoDB::Table"

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
