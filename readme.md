# tfdevops

Terraform support for AWS DevOps Guru.

This service team for whatever reason only supports cloudformation, meaning its useless
to the majority of AWS users.

This project provides support for terraform centric organizations to use it by automatically
converting terraform state to an imported cloudformation stack.

It also corrects a major usability defect of cloudformation, by providing client side schema validation
of templates.

Enjoy.


## Resource Support


```text
API Gateway : API Path/Route
Kinesis : Stream
Application ELB : LoadBalancer
NATGateway (VPC ) : NatGateway
CloudFront : Distribution
Network ELB : LoadBalancer
DynamoDB Streams : Stream
RDS : DBInstance
DynamoDB : Table
Redshift : Cluster, Node
EC2(ASG):Instance*
Route 53 : HostedZone
ECS : Service
SageMaker : InvocationEndpoint
EKS : Service
SNS : Topic
Elastic Beanstalk : Environment
SQS : Queue
ElastiCache : Node	
Step Functions : Activity, StateMachine
Elasticsearch : Node	
SWF : Workflow, Task
ELB : LoadBalancer
Lambda : Function	 
S3 : Bucket
```
