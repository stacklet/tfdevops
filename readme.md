# tfdevops

Terraform support for Amazon DevOps Guru. The service natively only supports AWS CloudFormation stacks.
https://aws.amazon.com/devops-guru/features/

This project provides support for terraform users by automatically
converting terraform state to an imported CloudFormation stack
and optionally enabling it with DevOps guru.

Note Amazon DevOps Guru only supports roughly 25 resources.
https://aws.amazon.com/devops-guru/pricing/


## How it works

- Translates terraform state into a CloudFormation template with a retain deletion policy
- Creates a CloudFormation stack with imported resources
- Enrolls the stack into Amazon DevOps Guru

## Usage

Install it.

```
pip install tfdevops
```

You've got a deployed terraform root module extant, let's generate a CloudFormation template and a set of importable resources for it

```
tfdevops cfn -d ~/path/to/terraform/module --template mycfn.json --resources importable-ids.json
```


And now we can go ahead and create a CloudFormation stack, import resources, and activate DevOps Guru on our stack.

```
tfdevops deploy --template mycfn.json --resources importable-ids.json
...
INFO:tfdevops:Found existing stack, state:IMPORT_COMPLETE
INFO:tfdevops:Creating import change set, 8 resources to import
INFO:tfdevops:Executing change set to import resources
INFO:tfdevops:Waiting for import to complete
INFO:tfdevops:Cloudformation Stack Deployed - Terraform resources imported
```

You can now visit the stack in the DevOps Guru dashboard.

Depending on the level activity of the resources it can take DevOps Guru a few hours to generate any actionable insight.


As a bonus, we can validate the generated template (or any other pure CloudFormation template, aka sans intrinsics funcs or vars ), with the following
command, which will download the jsonschema for the various resource types and validate each template resource against its schema.

```
tfdevops validate --template mycfn.json
```

## Large Resource/Templates

AWS CloudFormation has various size limitations (50k api upload, 500k s3 upload) on the resource size it supports, both the `gen` and `deploy` subcommands support passing
in an s3 path for the template and some resources which have larger configuration (step function workflows, etc). Note the s3 path for deploy is the actual template
path.

## FAQ

1. Is this a generic terraform to CloudFormation converter?

No, while it has some facilities that resemble that, its very targeted at simply producing enough cfn to make Amazon DevOps Guru work.

## Supported resources


At the moment tfdevops supports the following resources

 - AWS::StepFunctions::StateMachine
 - AWS::ECS::Service
 - AWS::SQS::Queue
 - AWS::SNS::Topic
 - AWS::RDS::DBInstance
 - AWS::Lambda::Function
 - AWS::Events::Rule
 - AWS::DynamoDB::Table