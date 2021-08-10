# tfdevops

Terraform support for AWS DevOps Guru.
https://aws.amazon.com/devops-guru/features/


Unfortunately the DevOps Guru service team only supports app level stack enablement via cloudformation, meaning its useless
to the majority of AWS users.

This project provides support for terraform centric organizations to use it by automatically
converting terraform state to an imported cloudformation stack and optionally enabling it with devops guru.

Note it only supports roughly 25 resources per the pricing page.
https://aws.amazon.com/devops-guru/pricing/


tfdevops also corrects a major usability issue of cloudformation, by providing client side schema validation
of templates.

Enjoy.

## Usage

Install it.

```
pip install tfdevops
```

You've got a deployed terraform root module extant, let's generate a cloudformation template and a set of importable resources for it

```
tfdevops cfn -d ~/path/to/terraform/module --template mycfn.json --resources importable-ids.json
```


And now we can go ahead and create a cloudformation stack, import resources, and activate devops guru on our stack.

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

Depending on the level activity of the resources it can DevOps Guru a few hours to generate any actionable insight.


As a bonus, we can validate the generated template (or any other pure cloudformation template, aka sans intrinsics funcs or vars ), with the following
command, which will download the jsonschema for the various resource types and validate each template resource against its schema.

```
tfdevops validate --template mycfn.json
```

## Large Resource/Templates

Cloudformation has various size limitations (50k api upload, 500k s3 upload) on the resource size it supports, both the `gen` and `deploy` subcommands support passing
in an s3 path for the template and some resources which have larger configuration (step function workflows, etc). Note the s3 path for deploy is the actual template
path.

## FAQ

1. Is this a generic terraform to cloudformation converter?

No, while it has some facilities that resemble that, its very targeted at simply producing enough cfn to make devops guru work.
