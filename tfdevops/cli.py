# Copyright Stacklet, Inc.
# SPDX-License-Identifier: Apache-2.0
#
import json
import logging

import boto3
import click
import jsonschema

from . import cfn
from .utils import format_s3_path, format_template_url, log, write_s3_key

__author__ = "Kapil Thangavelu <https://twitter.com/kapilvt>"


DEFAULT_STACK_NAME = "GuruStack"
DEFAULT_CHANGESET_NAME = "GuruImport"


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
@click.option("--no-guru", is_flag=True, default=False)
def deploy(template, resources, stack_name, no_guru, template_url, change_name):
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
    cfn.deploy(stack_name, stack_content, template_url, import_resources, change_name)

    if no_guru is False:
        ensure_devops_guru(stack_name)


def ensure_devops_guru(stack_name):
    log.info("Enrolling terraform stack into devops guru")
    guru = boto3.client("devops-guru")
    guru.update_resource_collection(
        Action="ADD",
        ResourceCollection={"CloudFormation": {"StackNames": [stack_name]}},
    )


@cli.command()
@click.option("-t", "--template", type=click.File("r"), required=True)
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


@cli.command(name="cfn")
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
    "--state-file", help="Terraform state file - output of terraform show -json",
)
@click.option("--types", multiple=True, help="Only consider these terraform types")
def gen_cfn(module, template, resources, types, s3_path, state_file):
    """Export a cloudformation template and importable resources

    s3 path only needs to be specified when handling resources with verbose
    definitions (step functions) or a large cardinality of resources which would
    overflow cloudformation's api limits on templates (50k).
    """
    s3_client = s3_path and boto3.client("s3")
    ctemplate, ids = cfn.get_cfn_template(s3_client, s3_path, module, state_file, types)
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


if __name__ == "__main__":
    cli()
