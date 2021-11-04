import json
from pathlib import Path

import boto3
import jsonschema
import pytest


def load_data(filename, location="unit"):
    path = Path(__file__).parent / location / "data" / filename
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


def write_data(filename, data, location="unit"):
    fpath = Path(__file__).parent / location / "data" / filename
    if not fpath.exists():
        fpath.write_text(data)


@pytest.fixture()
def validate():
    def schema_validate(translator, resource):
        schema_path = f"schema.{translator.tf_type}.json"
        schema = load_data(schema_path)
        if schema is None:
            cfn = boto3.client("cloudformation")
            rtype = cfn.describe_type(TypeName=translator.cfn_type, Type="RESOURCE")
            schema = json.loads(rtype["Schema"])
            write_data(schema_path, json.dumps(schema, indent=2))

        props = set(resource)
        sprops = set(schema["properties"].keys())
        unknown = props.difference(sprops)
        if unknown:
            raise KeyError("unknown resource keys %s" % (", ".join(unknown)))

        validator = jsonschema.Draft7Validator(schema)

        errors = list(validator.iter_errors(resource))
        if errors:
            print("%s errors %d" % (translator.cfn_type, len(errors)))

        for e in errors:
            print("Resource %s error:\n %s" % (translator.cfn_type, str(e)))

        if errors:
            raise ValueError(
                f"resource type {translator.cfn_type} had translation errors"
            )

    return schema_validate
