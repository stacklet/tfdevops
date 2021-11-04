import json
from pathlib import Path
from tfdevops.cli import get_state_resources, Translator
from pytest_terraform import terraform

import conftest

def get_state_path(tmpdir, tf_resources):
    with open(tmpdir / 'state.json', 'w') as fh :
        fh.write(json.dumps(
            tf_resources.terraform.show(), indent=2))
    return fh.name


@terraform("aws_kinesis_stream")
def test_kinesis_stream(tmpdir, aws_kinesis_stream, validate):    
    resources = get_state_resources(None, get_state_path(tmpdir, aws_kinesis_stream))    
    translator = Translator.get_translator('kinesis_stream')()
    props = translator.get_properties(resources['aws_kinesis_stream'][0])
    conftest.write_data('kinesis_stream.json', json.dumps(resources['aws_kinesis_stream'][0], indent=2))
    validate(translator, props)
