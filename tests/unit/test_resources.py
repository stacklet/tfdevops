from conftest import load_data
from tfdevops.cli import Translator


def test_elasticache_replication_group(validate):
    translator = Translator.get_translator("elasticache_replication_group")()
    resource = load_data("elasticache.json")
    props = translator.get_properties(resource)
    validate(translator, props)
