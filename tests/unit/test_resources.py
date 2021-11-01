from conftest import load_data
from tfdevops.cli import Translator, filter_empty


def test_elasticache_replication_group(validate):
    translator = Translator.get_translator("elasticache_replication_group")()
    resource = load_data("elasticache.json")
    props = translator.get_properties(resource)
    validate(translator, filter_empty(props))


def test_app_lb(validate):
    translator = Translator.get_translator("lb")()
    resource = load_data("app_lb.json")
    props = translator.get_properties(resource)
    validate(translator, props)
