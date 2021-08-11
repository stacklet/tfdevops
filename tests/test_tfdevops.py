from tfdevops.cli import Translator, TF_CFN_MAP


def test_translator_map():
    assert set(Translator.get_translator_map()) == set(TF_CFN_MAP)