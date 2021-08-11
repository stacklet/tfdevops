from tfdevops.cli import TF_CFN_MAP, Translator


def test_translator_map():
    assert set(Translator.get_translator_map()) == set(TF_CFN_MAP)
