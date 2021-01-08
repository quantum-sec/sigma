"""Tests for the Azure Log Analytics backend."""

import pytest

from sigma.backends.ala import AzureLogAnalyticsBackend
from sigma.configuration import SigmaConfiguration
from sigma.parser.modifiers.type import SigmaRegularExpressionModifier
from sigma.parser.rule import SigmaParser


@pytest.fixture()
def sigmaconfig():
    """Return a new instance of the sigmaconfig."""
    with open('../tools/config/ala.yml') as f:
        return SigmaConfiguration(f)


@pytest.fixture()
def backend(sigmaconfig):
    """Return a new instance of the backend."""
    return AzureLogAnalyticsBackend(sigmaconfig)


def test_default_value_mapping_simple_contains(backend):
    """Should return a simple `contains` KQL condition."""
    val = '*.dll*'
    result = backend.default_value_mapping(val)
    assert result == 'contains @".dll"'


def test_default_value_mapping_preserve_slashes(backend):
    """Should preserve slashes in directory paths."""
    val = "*/.git/*"
    result = backend.default_value_mapping(val)
    assert result == 'contains @"/.git/"'


def test_default_value_mapping_starts_with(backend):
    """Should return a simple `startswith` KQL condition."""
    val = 'abc*'
    result = backend.default_value_mapping(val)
    assert result == 'startswith @"abc"'


def test_default_value_mapping_ends_with(backend):
    """Should return a simple `endswith` KQL condition."""
    val = '*.env'
    result = backend.default_value_mapping(val)
    assert result == 'endswith @".env"'


def test_default_value_mapping_regex_prefix(backend):
    """Should prefix regex strings with `@`."""
    val = '.*test.*'
    result = backend.default_value_mapping(val)
    assert result == 'matches regex @".*test.*"'


def test_default_value_mapping_simple_equals(backend):
    """Should return a simple `==` KQL condition."""
    val = 'test'
    result = backend.default_value_mapping(val)
    assert result == '== @"test"'


def test_typed_node_simple_regex(backend):
    value = SigmaRegularExpressionModifier('.*test.*')
    result = backend.generateTypedValueNode(value)
    assert result == 'matches regex @".*test.*"'


def test_typed_node_keywords(backend, sigmaconfig):
    rule = {
        'logsource': {
            'product': 'test',
        },
        'detection': {
            'keywords': [
                '*TEST_KEYWORD_1*',
                'TEST_KEYWORD_2'
            ],
            'condition': 'keywords'
        }
    }
    parser = SigmaParser(rule, sigmaconfig)
    result = backend.generate(parser)
    assert result == 'Test | where (* contains @"TEST_KEYWORD_1" or * contains @"TEST_KEYWORD_2")'
