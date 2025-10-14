"""
Tests for generated Python code (v1).
"""

import pytest
from pydantic import ValidationError
from pentagi_taxonomy import TAXONOMY_VERSION, ENTITY_TYPES, EDGE_TYPES
from pentagi_taxonomy.nodes import Target, Port
from pentagi_taxonomy.edges import HasPort, Discovered


def test_taxonomy_version():
    """Test that TAXONOMY_VERSION is correctly set."""
    assert TAXONOMY_VERSION == 1


def test_entity_types_exported():
    """Test that entity type mappings are exported."""
    assert 'Target' in ENTITY_TYPES
    assert 'Port' in ENTITY_TYPES
    assert ENTITY_TYPES['Target'] == Target


def test_target_validation():
    """Test Target validation."""
    target = Target(
        hostname="example.com",
        ip_address="192.168.1.1",
        target_type="host",
        risk_score=5.0
    )
    assert target.hostname == "example.com"


def test_port_validation():
    """Test Port validation."""
    port = Port(
        port_number=443,
        protocol="tcp",
        state="open"
    )
    assert port.port_number == 443


def test_all_fields_optional():
    """Test that all fields are optional."""
    target = Target()
    assert target.version is None
    
    port = Port()
    assert port.port_number is None

