"""
Tests for generated Python code (v1).
"""

import pytest
from pydantic import ValidationError
from pentagi_taxonomy import TAXONOMY_VERSION, ENTITY_TYPES, EDGE_TYPES
from pentagi_taxonomy.nodes import Target, Vulnerability, Tool, TechnicalFinding
from pentagi_taxonomy.edges import HasVulnerability, UsedAgainst, Yields


def test_taxonomy_version():
    """Test that TAXONOMY_VERSION is correctly set."""
    assert TAXONOMY_VERSION == 1


def test_entity_types_exported():
    """Test that entity type mappings are exported."""
    assert 'Target' in ENTITY_TYPES
    assert 'Vulnerability' in ENTITY_TYPES
    assert 'Tool' in ENTITY_TYPES
    assert ENTITY_TYPES['Target'] == Target
    assert ENTITY_TYPES['Vulnerability'] == Vulnerability


def test_target_validation():
    """Test Target validation."""
    target = Target(
        hostname="example.com",
        ip_address="192.168.1.1",
        target_type="host",
        port=443,
        protocol="HTTPS"
    )
    assert target.hostname == "example.com"
    assert target.port == 443


def test_vulnerability_validation():
    """Test Vulnerability validation."""
    vuln = Vulnerability(
        vulnerability_name="SQL Injection",
        vulnerability_class="sql_injection",
        severity="high",
        cvss_score=7.5
    )
    assert vuln.vulnerability_name == "SQL Injection"
    assert vuln.cvss_score == 7.5


def test_tool_validation():
    """Test Tool validation."""
    tool = Tool(
        tool_name="sqlmap",
        tool_category="exploitation_framework",
        version_used="1.5.3"
    )
    assert tool.tool_name == "sqlmap"
    assert tool.tool_category == "exploitation_framework"


def test_all_fields_optional():
    """Test that all fields are optional."""
    target = Target()
    assert target.version is None
    assert target.hostname is None
    
    vuln = Vulnerability()
    assert vuln.vulnerability_name is None
    
    tool = Tool()
    assert tool.tool_name is None

