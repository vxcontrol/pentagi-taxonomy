"""
Auto-generated edge models for pentagi-taxonomy.
DO NOT EDIT - this file is generated from entities.yml
"""

from pydantic import BaseModel, Field
from typing import Literal

class HasVulnerability(BaseModel):
    """A target has or is affected by a vulnerability"""
    version: int | None = Field(None, description='Taxonomy schema version')
    timestamp: float | None = Field(None, description='When vulnerability was identified')
    confidence: float | None = Field(None, description='Confidence in the vulnerability', ge=0.0, le=1.0)
    verified: bool | None = Field(None, description='Whether vulnerability was verified through exploitation')

class UsedAgainst(BaseModel):
    """A tool or technique was used against a target"""
    version: int | None = Field(None, description='Taxonomy schema version')
    timestamp: float | None = Field(None, description='When tool was used')
    success: bool | None = Field(None, description='Whether the use was successful')
    execution_context: str | None = Field(None, description='Context of tool usage (command line, parameters)')

class Exploits(BaseModel):
    """A technique or exploit code exploits a vulnerability"""
    version: int | None = Field(None, description='Taxonomy schema version')
    timestamp: float | None = Field(None, description='When exploitation occurred')
    success: bool | None = Field(None, description='Whether exploitation was successful')
    impact: Literal['full_compromise', 'partial_access', 'information_disclosure', 'denial_of_service', 'none'] | None = Field(None, description='Impact of successful exploitation')

class DiscoveredIn(BaseModel):
    """A finding was discovered during a test phase"""
    version: int | None = Field(None, description='Taxonomy schema version')
    timestamp: float | None = Field(None, description='When discovery occurred')
    discovery_method: str | None = Field(None, description='How the finding was discovered')

class LeadsTo(BaseModel):
    """One finding, technique, or vulnerability leads to another (attack chain)"""
    version: int | None = Field(None, description='Taxonomy schema version')
    timestamp: float | None = Field(None, description='When connection was established')
    reasoning: str | None = Field(None, description='How one leads to the other')

class Targets(BaseModel):
    """A vulnerability, technique, or tool targets a specific target"""
    version: int | None = Field(None, description='Taxonomy schema version')
    timestamp: float | None = Field(None, description='When targeting occurred')

class ProvidesAccessTo(BaseModel):
    """A credential provides access to a target or service"""
    version: int | None = Field(None, description='Taxonomy schema version')
    timestamp: float | None = Field(None, description='When access was verified')
    access_level: Literal['read_only', 'read_write', 'administrative', 'root', 'limited'] | None = Field(None, description='Level of access provided')

class Yields(BaseModel):
    """An action, tool use, or technique yields a finding"""
    version: int | None = Field(None, description='Taxonomy schema version')
    timestamp: float | None = Field(None, description='When finding was produced')

class UsesTool(BaseModel):
    """A technique or attack uses a specific tool"""
    version: int | None = Field(None, description='Taxonomy schema version')
    timestamp: float | None = Field(None, description='When tool was used')

class AuthenticatedWith(BaseModel):
    """A credential was used to authenticate against a target"""
    version: int | None = Field(None, description='Taxonomy schema version')
    timestamp: float | None = Field(None, description='When authentication occurred')
    success: bool | None = Field(None, description='Whether authentication succeeded')
    session_created: str | None = Field(None, description='Session ID created (if applicable)')

class ExtractedFrom(BaseModel):
    """A finding was extracted from a target using a specific technique"""
    version: int | None = Field(None, description='Taxonomy schema version')
    timestamp: float | None = Field(None, description='When extraction occurred')
    extraction_method: str | None = Field(None, description='Method used for extraction (e.g., error-based SQLi)')

class Enumerated(BaseModel):
    """A tool enumerated database metadata"""
    version: int | None = Field(None, description='Taxonomy schema version')
    timestamp: float | None = Field(None, description='When enumeration occurred')
    records_found: int | None = Field(None, description='Number of records/items found')

class Establishes(BaseModel):
    """An authentication attempt establishes a session"""
    version: int | None = Field(None, description='Taxonomy schema version')
    timestamp: float | None = Field(None, description='When session was established')

class AccessedFile(BaseModel):
    """An attack technique or exploit accessed a file"""
    version: int | None = Field(None, description='Taxonomy schema version')
    timestamp: float | None = Field(None, description='When file was accessed')
    bytes_read: int | None = Field(None, description='Number of bytes read if applicable')

class Revealed(BaseModel):
    """A file system access revealed information or findings"""
    version: int | None = Field(None, description='Taxonomy schema version')
    timestamp: float | None = Field(None, description='When information was revealed')
    revelation_type: Literal['credentials', 'configuration', 'system_info', 'vulnerability', 'other'] | None = Field(None, description='Type of information revealed')

class UsesPayload(BaseModel):
    """An exploitation attempt uses a specific XML payload"""
    version: int | None = Field(None, description='Taxonomy schema version')
    timestamp: float | None = Field(None, description='When payload was used')
    attempt_number: int | None = Field(None, description='Sequential attempt number')

class OobInteraction(BaseModel):
    """An XML payload triggered an out-of-band interaction"""
    version: int | None = Field(None, description='Taxonomy schema version')
    timestamp: float | None = Field(None, description='When interaction occurred')
    interaction_type: Literal['http_callback', 'dns_query', 'ftp_connection', 'other'] | None = Field(None, description='Type of OOB interaction')
    data_exfiltrated: str | None = Field(None, description='Data exfiltrated via OOB channel (preview)')

