"""
Auto-generated node models for pentagi-taxonomy.
DO NOT EDIT - this file is generated from entities.yml
"""

from pydantic import BaseModel, Field
from typing import Literal

class Target(BaseModel):
    """Network endpoint, service, application, or host being assessed. Should include version information, technology stack, and network details (IP, port, protocol). Examples: 'phpMyAdmin 4.4.15.6 on 172.22.0.7:80', 'Apache 2.4.29 web server'"""
    version: int | None = Field(None, description='Taxonomy schema version')
    entity_uuid: str | None = Field(None, description='Unique identifier')
    identifier: str | None = Field(None, description='Primary identifier (hostname, IP, URL)')
    target_type: Literal['host', 'service', 'web_application', 'api_endpoint', 'network_range', 'container'] | None = Field(None, description='Type of target')
    hostname: str | None = Field(None, description='DNS hostname if applicable')
    ip_address: str | None = Field(None, description='IP address if applicable')
    port: int | None = Field(None, description='Port number if service-specific', ge=1, le=65535)
    protocol: str | None = Field(None, description='Protocol (HTTP, HTTPS, SSH, etc.)')
    technology_stack: list[str] | None = Field(None, description='Technologies detected (PHP, Apache, MySQL, etc.)')
    status: Literal['discovered', 'active', 'compromised', 'analyzed', 'unreachable'] | None = Field(None, description='Current assessment status')

class Vulnerability(BaseModel):
    """Security weakness or attack vector with CVE identifier, vulnerability class, or technical description. Should include severity assessment, exploitability status, version linkage, and test confirmation. Examples: 'CVE-2016-10134 SQLi in jsrpc.php profileIdx', 'XML External Entity (XXE) injection in document parser'"""
    version: int | None = Field(None, description='Taxonomy schema version')
    entity_uuid: str | None = Field(None, description='Unique identifier')
    vulnerability_name: str | None = Field(None, description='Vulnerability name or title')
    vulnerability_class: Literal['sql_injection', 'rce', 'xss', 'xxe', 'ssrf', 'lfi', 'rfi', 'csrf', 'auth_bypass', 'file_upload', 'command_injection', 'buffer_overflow', 'directory_traversal', 'privilege_escalation', 'information_disclosure', 'denial_of_service', 'deserialization', 'path_traversal', 'session_hijacking', 'other'] | None = Field(None, description='OWASP/CWE category of vulnerability')
    cve_id: str | None = Field(None, description='CVE identifier if applicable')
    cvss_score: float | None = Field(None, description='CVSS score if available', ge=0.0, le=10.0)
    severity: Literal['critical', 'high', 'medium', 'low', 'info'] | None = Field(None, description='Severity assessment')
    exploitability: Literal['confirmed_exploitable', 'likely_exploitable', 'theoretical', 'not_exploitable', 'unknown'] | None = Field(None, description='Whether vulnerability can be exploited')
    description: str | None = Field(None, description='Technical description of the vulnerability')
    exploitation_techniques_tested: list[str] | None = Field(None, description='List of exploitation techniques attempted (e.g., error-based SQLi, time-based SQLi, XXE file read)')
    successful_techniques: list[str] | None = Field(None, description='Techniques that successfully exploited this vulnerability')
    failed_techniques: list[str] | None = Field(None, description='Techniques that failed to exploit this vulnerability')
    xxe_parser_type: str | None = Field(None, description='XML parser type if XXE vulnerability (lxml, libxml2, Xerces, etc.)')
    xxe_protocol_handlers: list[str] | None = Field(None, description='Available protocol handlers for XXE (file, http, ftp, expect, php, jar)')
    xxe_oob_confirmed: bool | None = Field(None, description='Whether out-of-band XXE interaction was confirmed')

class Tool(BaseModel):
    """Executable scanner, testing tool, or exploitation framework. Extract when tool produces actionable results; note success/failure status. Examples: 'sqlmap', 'nmap', 'metasploit', 'Burp Suite'"""
    version: int | None = Field(None, description='Taxonomy schema version')
    entity_uuid: str | None = Field(None, description='Unique identifier')
    tool_name: str | None = Field(None, description='Tool name (nmap, sqlmap, metasploit, etc.)')
    tool_category: Literal['scanner', 'exploitation_framework', 'fuzzer', 'reconnaissance', 'enumeration', 'post_exploitation', 'password_cracker', 'web_proxy', 'network_tool', 'custom_script'] | None = Field(None, description='Category of tool')
    version_used: str | None = Field(None, description='Version of the tool used')
    purpose: str | None = Field(None, description='What the tool was used for in this context')

class TechnicalFinding(BaseModel):
    """Specific security observation or test result. Summarize concisely (max 500 chars), include confidence level, prioritize findings that advance the assessment narrative. Examples: '113 DB tables enumerated via error-based SQLi', '/etc/passwd accessed via XXE: 48 users listed', 'phpMyAdmin version 4.4.15.6 disclosed in HTTP headers'"""
    version: int | None = Field(None, description='Taxonomy schema version')
    entity_uuid: str | None = Field(None, description='Unique identifier')
    finding_type: Literal['version_disclosure', 'open_port', 'exposed_endpoint', 'configuration_issue', 'credential', 'sensitive_data', 'exploit_success', 'reconnaissance_data', 'vulnerability_confirmation', 'patch_status', 'service_banner', 'database_enumeration', 'authentication_result'] | None = Field(None, description='Type of finding')
    title: str | None = Field(None, description='Brief title of the finding')
    content: str | None = Field(None, description='Detailed finding content (sanitized and summarized)')
    confidence: float | None = Field(None, description='Confidence in the finding', ge=0.0, le=1.0)
    severity: Literal['critical', 'high', 'medium', 'low', 'info'] | None = Field(None, description='Severity of the finding')
    evidence: str | None = Field(None, description='Key evidence supporting the finding (truncated)')
    extraction_technique: str | None = Field(None, description='How data was extracted (e.g., error-based SQLi, time-based, manual)')
    data_type: Literal['database_schema', 'user_info', 'configuration', 'privileges', 'file_content', 'command_output', 'network_data', 'session_info', 'other'] | None = Field(None, description='Type of data in this finding')

class AttackTechnique(BaseModel):
    """Specific exploitation method with technical details and payload information. Should map to MITRE ATT&CK taxonomy when applicable, record success/failure, and include actual payloads used. Examples: 'Error-based SQLi via updatexml()', 'Time-based blind SQLi with sleep()', 'Out-of-band XXE data exfiltration'"""
    version: int | None = Field(None, description='Taxonomy schema version')
    entity_uuid: str | None = Field(None, description='Unique identifier')
    attack_technique_name: str | None = Field(None, description='Name of the attack technique')
    technique_category: Literal['initial_access', 'execution', 'persistence', 'privilege_escalation', 'defense_evasion', 'credential_access', 'discovery', 'lateral_movement', 'collection', 'exfiltration', 'impact'] | None = Field(None, description='MITRE ATT&CK category')
    description: str | None = Field(None, description='Description of how the technique works')
    payload: str | None = Field(None, description='Actual payload or command used (sanitized)')
    success_indicator: str | None = Field(None, description='What indicates successful execution')

class TestPhase(BaseModel):
    """A phase or stage of the penetration testing engagement"""
    version: int | None = Field(None, description='Taxonomy schema version')
    entity_uuid: str | None = Field(None, description='Unique identifier')
    test_phase_name: Literal['reconnaissance', 'scanning', 'enumeration', 'vulnerability_analysis', 'exploitation', 'post_exploitation', 'reporting', 'cleanup'] | None = Field(None, description='Name of the test phase')
    objective: str | None = Field(None, description='Objective of this phase')
    status: Literal['not_started', 'in_progress', 'completed', 'blocked', 'skipped'] | None = Field(None, description='Status of the phase')
    start_timestamp: float | None = Field(None, description='When phase started')
    end_timestamp: float | None = Field(None, description='When phase completed')

class Credential(BaseModel):
    """Actual authentication credentials with values (ALWAYS extract, including default credentials). Should include privilege level, discovery source, authentication status, and session tokens when applicable. Examples: 'Admin/zabbix', 'root/password', 'zbx_sessionid=0a0f93de...', 'API key: sk-abc123...'"""
    version: int | None = Field(None, description='Taxonomy schema version')
    entity_uuid: str | None = Field(None, description='Unique identifier')
    credential_type: Literal['username_password', 'api_key', 'token', 'ssh_key', 'certificate', 'hash', 'cookie'] | None = Field(None, description='Type of credential')
    username: str | None = Field(None, description='Username if applicable')
    is_valid: bool | None = Field(None, description='Whether credential is valid')
    is_default: bool | None = Field(None, description='Whether this is a default credential (e.g., Admin/zabbix)')
    privilege_level: Literal['admin', 'user', 'guest', 'service_account', 'root', 'unknown'] | None = Field(None, description='Privilege level of the credential')
    source: str | None = Field(None, description='How the credential was obtained')
    authentication_state: Literal['success', 'failure', 'requires_2fa', 'locked', 'expired', 'unknown'] | None = Field(None, description='Result of authentication attempt with this credential')

class ExploitCode(BaseModel):
    """Actual exploit code, script, or payload used during testing. Should reference target vulnerability, include programming language, and document purpose/objective. Can be proof-of-concept, weaponized exploit, web shell, or reconnaissance script."""
    version: int | None = Field(None, description='Taxonomy schema version')
    entity_uuid: str | None = Field(None, description='Unique identifier')
    exploit_code_name: str | None = Field(None, description='Name of the exploit')
    language: Literal['python', 'bash', 'php', 'ruby', 'powershell', 'javascript', 'go', 'other'] | None = Field(None, description='Programming language')
    purpose: str | None = Field(None, description='What the exploit is designed to achieve')
    file_path: str | None = Field(None, description='Path where exploit was saved')
    code_type: Literal['proof_of_concept', 'weaponized_exploit', 'web_shell', 'reverse_shell', 'payload', 'script', 'reconnaissance_tool'] | None = Field(None, description='Type of code')

class AuthenticationAttempt(BaseModel):
    """Login attempt (success or failure), session establishment (cookies/tokens/CSRF), credential validation, or bypass attempt. Should capture authentication state changes, privilege levels obtained, session tokens, and response details."""
    version: int | None = Field(None, description='Taxonomy schema version')
    entity_uuid: str | None = Field(None, description='Unique identifier')
    timestamp: float | None = Field(None, description='When authentication was attempted')
    success: bool | None = Field(None, description='Whether authentication succeeded')
    credential_used: str | None = Field(None, description='Reference to credential entity used')
    session_established: bool | None = Field(None, description='Whether a session was established')
    response_code: int | None = Field(None, description='HTTP response code if applicable')
    error_message: str | None = Field(None, description='Error message if authentication failed')

class DatabaseMetadata(BaseModel):
    """Database configuration, schema, and structure information. Should include SQLi payload types used for extraction, enumeration results (tables/columns), user privileges, configuration details, and technique comparisons. Avoid duplicate error entries. Examples: 'MySQL 5.7.33 with FILE privilege', '113 tables enumerated: users, sessions, config, logs...'"""
    version: int | None = Field(None, description='Taxonomy schema version')
    entity_uuid: str | None = Field(None, description='Unique identifier')
    database_type: Literal['mysql', 'postgresql', 'mssql', 'oracle', 'mongodb', 'redis', 'other'] | None = Field(None, description='Type of database')
    database_version: str | None = Field(None, description='Database version if known')
    database_user: str | None = Field(None, description='Database user (e.g., root@172.22.0.7)')
    table_count: int | None = Field(None, description='Number of tables discovered')
    table_names: list[str] | None = Field(None, description='List of table names discovered')
    privileges: list[str] | None = Field(None, description='User privileges (e.g., FILE, SELECT, INSERT)')
    secure_file_priv: str | None = Field(None, description='secure_file_priv setting value')
    configuration_details: str | None = Field(None, description='Other relevant configuration information')

class ExploitationAttempt(BaseModel):
    """A specific exploitation attempt with a technique"""
    version: int | None = Field(None, description='Taxonomy schema version')
    entity_uuid: str | None = Field(None, description='Unique identifier')
    timestamp: float | None = Field(None, description='When exploitation was attempted')
    technique_type: Literal['error_based_sqli', 'time_based_sqli', 'boolean_based_sqli', 'union_based_sqli', 'file_inclusion', 'command_injection', 'xxe', 'buffer_overflow', 'other'] | None = Field(None, description='Type of exploitation technique')
    success: bool | None = Field(None, description='Whether exploitation succeeded')
    payload: str | None = Field(None, description='Payload used (sanitized)')
    response_hash: str | None = Field(None, description='Hash of response for deduplication')
    result_summary: str | None = Field(None, description='Summary of what happened')

class SessionInfo(BaseModel):
    """Session tokens, cookies, and authentication state AFTER successful authentication"""
    version: int | None = Field(None, description='Taxonomy schema version')
    entity_uuid: str | None = Field(None, description='Unique identifier')
    session_type: Literal['cookie', 'token', 'jwt', 'oauth', 'api_key', 'other'] | None = Field(None, description='Type of session mechanism')
    session_id: str | None = Field(None, description='Session identifier (e.g., zbx_sessionid value)')
    csrf_token: str | None = Field(None, description='CSRF token if applicable')
    established_at: float | None = Field(None, description='When session was established')
    expires_at: float | None = Field(None, description='When session expires (if known)')
    privilege_level: Literal['guest', 'user', 'admin', 'root', 'unknown'] | None = Field(None, description='Privilege level of this session')

class FileSystemAccess(BaseModel):
    """File system access attempt and result. For successful reads, include file path and content preview. Document permission boundaries, file types accessed, and sensitivity level. Skip duplicate permission denials (keep first only) and verbose methodology without results. Examples: '/etc/passwd read: 48 user accounts', 'SSH private key found at /root/.ssh/id_rsa'"""
    version: int | None = Field(None, description='Taxonomy schema version')
    entity_uuid: str | None = Field(None, description='Unique identifier')
    file_path: str | None = Field(None, description='Path to file or directory accessed')
    access_type: Literal['read', 'write', 'execute', 'list', 'stat'] | None = Field(None, description='Type of access attempted')
    success: bool | None = Field(None, description='Whether access was successful')
    access_method: Literal['xxe', 'lfi', 'rfi', 'command_injection', 'direct_access', 'path_traversal'] | None = Field(None, description='Method used to access file')
    content_preview: str | None = Field(None, description='Preview of file content if read (truncated to 500 chars)')
    permission_error: str | None = Field(None, description='Permission error message if access denied')
    file_type: Literal['config', 'credential', 'log', 'system_info', 'ssh_key', 'source_code', 'database', 'other'] | None = Field(None, description='Type of file accessed')
    sensitivity: Literal['critical', 'high', 'medium', 'low', 'info'] | None = Field(None, description='Sensitivity level of accessed file')

class XMLPayload(BaseModel):
    """XML payload used in XXE exploitation. Should identify XML parser (type/version), protocol handlers available (file/http/ftp/expect/php/jar), successful file reads, OOB interaction confirmations, payload variations tested, and parser configuration. Examples: 'XXE file:// payload reading /etc/passwd', 'OOB XXE via HTTP callback to attacker.com'"""
    version: int | None = Field(None, description='Taxonomy schema version')
    entity_uuid: str | None = Field(None, description='Unique identifier')
    payload_type: Literal['file_read', 'oob_exfil', 'rce_attempt', 'ssrf', 'entity_expansion', 'parameter_entity'] | None = Field(None, description='Type of XXE payload')
    payload_content: str | None = Field(None, description='Actual XML payload (sanitized)')
    encoding: Literal['utf-8', 'utf-16', 'utf-16be', 'base64', 'other'] | None = Field(None, description='Payload encoding')
    protocol_handler: Literal['file', 'http', 'https', 'ftp', 'expect', 'php', 'jar', 'data', 'gopher', 'other'] | None = Field(None, description='Protocol handler used in payload')
    success: bool | None = Field(None, description='Whether payload was successful')
    response_length: int | None = Field(None, description='Length of response in bytes')
    oob_interaction: bool | None = Field(None, description='Whether OOB interaction was observed')

