/**
 * Auto-generated Zod schemas for pentagi-taxonomy.
 * DO NOT EDIT - this file is generated from entities.yml
 */

import { z } from 'zod';

// Network endpoint, service, application, or host being assessed. Should include version information, technology stack, and network details (IP, port, protocol). Examples: 'phpMyAdmin 4.4.15.6 on 172.22.0.7:80', 'Apache 2.4.29 web server'
export const TargetSchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // Unique identifier
  entity_uuid: z.string().optional(),
  // Primary identifier (hostname, IP, URL)
  identifier: z.string().optional(),
  // Type of target
  target_type: z.enum(["host", "service", "web_application", "api_endpoint", "network_range", "container"]).optional(),
  // DNS hostname if applicable
  hostname: z.string().optional(),
  // IP address if applicable
  ip_address: z.string().regex(/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/).optional(),
  // Port number if service-specific
  port: z.number().int().min(1).max(65535).optional(),
  // Protocol (HTTP, HTTPS, SSH, etc.)
  protocol: z.string().optional(),
  // Technologies detected (PHP, Apache, MySQL, etc.)
  technology_stack: z.array(z.string()).optional(),
  // Current assessment status
  status: z.enum(["discovered", "active", "compromised", "analyzed", "unreachable"]).optional(),
});

export type Target = z.infer<typeof TargetSchema>;

// Security weakness or attack vector with CVE identifier, vulnerability class, or technical description. Should include severity assessment, exploitability status, version linkage, and test confirmation. Examples: 'CVE-2016-10134 SQLi in jsrpc.php profileIdx', 'XML External Entity (XXE) injection in document parser'
export const VulnerabilitySchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // Unique identifier
  entity_uuid: z.string().optional(),
  // Vulnerability name or title
  vulnerability_name: z.string().optional(),
  // OWASP/CWE category of vulnerability
  vulnerability_class: z.enum(["sql_injection", "rce", "xss", "xxe", "ssrf", "lfi", "rfi", "csrf", "auth_bypass", "file_upload", "command_injection", "buffer_overflow", "directory_traversal", "privilege_escalation", "information_disclosure", "denial_of_service", "deserialization", "path_traversal", "session_hijacking", "other"]).optional(),
  // CVE identifier if applicable
  cve_id: z.string().regex(/^CVE-\d{4}-\d{4,7}$/).optional(),
  // CVSS score if available
  cvss_score: z.number().min(0.0).max(10.0).optional(),
  // Severity assessment
  severity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
  // Whether vulnerability can be exploited
  exploitability: z.enum(["confirmed_exploitable", "likely_exploitable", "theoretical", "not_exploitable", "unknown"]).optional(),
  // Technical description of the vulnerability
  description: z.string().optional(),
  // List of exploitation techniques attempted (e.g., error-based SQLi, time-based SQLi, XXE file read)
  exploitation_techniques_tested: z.array(z.string()).optional(),
  // Techniques that successfully exploited this vulnerability
  successful_techniques: z.array(z.string()).optional(),
  // Techniques that failed to exploit this vulnerability
  failed_techniques: z.array(z.string()).optional(),
  // XML parser type if XXE vulnerability (lxml, libxml2, Xerces, etc.)
  xxe_parser_type: z.string().optional(),
  // Available protocol handlers for XXE (file, http, ftp, expect, php, jar)
  xxe_protocol_handlers: z.array(z.string()).optional(),
  // Whether out-of-band XXE interaction was confirmed
  xxe_oob_confirmed: z.boolean().optional(),
});

export type Vulnerability = z.infer<typeof VulnerabilitySchema>;

// Executable scanner, testing tool, or exploitation framework. Extract when tool produces actionable results; note success/failure status. Examples: 'sqlmap', 'nmap', 'metasploit', 'Burp Suite'
export const ToolSchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // Unique identifier
  entity_uuid: z.string().optional(),
  // Tool name (nmap, sqlmap, metasploit, etc.)
  tool_name: z.string().optional(),
  // Category of tool
  tool_category: z.enum(["scanner", "exploitation_framework", "fuzzer", "reconnaissance", "enumeration", "post_exploitation", "password_cracker", "web_proxy", "network_tool", "custom_script"]).optional(),
  // Version of the tool used
  version_used: z.string().optional(),
  // What the tool was used for in this context
  purpose: z.string().optional(),
});

export type Tool = z.infer<typeof ToolSchema>;

// Specific security observation or test result. Summarize concisely (max 500 chars), include confidence level, prioritize findings that advance the assessment narrative. Examples: '113 DB tables enumerated via error-based SQLi', '/etc/passwd accessed via XXE: 48 users listed', 'phpMyAdmin version 4.4.15.6 disclosed in HTTP headers'
export const TechnicalFindingSchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // Unique identifier
  entity_uuid: z.string().optional(),
  // Type of finding
  finding_type: z.enum(["version_disclosure", "open_port", "exposed_endpoint", "configuration_issue", "credential", "sensitive_data", "exploit_success", "reconnaissance_data", "vulnerability_confirmation", "patch_status", "service_banner", "database_enumeration", "authentication_result"]).optional(),
  // Brief title of the finding
  title: z.string().optional(),
  // Detailed finding content (sanitized and summarized)
  content: z.string().optional(),
  // Confidence in the finding
  confidence: z.number().min(0.0).max(1.0).optional(),
  // Severity of the finding
  severity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
  // Key evidence supporting the finding (truncated)
  evidence: z.string().optional(),
  // How data was extracted (e.g., error-based SQLi, time-based, manual)
  extraction_technique: z.string().optional(),
  // Type of data in this finding
  data_type: z.enum(["database_schema", "user_info", "configuration", "privileges", "file_content", "command_output", "network_data", "session_info", "other"]).optional(),
});

export type TechnicalFinding = z.infer<typeof TechnicalFindingSchema>;

// Specific exploitation method with technical details and payload information. Should map to MITRE ATT&CK taxonomy when applicable, record success/failure, and include actual payloads used. Examples: 'Error-based SQLi via updatexml()', 'Time-based blind SQLi with sleep()', 'Out-of-band XXE data exfiltration'
export const AttackTechniqueSchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // Unique identifier
  entity_uuid: z.string().optional(),
  // Name of the attack technique
  attack_technique_name: z.string().optional(),
  // MITRE ATT&CK category
  technique_category: z.enum(["initial_access", "execution", "persistence", "privilege_escalation", "defense_evasion", "credential_access", "discovery", "lateral_movement", "collection", "exfiltration", "impact"]).optional(),
  // Description of how the technique works
  description: z.string().optional(),
  // Actual payload or command used (sanitized)
  payload: z.string().optional(),
  // What indicates successful execution
  success_indicator: z.string().optional(),
});

export type AttackTechnique = z.infer<typeof AttackTechniqueSchema>;

// A phase or stage of the penetration testing engagement
export const TestPhaseSchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // Unique identifier
  entity_uuid: z.string().optional(),
  // Name of the test phase
  test_phase_name: z.enum(["reconnaissance", "scanning", "enumeration", "vulnerability_analysis", "exploitation", "post_exploitation", "reporting", "cleanup"]).optional(),
  // Objective of this phase
  objective: z.string().optional(),
  // Status of the phase
  status: z.enum(["not_started", "in_progress", "completed", "blocked", "skipped"]).optional(),
  // When phase started
  start_timestamp: z.number().optional(),
  // When phase completed
  end_timestamp: z.number().optional(),
});

export type TestPhase = z.infer<typeof TestPhaseSchema>;

// Actual authentication credentials with values (ALWAYS extract, including default credentials). Should include privilege level, discovery source, authentication status, and session tokens when applicable. Examples: 'Admin/zabbix', 'root/password', 'zbx_sessionid=0a0f93de...', 'API key: sk-abc123...'
export const CredentialSchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // Unique identifier
  entity_uuid: z.string().optional(),
  // Type of credential
  credential_type: z.enum(["username_password", "api_key", "token", "ssh_key", "certificate", "hash", "cookie"]).optional(),
  // Username if applicable
  username: z.string().optional(),
  // Whether credential is valid
  is_valid: z.boolean().optional(),
  // Whether this is a default credential (e.g., Admin/zabbix)
  is_default: z.boolean().optional(),
  // Privilege level of the credential
  privilege_level: z.enum(["admin", "user", "guest", "service_account", "root", "unknown"]).optional(),
  // How the credential was obtained
  source: z.string().optional(),
  // Result of authentication attempt with this credential
  authentication_state: z.enum(["success", "failure", "requires_2fa", "locked", "expired", "unknown"]).optional(),
});

export type Credential = z.infer<typeof CredentialSchema>;

// Actual exploit code, script, or payload used during testing. Should reference target vulnerability, include programming language, and document purpose/objective. Can be proof-of-concept, weaponized exploit, web shell, or reconnaissance script.
export const ExploitCodeSchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // Unique identifier
  entity_uuid: z.string().optional(),
  // Name of the exploit
  exploit_code_name: z.string().optional(),
  // Programming language
  language: z.enum(["python", "bash", "php", "ruby", "powershell", "javascript", "go", "other"]).optional(),
  // What the exploit is designed to achieve
  purpose: z.string().optional(),
  // Path where exploit was saved
  file_path: z.string().optional(),
  // Type of code
  code_type: z.enum(["proof_of_concept", "weaponized_exploit", "web_shell", "reverse_shell", "payload", "script", "reconnaissance_tool"]).optional(),
});

export type ExploitCode = z.infer<typeof ExploitCodeSchema>;

// Login attempt (success or failure), session establishment (cookies/tokens/CSRF), credential validation, or bypass attempt. Should capture authentication state changes, privilege levels obtained, session tokens, and response details.
export const AuthenticationAttemptSchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // Unique identifier
  entity_uuid: z.string().optional(),
  // When authentication was attempted
  timestamp: z.number().optional(),
  // Whether authentication succeeded
  success: z.boolean().optional(),
  // Reference to credential entity used
  credential_used: z.string().optional(),
  // Whether a session was established
  session_established: z.boolean().optional(),
  // HTTP response code if applicable
  response_code: z.number().int().optional(),
  // Error message if authentication failed
  error_message: z.string().optional(),
});

export type AuthenticationAttempt = z.infer<typeof AuthenticationAttemptSchema>;

// Database configuration, schema, and structure information. Should include SQLi payload types used for extraction, enumeration results (tables/columns), user privileges, configuration details, and technique comparisons. Avoid duplicate error entries. Examples: 'MySQL 5.7.33 with FILE privilege', '113 tables enumerated: users, sessions, config, logs...'
export const DatabaseMetadataSchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // Unique identifier
  entity_uuid: z.string().optional(),
  // Type of database
  database_type: z.enum(["mysql", "postgresql", "mssql", "oracle", "mongodb", "redis", "other"]).optional(),
  // Database version if known
  database_version: z.string().optional(),
  // Database user (e.g., root@172.22.0.7)
  database_user: z.string().optional(),
  // Number of tables discovered
  table_count: z.number().int().optional(),
  // List of table names discovered
  table_names: z.array(z.string()).optional(),
  // User privileges (e.g., FILE, SELECT, INSERT)
  privileges: z.array(z.string()).optional(),
  // secure_file_priv setting value
  secure_file_priv: z.string().optional(),
  // Other relevant configuration information
  configuration_details: z.string().optional(),
});

export type DatabaseMetadata = z.infer<typeof DatabaseMetadataSchema>;

// A specific exploitation attempt with a technique
export const ExploitationAttemptSchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // Unique identifier
  entity_uuid: z.string().optional(),
  // When exploitation was attempted
  timestamp: z.number().optional(),
  // Type of exploitation technique
  technique_type: z.enum(["error_based_sqli", "time_based_sqli", "boolean_based_sqli", "union_based_sqli", "file_inclusion", "command_injection", "xxe", "buffer_overflow", "other"]).optional(),
  // Whether exploitation succeeded
  success: z.boolean().optional(),
  // Payload used (sanitized)
  payload: z.string().optional(),
  // Hash of response for deduplication
  response_hash: z.string().optional(),
  // Summary of what happened
  result_summary: z.string().optional(),
});

export type ExploitationAttempt = z.infer<typeof ExploitationAttemptSchema>;

// Session tokens, cookies, and authentication state AFTER successful authentication
export const SessionInfoSchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // Unique identifier
  entity_uuid: z.string().optional(),
  // Type of session mechanism
  session_type: z.enum(["cookie", "token", "jwt", "oauth", "api_key", "other"]).optional(),
  // Session identifier (e.g., zbx_sessionid value)
  session_id: z.string().optional(),
  // CSRF token if applicable
  csrf_token: z.string().optional(),
  // When session was established
  established_at: z.number().optional(),
  // When session expires (if known)
  expires_at: z.number().optional(),
  // Privilege level of this session
  privilege_level: z.enum(["guest", "user", "admin", "root", "unknown"]).optional(),
});

export type SessionInfo = z.infer<typeof SessionInfoSchema>;

// File system access attempt and result. For successful reads, include file path and content preview. Document permission boundaries, file types accessed, and sensitivity level. Skip duplicate permission denials (keep first only) and verbose methodology without results. Examples: '/etc/passwd read: 48 user accounts', 'SSH private key found at /root/.ssh/id_rsa'
export const FileSystemAccessSchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // Unique identifier
  entity_uuid: z.string().optional(),
  // Path to file or directory accessed
  file_path: z.string().optional(),
  // Type of access attempted
  access_type: z.enum(["read", "write", "execute", "list", "stat"]).optional(),
  // Whether access was successful
  success: z.boolean().optional(),
  // Method used to access file
  access_method: z.enum(["xxe", "lfi", "rfi", "command_injection", "direct_access", "path_traversal"]).optional(),
  // Preview of file content if read (truncated to 500 chars)
  content_preview: z.string().optional(),
  // Permission error message if access denied
  permission_error: z.string().optional(),
  // Type of file accessed
  file_type: z.enum(["config", "credential", "log", "system_info", "ssh_key", "source_code", "database", "other"]).optional(),
  // Sensitivity level of accessed file
  sensitivity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
});

export type FileSystemAccess = z.infer<typeof FileSystemAccessSchema>;

// XML payload used in XXE exploitation. Should identify XML parser (type/version), protocol handlers available (file/http/ftp/expect/php/jar), successful file reads, OOB interaction confirmations, payload variations tested, and parser configuration. Examples: 'XXE file:// payload reading /etc/passwd', 'OOB XXE via HTTP callback to attacker.com'
export const XMLPayloadSchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // Unique identifier
  entity_uuid: z.string().optional(),
  // Type of XXE payload
  payload_type: z.enum(["file_read", "oob_exfil", "rce_attempt", "ssrf", "entity_expansion", "parameter_entity"]).optional(),
  // Actual XML payload (sanitized)
  payload_content: z.string().optional(),
  // Payload encoding
  encoding: z.enum(["utf-8", "utf-16", "utf-16be", "base64", "other"]).optional(),
  // Protocol handler used in payload
  protocol_handler: z.enum(["file", "http", "https", "ftp", "expect", "php", "jar", "data", "gopher", "other"]).optional(),
  // Whether payload was successful
  success: z.boolean().optional(),
  // Length of response in bytes
  response_length: z.number().int().optional(),
  // Whether OOB interaction was observed
  oob_interaction: z.boolean().optional(),
});

export type XMLPayload = z.infer<typeof XMLPayloadSchema>;

// A target has or is affected by a vulnerability
export const HasVulnerabilitySchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // When vulnerability was identified
  timestamp: z.number().optional(),
  // Confidence in the vulnerability
  confidence: z.number().min(0.0).max(1.0).optional(),
  // Whether vulnerability was verified through exploitation
  verified: z.boolean().optional(),
});

export type HasVulnerability = z.infer<typeof HasVulnerabilitySchema>;

// A tool or technique was used against a target
export const UsedAgainstSchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // When tool was used
  timestamp: z.number().optional(),
  // Whether the use was successful
  success: z.boolean().optional(),
  // Context of tool usage (command line, parameters)
  execution_context: z.string().optional(),
});

export type UsedAgainst = z.infer<typeof UsedAgainstSchema>;

// A technique or exploit code exploits a vulnerability
export const ExploitsSchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // When exploitation occurred
  timestamp: z.number().optional(),
  // Whether exploitation was successful
  success: z.boolean().optional(),
  // Impact of successful exploitation
  impact: z.enum(["full_compromise", "partial_access", "information_disclosure", "denial_of_service", "none"]).optional(),
});

export type Exploits = z.infer<typeof ExploitsSchema>;

// A finding was discovered during a test phase
export const DiscoveredInSchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // When discovery occurred
  timestamp: z.number().optional(),
  // How the finding was discovered
  discovery_method: z.string().optional(),
});

export type DiscoveredIn = z.infer<typeof DiscoveredInSchema>;

// One finding, technique, or vulnerability leads to another (attack chain)
export const LeadsToSchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // When connection was established
  timestamp: z.number().optional(),
  // How one leads to the other
  reasoning: z.string().optional(),
});

export type LeadsTo = z.infer<typeof LeadsToSchema>;

// A vulnerability, technique, or tool targets a specific target
export const TargetsSchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // When targeting occurred
  timestamp: z.number().optional(),
});

export type Targets = z.infer<typeof TargetsSchema>;

// A credential provides access to a target or service
export const ProvidesAccessToSchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // When access was verified
  timestamp: z.number().optional(),
  // Level of access provided
  access_level: z.enum(["read_only", "read_write", "administrative", "root", "limited"]).optional(),
});

export type ProvidesAccessTo = z.infer<typeof ProvidesAccessToSchema>;

// An action, tool use, or technique yields a finding
export const YieldsSchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // When finding was produced
  timestamp: z.number().optional(),
});

export type Yields = z.infer<typeof YieldsSchema>;

// A technique or attack uses a specific tool
export const UsesToolSchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // When tool was used
  timestamp: z.number().optional(),
});

export type UsesTool = z.infer<typeof UsesToolSchema>;

// A credential was used to authenticate against a target
export const AuthenticatedWithSchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // When authentication occurred
  timestamp: z.number().optional(),
  // Whether authentication succeeded
  success: z.boolean().optional(),
  // Session ID created (if applicable)
  session_created: z.string().optional(),
});

export type AuthenticatedWith = z.infer<typeof AuthenticatedWithSchema>;

// A finding was extracted from a target using a specific technique
export const ExtractedFromSchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // When extraction occurred
  timestamp: z.number().optional(),
  // Method used for extraction (e.g., error-based SQLi)
  extraction_method: z.string().optional(),
});

export type ExtractedFrom = z.infer<typeof ExtractedFromSchema>;

// A tool enumerated database metadata
export const EnumeratedSchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // When enumeration occurred
  timestamp: z.number().optional(),
  // Number of records/items found
  records_found: z.number().int().optional(),
});

export type Enumerated = z.infer<typeof EnumeratedSchema>;

// An authentication attempt establishes a session
export const EstablishesSchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // When session was established
  timestamp: z.number().optional(),
});

export type Establishes = z.infer<typeof EstablishesSchema>;

// An attack technique or exploit accessed a file
export const AccessedFileSchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // When file was accessed
  timestamp: z.number().optional(),
  // Number of bytes read if applicable
  bytes_read: z.number().int().optional(),
});

export type AccessedFile = z.infer<typeof AccessedFileSchema>;

// A file system access revealed information or findings
export const RevealedSchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // When information was revealed
  timestamp: z.number().optional(),
  // Type of information revealed
  revelation_type: z.enum(["credentials", "configuration", "system_info", "vulnerability", "other"]).optional(),
});

export type Revealed = z.infer<typeof RevealedSchema>;

// An exploitation attempt uses a specific XML payload
export const UsesPayloadSchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // When payload was used
  timestamp: z.number().optional(),
  // Sequential attempt number
  attempt_number: z.number().int().optional(),
});

export type UsesPayload = z.infer<typeof UsesPayloadSchema>;

// An XML payload triggered an out-of-band interaction
export const OobInteractionSchema = z.object({
  // Taxonomy schema version
  version: z.number().int().optional(),
  // When interaction occurred
  timestamp: z.number().optional(),
  // Type of OOB interaction
  interaction_type: z.enum(["http_callback", "dns_query", "ftp_connection", "other"]).optional(),
  // Data exfiltrated via OOB channel (preview)
  data_exfiltrated: z.string().optional(),
});

export type OobInteraction = z.infer<typeof OobInteractionSchema>;


