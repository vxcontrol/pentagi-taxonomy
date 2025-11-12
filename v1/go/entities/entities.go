// Auto-generated entity definitions for pentagi-taxonomy.
// DO NOT EDIT - this file is generated from entities.yml

package entities

// Target Network endpoint, service, application, or host being assessed. Should include version information, technology stack, and network details (IP, port, protocol). Examples: 'phpMyAdmin 4.4.15.6 on 172.22.0.7:80', 'Apache 2.4.29 web server'
type Target struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	EntityUuid *string `json:"entity_uuid,omitempty"` // Unique identifier
	Identifier *string `json:"identifier,omitempty"` // Primary identifier (hostname, IP, URL)
	TargetType *string `json:"target_type,omitempty" validate:"omitempty,oneof=host service web_application api_endpoint network_range container"` // Type of target
	Hostname *string `json:"hostname,omitempty"` // DNS hostname if applicable
	IpAddress *string `json:"ip_address,omitempty" validate:"omitempty,ipv4"` // IP address if applicable
	Port *int `json:"port,omitempty" validate:"omitempty,min=1,max=65535"` // Port number if service-specific
	Protocol *string `json:"protocol,omitempty"` // Protocol (HTTP, HTTPS, SSH, etc.)
	TechnologyStack *[]*string `json:"technology_stack,omitempty"` // Technologies detected (PHP, Apache, MySQL, etc.)
	Status *string `json:"status,omitempty" validate:"omitempty,oneof=discovered active compromised analyzed unreachable"` // Current assessment status
}

// Vulnerability Security weakness or attack vector with CVE identifier, vulnerability class, or technical description. Should include severity assessment, exploitability status, version linkage, and test confirmation. Examples: 'CVE-2016-10134 SQLi in jsrpc.php profileIdx', 'XML External Entity (XXE) injection in document parser'
type Vulnerability struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	EntityUuid *string `json:"entity_uuid,omitempty"` // Unique identifier
	VulnerabilityName *string `json:"vulnerability_name,omitempty"` // Vulnerability name or title
	VulnerabilityClass *string `json:"vulnerability_class,omitempty" validate:"omitempty,oneof=sql_injection rce xss xxe ssrf lfi rfi csrf auth_bypass file_upload command_injection buffer_overflow directory_traversal privilege_escalation information_disclosure denial_of_service deserialization path_traversal session_hijacking other"` // OWASP/CWE category of vulnerability
	CveId *string `json:"cve_id,omitempty"` // CVE identifier if applicable
	CvssScore *float64 `json:"cvss_score,omitempty" validate:"omitempty,min=0.0,max=10.0"` // CVSS score if available
	Severity *string `json:"severity,omitempty" validate:"omitempty,oneof=critical high medium low info"` // Severity assessment
	Exploitability *string `json:"exploitability,omitempty" validate:"omitempty,oneof=confirmed_exploitable likely_exploitable theoretical not_exploitable unknown"` // Whether vulnerability can be exploited
	Description *string `json:"description,omitempty"` // Technical description of the vulnerability
	ExploitationTechniquesTested *[]*string `json:"exploitation_techniques_tested,omitempty"` // List of exploitation techniques attempted (e.g., error-based SQLi, time-based SQLi, XXE file read)
	SuccessfulTechniques *[]*string `json:"successful_techniques,omitempty"` // Techniques that successfully exploited this vulnerability
	FailedTechniques *[]*string `json:"failed_techniques,omitempty"` // Techniques that failed to exploit this vulnerability
	XxeParserType *string `json:"xxe_parser_type,omitempty"` // XML parser type if XXE vulnerability (lxml, libxml2, Xerces, etc.)
	XxeProtocolHandlers *[]*string `json:"xxe_protocol_handlers,omitempty"` // Available protocol handlers for XXE (file, http, ftp, expect, php, jar)
	XxeOobConfirmed *bool `json:"xxe_oob_confirmed,omitempty"` // Whether out-of-band XXE interaction was confirmed
}

// Tool Executable scanner, testing tool, or exploitation framework. Extract when tool produces actionable results; note success/failure status. Examples: 'sqlmap', 'nmap', 'metasploit', 'Burp Suite'
type Tool struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	EntityUuid *string `json:"entity_uuid,omitempty"` // Unique identifier
	ToolName *string `json:"tool_name,omitempty"` // Tool name (nmap, sqlmap, metasploit, etc.)
	ToolCategory *string `json:"tool_category,omitempty" validate:"omitempty,oneof=scanner exploitation_framework fuzzer reconnaissance enumeration post_exploitation password_cracker web_proxy network_tool custom_script"` // Category of tool
	VersionUsed *string `json:"version_used,omitempty"` // Version of the tool used
	Purpose *string `json:"purpose,omitempty"` // What the tool was used for in this context
}

// TechnicalFinding Specific security observation or test result. Summarize concisely (max 500 chars), include confidence level, prioritize findings that advance the assessment narrative. Examples: '113 DB tables enumerated via error-based SQLi', '/etc/passwd accessed via XXE: 48 users listed', 'phpMyAdmin version 4.4.15.6 disclosed in HTTP headers'
type TechnicalFinding struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	EntityUuid *string `json:"entity_uuid,omitempty"` // Unique identifier
	FindingType *string `json:"finding_type,omitempty" validate:"omitempty,oneof=version_disclosure open_port exposed_endpoint configuration_issue credential sensitive_data exploit_success reconnaissance_data vulnerability_confirmation patch_status service_banner database_enumeration authentication_result"` // Type of finding
	Title *string `json:"title,omitempty"` // Brief title of the finding
	Content *string `json:"content,omitempty"` // Detailed finding content (sanitized and summarized)
	Confidence *float64 `json:"confidence,omitempty" validate:"omitempty,min=0.0,max=1.0"` // Confidence in the finding
	Severity *string `json:"severity,omitempty" validate:"omitempty,oneof=critical high medium low info"` // Severity of the finding
	Evidence *string `json:"evidence,omitempty"` // Key evidence supporting the finding (truncated)
	ExtractionTechnique *string `json:"extraction_technique,omitempty"` // How data was extracted (e.g., error-based SQLi, time-based, manual)
	DataType *string `json:"data_type,omitempty" validate:"omitempty,oneof=database_schema user_info configuration privileges file_content command_output network_data session_info other"` // Type of data in this finding
}

// AttackTechnique Specific exploitation method with technical details and payload information. Should map to MITRE ATT&CK taxonomy when applicable, record success/failure, and include actual payloads used. Examples: 'Error-based SQLi via updatexml()', 'Time-based blind SQLi with sleep()', 'Out-of-band XXE data exfiltration'
type AttackTechnique struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	EntityUuid *string `json:"entity_uuid,omitempty"` // Unique identifier
	AttackTechniqueName *string `json:"attack_technique_name,omitempty"` // Name of the attack technique
	TechniqueCategory *string `json:"technique_category,omitempty" validate:"omitempty,oneof=initial_access execution persistence privilege_escalation defense_evasion credential_access discovery lateral_movement collection exfiltration impact"` // MITRE ATT&CK category
	Description *string `json:"description,omitempty"` // Description of how the technique works
	Payload *string `json:"payload,omitempty"` // Actual payload or command used (sanitized)
	SuccessIndicator *string `json:"success_indicator,omitempty"` // What indicates successful execution
}

// TestPhase A phase or stage of the penetration testing engagement
type TestPhase struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	EntityUuid *string `json:"entity_uuid,omitempty"` // Unique identifier
	TestPhaseName *string `json:"test_phase_name,omitempty" validate:"omitempty,oneof=reconnaissance scanning enumeration vulnerability_analysis exploitation post_exploitation reporting cleanup"` // Name of the test phase
	Objective *string `json:"objective,omitempty"` // Objective of this phase
	Status *string `json:"status,omitempty" validate:"omitempty,oneof=not_started in_progress completed blocked skipped"` // Status of the phase
	StartTimestamp *float64 `json:"start_timestamp,omitempty"` // When phase started
	EndTimestamp *float64 `json:"end_timestamp,omitempty"` // When phase completed
}

// Credential Actual authentication credentials with values (ALWAYS extract, including default credentials). Should include privilege level, discovery source, authentication status, and session tokens when applicable. Examples: 'Admin/zabbix', 'root/password', 'zbx_sessionid=0a0f93de...', 'API key: sk-abc123...'
type Credential struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	EntityUuid *string `json:"entity_uuid,omitempty"` // Unique identifier
	CredentialType *string `json:"credential_type,omitempty" validate:"omitempty,oneof=username_password api_key token ssh_key certificate hash cookie"` // Type of credential
	Username *string `json:"username,omitempty"` // Username if applicable
	IsValid *bool `json:"is_valid,omitempty"` // Whether credential is valid
	IsDefault *bool `json:"is_default,omitempty"` // Whether this is a default credential (e.g., Admin/zabbix)
	PrivilegeLevel *string `json:"privilege_level,omitempty" validate:"omitempty,oneof=admin user guest service_account root unknown"` // Privilege level of the credential
	Source *string `json:"source,omitempty"` // How the credential was obtained
	AuthenticationState *string `json:"authentication_state,omitempty" validate:"omitempty,oneof=success failure requires_2fa locked expired unknown"` // Result of authentication attempt with this credential
}

// ExploitCode Actual exploit code, script, or payload used during testing. Should reference target vulnerability, include programming language, and document purpose/objective. Can be proof-of-concept, weaponized exploit, web shell, or reconnaissance script.
type ExploitCode struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	EntityUuid *string `json:"entity_uuid,omitempty"` // Unique identifier
	ExploitCodeName *string `json:"exploit_code_name,omitempty"` // Name of the exploit
	Language *string `json:"language,omitempty" validate:"omitempty,oneof=python bash php ruby powershell javascript go other"` // Programming language
	Purpose *string `json:"purpose,omitempty"` // What the exploit is designed to achieve
	FilePath *string `json:"file_path,omitempty"` // Path where exploit was saved
	CodeType *string `json:"code_type,omitempty" validate:"omitempty,oneof=proof_of_concept weaponized_exploit web_shell reverse_shell payload script reconnaissance_tool"` // Type of code
}

// AuthenticationAttempt Login attempt (success or failure), session establishment (cookies/tokens/CSRF), credential validation, or bypass attempt. Should capture authentication state changes, privilege levels obtained, session tokens, and response details.
type AuthenticationAttempt struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	EntityUuid *string `json:"entity_uuid,omitempty"` // Unique identifier
	Timestamp *float64 `json:"timestamp,omitempty"` // When authentication was attempted
	Success *bool `json:"success,omitempty"` // Whether authentication succeeded
	CredentialUsed *string `json:"credential_used,omitempty"` // Reference to credential entity used
	SessionEstablished *bool `json:"session_established,omitempty"` // Whether a session was established
	ResponseCode *int `json:"response_code,omitempty"` // HTTP response code if applicable
	ErrorMessage *string `json:"error_message,omitempty"` // Error message if authentication failed
}

// DatabaseMetadata Database configuration, schema, and structure information. Should include SQLi payload types used for extraction, enumeration results (tables/columns), user privileges, configuration details, and technique comparisons. Avoid duplicate error entries. Examples: 'MySQL 5.7.33 with FILE privilege', '113 tables enumerated: users, sessions, config, logs...'
type DatabaseMetadata struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	EntityUuid *string `json:"entity_uuid,omitempty"` // Unique identifier
	DatabaseType *string `json:"database_type,omitempty" validate:"omitempty,oneof=mysql postgresql mssql oracle mongodb redis other"` // Type of database
	DatabaseVersion *string `json:"database_version,omitempty"` // Database version if known
	DatabaseUser *string `json:"database_user,omitempty"` // Database user (e.g., root@172.22.0.7)
	TableCount *int `json:"table_count,omitempty"` // Number of tables discovered
	TableNames *[]*string `json:"table_names,omitempty"` // List of table names discovered
	Privileges *[]*string `json:"privileges,omitempty"` // User privileges (e.g., FILE, SELECT, INSERT)
	SecureFilePriv *string `json:"secure_file_priv,omitempty"` // secure_file_priv setting value
	ConfigurationDetails *string `json:"configuration_details,omitempty"` // Other relevant configuration information
}

// ExploitationAttempt A specific exploitation attempt with a technique
type ExploitationAttempt struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	EntityUuid *string `json:"entity_uuid,omitempty"` // Unique identifier
	Timestamp *float64 `json:"timestamp,omitempty"` // When exploitation was attempted
	TechniqueType *string `json:"technique_type,omitempty" validate:"omitempty,oneof=error_based_sqli time_based_sqli boolean_based_sqli union_based_sqli file_inclusion command_injection xxe buffer_overflow other"` // Type of exploitation technique
	Success *bool `json:"success,omitempty"` // Whether exploitation succeeded
	Payload *string `json:"payload,omitempty"` // Payload used (sanitized)
	ResponseHash *string `json:"response_hash,omitempty"` // Hash of response for deduplication
	ResultSummary *string `json:"result_summary,omitempty"` // Summary of what happened
}

// SessionInfo Session tokens, cookies, and authentication state AFTER successful authentication
type SessionInfo struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	EntityUuid *string `json:"entity_uuid,omitempty"` // Unique identifier
	SessionType *string `json:"session_type,omitempty" validate:"omitempty,oneof=cookie token jwt oauth api_key other"` // Type of session mechanism
	SessionId *string `json:"session_id,omitempty"` // Session identifier (e.g., zbx_sessionid value)
	CsrfToken *string `json:"csrf_token,omitempty"` // CSRF token if applicable
	EstablishedAt *float64 `json:"established_at,omitempty"` // When session was established
	ExpiresAt *float64 `json:"expires_at,omitempty"` // When session expires (if known)
	PrivilegeLevel *string `json:"privilege_level,omitempty" validate:"omitempty,oneof=guest user admin root unknown"` // Privilege level of this session
}

// FileSystemAccess File system access attempt and result. For successful reads, include file path and content preview. Document permission boundaries, file types accessed, and sensitivity level. Skip duplicate permission denials (keep first only) and verbose methodology without results. Examples: '/etc/passwd read: 48 user accounts', 'SSH private key found at /root/.ssh/id_rsa'
type FileSystemAccess struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	EntityUuid *string `json:"entity_uuid,omitempty"` // Unique identifier
	FilePath *string `json:"file_path,omitempty"` // Path to file or directory accessed
	AccessType *string `json:"access_type,omitempty" validate:"omitempty,oneof=read write execute list stat"` // Type of access attempted
	Success *bool `json:"success,omitempty"` // Whether access was successful
	AccessMethod *string `json:"access_method,omitempty" validate:"omitempty,oneof=xxe lfi rfi command_injection direct_access path_traversal"` // Method used to access file
	ContentPreview *string `json:"content_preview,omitempty"` // Preview of file content if read (truncated to 500 chars)
	PermissionError *string `json:"permission_error,omitempty"` // Permission error message if access denied
	FileType *string `json:"file_type,omitempty" validate:"omitempty,oneof=config credential log system_info ssh_key source_code database other"` // Type of file accessed
	Sensitivity *string `json:"sensitivity,omitempty" validate:"omitempty,oneof=critical high medium low info"` // Sensitivity level of accessed file
}

// XMLPayload XML payload used in XXE exploitation. Should identify XML parser (type/version), protocol handlers available (file/http/ftp/expect/php/jar), successful file reads, OOB interaction confirmations, payload variations tested, and parser configuration. Examples: 'XXE file:// payload reading /etc/passwd', 'OOB XXE via HTTP callback to attacker.com'
type XMLPayload struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	EntityUuid *string `json:"entity_uuid,omitempty"` // Unique identifier
	PayloadType *string `json:"payload_type,omitempty" validate:"omitempty,oneof=file_read oob_exfil rce_attempt ssrf entity_expansion parameter_entity"` // Type of XXE payload
	PayloadContent *string `json:"payload_content,omitempty"` // Actual XML payload (sanitized)
	Encoding *string `json:"encoding,omitempty" validate:"omitempty,oneof=utf-8 utf-16 utf-16be base64 other"` // Payload encoding
	ProtocolHandler *string `json:"protocol_handler,omitempty" validate:"omitempty,oneof=file http https ftp expect php jar data gopher other"` // Protocol handler used in payload
	Success *bool `json:"success,omitempty"` // Whether payload was successful
	ResponseLength *int `json:"response_length,omitempty"` // Length of response in bytes
	OobInteraction *bool `json:"oob_interaction,omitempty"` // Whether OOB interaction was observed
}

// HasVulnerability A target has or is affected by a vulnerability
type HasVulnerability struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	Timestamp *float64 `json:"timestamp,omitempty"` // When vulnerability was identified
	Confidence *float64 `json:"confidence,omitempty" validate:"omitempty,min=0.0,max=1.0"` // Confidence in the vulnerability
	Verified *bool `json:"verified,omitempty"` // Whether vulnerability was verified through exploitation
}

// UsedAgainst A tool or technique was used against a target
type UsedAgainst struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	Timestamp *float64 `json:"timestamp,omitempty"` // When tool was used
	Success *bool `json:"success,omitempty"` // Whether the use was successful
	ExecutionContext *string `json:"execution_context,omitempty"` // Context of tool usage (command line, parameters)
}

// Exploits A technique or exploit code exploits a vulnerability
type Exploits struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	Timestamp *float64 `json:"timestamp,omitempty"` // When exploitation occurred
	Success *bool `json:"success,omitempty"` // Whether exploitation was successful
	Impact *string `json:"impact,omitempty" validate:"omitempty,oneof=full_compromise partial_access information_disclosure denial_of_service none"` // Impact of successful exploitation
}

// DiscoveredIn A finding was discovered during a test phase
type DiscoveredIn struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	Timestamp *float64 `json:"timestamp,omitempty"` // When discovery occurred
	DiscoveryMethod *string `json:"discovery_method,omitempty"` // How the finding was discovered
}

// LeadsTo One finding, technique, or vulnerability leads to another (attack chain)
type LeadsTo struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	Timestamp *float64 `json:"timestamp,omitempty"` // When connection was established
	Reasoning *string `json:"reasoning,omitempty"` // How one leads to the other
}

// Targets A vulnerability, technique, or tool targets a specific target
type Targets struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	Timestamp *float64 `json:"timestamp,omitempty"` // When targeting occurred
}

// ProvidesAccessTo A credential provides access to a target or service
type ProvidesAccessTo struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	Timestamp *float64 `json:"timestamp,omitempty"` // When access was verified
	AccessLevel *string `json:"access_level,omitempty" validate:"omitempty,oneof=read_only read_write administrative root limited"` // Level of access provided
}

// Yields An action, tool use, or technique yields a finding
type Yields struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	Timestamp *float64 `json:"timestamp,omitempty"` // When finding was produced
}

// UsesTool A technique or attack uses a specific tool
type UsesTool struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	Timestamp *float64 `json:"timestamp,omitempty"` // When tool was used
}

// AuthenticatedWith A credential was used to authenticate against a target
type AuthenticatedWith struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	Timestamp *float64 `json:"timestamp,omitempty"` // When authentication occurred
	Success *bool `json:"success,omitempty"` // Whether authentication succeeded
	SessionCreated *string `json:"session_created,omitempty"` // Session ID created (if applicable)
}

// ExtractedFrom A finding was extracted from a target using a specific technique
type ExtractedFrom struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	Timestamp *float64 `json:"timestamp,omitempty"` // When extraction occurred
	ExtractionMethod *string `json:"extraction_method,omitempty"` // Method used for extraction (e.g., error-based SQLi)
}

// Enumerated A tool enumerated database metadata
type Enumerated struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	Timestamp *float64 `json:"timestamp,omitempty"` // When enumeration occurred
	RecordsFound *int `json:"records_found,omitempty"` // Number of records/items found
}

// Establishes An authentication attempt establishes a session
type Establishes struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	Timestamp *float64 `json:"timestamp,omitempty"` // When session was established
}

// AccessedFile An attack technique or exploit accessed a file
type AccessedFile struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	Timestamp *float64 `json:"timestamp,omitempty"` // When file was accessed
	BytesRead *int `json:"bytes_read,omitempty"` // Number of bytes read if applicable
}

// Revealed A file system access revealed information or findings
type Revealed struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	Timestamp *float64 `json:"timestamp,omitempty"` // When information was revealed
	RevelationType *string `json:"revelation_type,omitempty" validate:"omitempty,oneof=credentials configuration system_info vulnerability other"` // Type of information revealed
}

// UsesPayload An exploitation attempt uses a specific XML payload
type UsesPayload struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	Timestamp *float64 `json:"timestamp,omitempty"` // When payload was used
	AttemptNumber *int `json:"attempt_number,omitempty"` // Sequential attempt number
}

// OobInteraction An XML payload triggered an out-of-band interaction
type OobInteraction struct {
	Version *int `json:"version,omitempty"` // Taxonomy schema version
	Timestamp *float64 `json:"timestamp,omitempty"` // When interaction occurred
	InteractionType *string `json:"interaction_type,omitempty" validate:"omitempty,oneof=http_callback dns_query ftp_connection other"` // Type of OOB interaction
	DataExfiltrated *string `json:"data_exfiltrated,omitempty"` // Data exfiltrated via OOB channel (preview)
}


