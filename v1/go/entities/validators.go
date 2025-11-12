// Auto-generated validator helpers for pentagi-taxonomy.
// DO NOT EDIT - this file is generated from entities.yml

package entities

import (
	"github.com/go-playground/validator/v10"
)

// Validator is the shared validator instance for all entities
var Validator *validator.Validate

func init() {
	Validator = validator.New()
	
	// Register custom validators for complex regex patterns here
	// Example: Validator.RegisterValidation("cve_id", cveIDValidator)
}

// Validate validates a Target entity
func (e *Target) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a Vulnerability entity
func (e *Vulnerability) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a Tool entity
func (e *Tool) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a TechnicalFinding entity
func (e *TechnicalFinding) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a AttackTechnique entity
func (e *AttackTechnique) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a TestPhase entity
func (e *TestPhase) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a Credential entity
func (e *Credential) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a ExploitCode entity
func (e *ExploitCode) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a AuthenticationAttempt entity
func (e *AuthenticationAttempt) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a DatabaseMetadata entity
func (e *DatabaseMetadata) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a ExploitationAttempt entity
func (e *ExploitationAttempt) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a SessionInfo entity
func (e *SessionInfo) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a FileSystemAccess entity
func (e *FileSystemAccess) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a XMLPayload entity
func (e *XMLPayload) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a HasVulnerability edge
func (e *HasVulnerability) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a UsedAgainst edge
func (e *UsedAgainst) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a Exploits edge
func (e *Exploits) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a DiscoveredIn edge
func (e *DiscoveredIn) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a LeadsTo edge
func (e *LeadsTo) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a Targets edge
func (e *Targets) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a ProvidesAccessTo edge
func (e *ProvidesAccessTo) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a Yields edge
func (e *Yields) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a UsesTool edge
func (e *UsesTool) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a AuthenticatedWith edge
func (e *AuthenticatedWith) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a ExtractedFrom edge
func (e *ExtractedFrom) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a Enumerated edge
func (e *Enumerated) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a Establishes edge
func (e *Establishes) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a AccessedFile edge
func (e *AccessedFile) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a Revealed edge
func (e *Revealed) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a UsesPayload edge
func (e *UsesPayload) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a OobInteraction edge
func (e *OobInteraction) Validate() error {
	return Validator.Struct(e)
}

