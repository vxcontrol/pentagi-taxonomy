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

// Validate validates a Port entity
func (e *Port) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a HasPort edge
func (e *HasPort) Validate() error {
	return Validator.Struct(e)
}

// Validate validates a Discovered edge
func (e *Discovered) Validate() error {
	return Validator.Struct(e)
}

