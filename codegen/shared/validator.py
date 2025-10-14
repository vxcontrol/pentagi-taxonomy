"""
Shared schema validation logic for pentagi-taxonomy.
Used by all code generators to ensure consistent validation.
"""

import yaml
from typing import Any, Dict, List, Set
from pathlib import Path


SUPPORTED_PRIMITIVE_TYPES = {"string", "int", "float", "boolean", "timestamp"}


class SchemaValidationError(Exception):
    """Exception raised for schema validation errors."""
    pass


def validate_field_type(field_name: str, field_def: Dict[str, Any], entity_type: str) -> None:
    """Validate that a field has a supported type."""
    if "type" not in field_def:
        raise SchemaValidationError(
            f"Field '{field_name}' in {entity_type} must have a 'type' property"
        )
    
    field_type = field_def["type"]
    
    # Check for array types
    if field_type.endswith("[]"):
        base_type = field_type[:-2]
        if base_type not in SUPPORTED_PRIMITIVE_TYPES:
            raise SchemaValidationError(
                f"Field '{field_name}' in {entity_type} has unsupported array base type '{base_type}'. "
                f"Supported types: {', '.join(SUPPORTED_PRIMITIVE_TYPES)}"
            )
    elif field_type not in SUPPORTED_PRIMITIVE_TYPES:
        raise SchemaValidationError(
            f"Field '{field_name}' in {entity_type} has unsupported type '{field_type}'. "
            f"Supported types: {', '.join(SUPPORTED_PRIMITIVE_TYPES)} and arrays of these (e.g., 'string[]')"
        )


def validate_field_constraints(field_name: str, field_def: Dict[str, Any], entity_type: str) -> None:
    """Validate field validation constraints are appropriate for the field type."""
    field_type = field_def.get("type", "")
    base_type = field_type.rstrip("[]")
    
    # Validate enum constraints
    if "enum" in field_def:
        if base_type != "string":
            raise SchemaValidationError(
                f"Field '{field_name}' in {entity_type} has 'enum' constraint but type is '{field_type}'. "
                f"Enum constraints are only valid for 'string' type."
            )
        enum_values = field_def["enum"]
        if not isinstance(enum_values, list) or len(enum_values) == 0:
            raise SchemaValidationError(
                f"Field '{field_name}' in {entity_type} has invalid 'enum' constraint. "
                f"Must be a non-empty list."
            )
    
    # Validate regex constraints
    if "regex" in field_def:
        if base_type != "string":
            raise SchemaValidationError(
                f"Field '{field_name}' in {entity_type} has 'regex' constraint but type is '{field_type}'. "
                f"Regex constraints are only valid for 'string' type."
            )
    
    # Validate min/max constraints
    if "min" in field_def or "max" in field_def:
        if base_type not in ["int", "float", "timestamp"]:
            raise SchemaValidationError(
                f"Field '{field_name}' in {entity_type} has min/max constraint but type is '{field_type}'. "
                f"Min/max constraints are only valid for numeric types (int, float, timestamp)."
            )
        
        # Validate min <= max
        if "min" in field_def and "max" in field_def:
            min_val = field_def["min"]
            max_val = field_def["max"]
            if min_val > max_val:
                raise SchemaValidationError(
                    f"Field '{field_name}' in {entity_type} has min ({min_val}) > max ({max_val}). "
                    f"Min must be less than or equal to max."
                )


def validate_relationships(schema: Dict[str, Any]) -> None:
    """Validate that all entities referenced in relationships are defined in nodes."""
    if "relationships" not in schema:
        return
    
    nodes = set(schema.get("nodes", {}).keys())
    edges = set(schema.get("edges", {}).keys())
    
    for i, rel in enumerate(schema["relationships"]):
        if "source" not in rel:
            raise SchemaValidationError(
                f"Relationship #{i+1} missing 'source' field"
            )
        if "target" not in rel:
            raise SchemaValidationError(
                f"Relationship #{i+1} missing 'target' field"
            )
        if "edges" not in rel:
            raise SchemaValidationError(
                f"Relationship #{i+1} missing 'edges' field"
            )
        
        source = rel["source"]
        target = rel["target"]
        rel_edges = rel["edges"]
        
        if source not in nodes:
            raise SchemaValidationError(
                f"Relationship #{i+1} references undefined source node '{source}'"
            )
        if target not in nodes:
            raise SchemaValidationError(
                f"Relationship #{i+1} references undefined target node '{target}'"
            )
        
        if not isinstance(rel_edges, list) or len(rel_edges) == 0:
            raise SchemaValidationError(
                f"Relationship #{i+1} must have non-empty 'edges' list"
            )
        
        for edge in rel_edges:
            if edge not in edges:
                raise SchemaValidationError(
                    f"Relationship #{i+1} references undefined edge type '{edge}'"
                )


def validate_schema(schema_path: Path) -> Dict[str, Any]:
    """
    Validate a YAML schema file.
    
    Args:
        schema_path: Path to entities.yml file
        
    Returns:
        Parsed schema dictionary
        
    Raises:
        SchemaValidationError: If schema is invalid
    """
    if not schema_path.exists():
        raise SchemaValidationError(f"Schema file not found: {schema_path}")
    
    try:
        with open(schema_path, 'r') as f:
            schema = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise SchemaValidationError(f"Invalid YAML syntax: {e}")
    
    if not isinstance(schema, dict):
        raise SchemaValidationError("Schema must be a dictionary")
    
    # Validate version field
    if "version" not in schema:
        raise SchemaValidationError("Schema must have a 'version' field")
    
    if not isinstance(schema["version"], int):
        raise SchemaValidationError("Schema 'version' must be an integer")
    
    # Validate nodes section
    if "nodes" in schema:
        if not isinstance(schema["nodes"], dict):
            raise SchemaValidationError("'nodes' section must be a dictionary")
        
        for node_name, node_def in schema["nodes"].items():
            if not isinstance(node_def, dict):
                raise SchemaValidationError(f"Node '{node_name}' definition must be a dictionary")
            
            if "fields" not in node_def:
                raise SchemaValidationError(f"Node '{node_name}' must have 'fields' property")
            
            if not isinstance(node_def["fields"], dict):
                raise SchemaValidationError(f"Node '{node_name}' 'fields' must be a dictionary")
            
            for field_name, field_def in node_def["fields"].items():
                if not isinstance(field_def, dict):
                    raise SchemaValidationError(
                        f"Field '{field_name}' in node '{node_name}' must be a dictionary"
                    )
                validate_field_type(field_name, field_def, f"node '{node_name}'")
                validate_field_constraints(field_name, field_def, f"node '{node_name}'")
    
    # Validate edges section
    if "edges" in schema:
        if not isinstance(schema["edges"], dict):
            raise SchemaValidationError("'edges' section must be a dictionary")
        
        for edge_name, edge_def in schema["edges"].items():
            if not isinstance(edge_def, dict):
                raise SchemaValidationError(f"Edge '{edge_name}' definition must be a dictionary")
            
            if "fields" not in edge_def:
                raise SchemaValidationError(f"Edge '{edge_name}' must have 'fields' property")
            
            if not isinstance(edge_def["fields"], dict):
                raise SchemaValidationError(f"Edge '{edge_name}' 'fields' must be a dictionary")
            
            for field_name, field_def in edge_def["fields"].items():
                if not isinstance(field_def, dict):
                    raise SchemaValidationError(
                        f"Field '{field_name}' in edge '{edge_name}' must be a dictionary"
                    )
                validate_field_type(field_name, field_def, f"edge '{edge_name}'")
                validate_field_constraints(field_name, field_def, f"edge '{edge_name}'")
    
    # Validate relationships
    validate_relationships(schema)
    
    return schema


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python validator.py <path-to-entities.yml>")
        sys.exit(1)
    
    schema_path = Path(sys.argv[1])
    
    try:
        schema = validate_schema(schema_path)
        print(f"✓ Schema validation passed for version {schema['version']}")
        print(f"  - {len(schema.get('nodes', {}))} node types")
        print(f"  - {len(schema.get('edges', {}))} edge types")
        print(f"  - {len(schema.get('relationships', []))} relationships")
    except SchemaValidationError as e:
        print(f"✗ Schema validation failed: {e}", file=sys.stderr)
        sys.exit(1)

