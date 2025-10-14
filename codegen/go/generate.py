#!/usr/bin/env python
"""
Go code generator for pentagi-taxonomy.
Generates Go structs with validation tags from YAML entity definitions using Jinja2 templates.
"""

import sys
import re
from pathlib import Path
from typing import Any, Dict, List
from jinja2 import Environment, FileSystemLoader


# Add shared validator to path
sys.path.insert(0, str(Path(__file__).parent.parent / "shared"))
from validator import validate_schema, SchemaValidationError


def to_pascal_case(snake_case: str) -> str:
    """Convert snake_case to PascalCase."""
    return ''.join(word.capitalize() for word in snake_case.split('_'))


def go_type_from_yaml(yaml_type: str) -> str:
    """Convert YAML type to Go type."""
    if yaml_type.endswith("[]"):
        base_type = yaml_type[:-2]
        go_base = go_type_from_yaml(base_type)
        return f"*[]{go_base}"
    
    type_map = {
        "string": "*string",
        "int": "*int",
        "float": "*float64",
        "boolean": "*bool",
        "timestamp": "*float64",
    }
    return type_map.get(yaml_type, "*string")


def is_ipv4_regex(regex: str) -> bool:
    """Check if regex pattern matches IPv4."""
    ipv4_patterns = [
        r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$",
        r"^(?:[0-9]+\.){3}[0-9]+$",
    ]
    normalized = regex.replace("\\\\", "\\")
    return any(pattern in normalized for pattern in ipv4_patterns)


def validation_tag_from_field(field_def: Dict[str, Any]) -> str:
    """Generate validator/v10 struct tag for a field."""
    yaml_type = field_def.get("type", "string")
    base_type = yaml_type.rstrip("[]")
    
    tags = ["omitempty"]
    
    # Enum validation
    if "enum" in field_def:
        enum_values = field_def["enum"]
        enum_str = " ".join(enum_values)
        tags.append(f"oneof={enum_str}")
    
    # Regex validation (map to built-in validators where possible)
    if "regex" in field_def and "enum" not in field_def:
        regex = field_def["regex"]
        if is_ipv4_regex(regex):
            tags.append("ipv4")
        elif "email" in regex.lower():
            tags.append("email")
        elif regex.startswith("^https?://"):
            tags.append("url")
        # For other regex patterns, we'd need custom validators
        # For now, skip custom regex validators in generated code
    
    # Min/max validation
    if "min" in field_def:
        tags.append(f"min={field_def['min']}")
    if "max" in field_def:
        tags.append(f"max={field_def['max']}")
    
    if len(tags) > 1:  # More than just "omitempty"
        return f'validate:"{",".join(tags)}"'
    return ""


def prepare_field_for_go(field_name: str, field_def: Dict[str, Any]) -> Dict[str, Any]:
    """Prepare field data for Go struct generation."""
    go_type = go_type_from_yaml(field_def.get("type", "string"))
    go_name = to_pascal_case(field_name)
    
    # Build struct tags
    json_tag = f'json:"{field_name},omitempty"'
    validate_tag = validation_tag_from_field(field_def)
    
    if validate_tag:
        struct_tag = f'`{json_tag} {validate_tag}`'
    else:
        struct_tag = f'`{json_tag}`'
    
    return {
        "go_name": go_name,
        "go_type": go_type,
        "struct_tag": struct_tag,
        "description": field_def.get("description", "")
    }


def prepare_nodes_data(schema: Dict[str, Any]) -> Dict[str, Any]:
    """Prepare node data for template rendering."""
    nodes = {}
    for node_name, node_def in schema.get("nodes", {}).items():
        fields = {}
        for field_name, field_def in node_def.get("fields", {}).items():
            fields[field_name] = prepare_field_for_go(field_name, field_def)
        
        nodes[node_name] = {
            "description": node_def.get("description", ""),
            "fields": fields
        }
    
    return nodes


def prepare_edges_data(schema: Dict[str, Any]) -> Dict[str, Any]:
    """Prepare edge data for template rendering."""
    edges = {}
    for edge_name, edge_def in schema.get("edges", {}).items():
        # Convert SCREAMING_SNAKE_CASE to PascalCase
        class_name = ''.join(word.capitalize() for word in edge_name.split('_'))
        
        fields = {}
        for field_name, field_def in edge_def.get("fields", {}).items():
            fields[field_name] = prepare_field_for_go(field_name, field_def)
        
        edges[edge_name] = {
            "class_name": class_name,
            "description": edge_def.get("description", ""),
            "fields": fields
        }
    
    return edges


def main():
    if len(sys.argv) != 2:
        print("Usage: python generate.py <version>")
        print("Example: python generate.py 2")
        sys.exit(1)
    
    version_arg = sys.argv[1]
    
    # Determine paths
    codegen_dir = Path(__file__).parent.parent.parent
    version_dir = codegen_dir / f"v{version_arg}"
    schema_path = version_dir / "entities.yml"
    output_dir = version_dir / "go"
    entities_dir = output_dir / "entities"
    templates_dir = codegen_dir / "codegen" / "templates" / "go"
    
    print(f"Generating Go code for version {version_arg}...")
    print(f"  Schema: {schema_path}")
    print(f"  Output: {output_dir}")
    
    # Validate schema
    try:
        schema = validate_schema(schema_path)
    except SchemaValidationError as e:
        print(f"✗ Schema validation failed: {e}", file=sys.stderr)
        sys.exit(1)
    
    schema_version = schema.get("version", int(version_arg))
    
    # Create output directories
    entities_dir.mkdir(parents=True, exist_ok=True)
    
    # Setup Jinja2 environment
    env = Environment(loader=FileSystemLoader(templates_dir), trim_blocks=True, lstrip_blocks=True)
    
    # Prepare data for templates
    nodes_data = prepare_nodes_data(schema)
    edges_data = prepare_edges_data(schema)
    
    # Generate files
    print("  Generating go.mod...")
    go_mod_template = env.get_template("go.mod.j2")
    go_mod = go_mod_template.render(version=schema_version, org="vxcontrol")
    (output_dir / "go.mod").write_text(go_mod)
    
    print("  Generating entities/entities.go...")
    entities_template = env.get_template("entities.go.j2")
    entities_content = entities_template.render(nodes=nodes_data, edges=edges_data)
    (entities_dir / "entities.go").write_text(entities_content)
    
    print("  Generating entities/validators.go...")
    validators_template = env.get_template("validators.go.j2")
    validators_content = validators_template.render(nodes=nodes_data, edges=edges_data)
    (entities_dir / "validators.go").write_text(validators_content)
    
    print(f"✓ Go code generation complete!")
    print(f"  Generated {len(nodes_data)} node structs")
    print(f"  Generated {len(edges_data)} edge structs")


if __name__ == "__main__":
    main()
