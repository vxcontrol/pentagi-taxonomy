#!/usr/bin/env python
"""
TypeScript code generator for pentagi-taxonomy.
Generates Zod schemas and TypeScript types from YAML entity definitions using Jinja2 templates.
"""

import sys
import json
from pathlib import Path
from typing import Any, Dict, List
from jinja2 import Environment, FileSystemLoader


# Add shared validator to path
sys.path.insert(0, str(Path(__file__).parent.parent / "shared"))
from validator import validate_schema, SchemaValidationError


def ts_type_from_yaml(yaml_type: str) -> str:
    """Convert YAML type to TypeScript type."""
    if yaml_type.endswith("[]"):
        base_type = yaml_type[:-2]
        ts_base = ts_type_from_yaml(base_type)
        return f"{ts_base}[]"
    
    type_map = {
        "string": "string",
        "int": "number",
        "float": "number",
        "boolean": "boolean",
        "timestamp": "number",
    }
    return type_map.get(yaml_type, "string")


def zod_schema_from_field(field_def: Dict[str, Any]) -> str:
    """Generate Zod schema for a field."""
    yaml_type = field_def.get("type", "string")
    
    # Handle arrays
    if yaml_type.endswith("[]"):
        base_type = yaml_type[:-2]
        base_schema = zod_schema_from_field({"type": base_type, **{k: v for k, v in field_def.items() if k != "type"}})
        return f"z.array({base_schema})"
    
    # Base type mapping
    type_map = {
        "string": "z.string()",
        "int": "z.number().int()",
        "float": "z.number()",
        "boolean": "z.boolean()",
        "timestamp": "z.number()",
    }
    
    schema = type_map.get(yaml_type, "z.string()")
    
    # Apply enum constraint
    if "enum" in field_def:
        enum_values = field_def["enum"]
        enum_str = ", ".join(json.dumps(v) for v in enum_values)
        schema = f"z.enum([{enum_str}])"
    
    # Apply regex constraint
    if "regex" in field_def and "enum" not in field_def:
        regex = field_def["regex"]
        schema = f"z.string().regex(/{regex}/)"
    
    # Apply min/max constraints
    if "min" in field_def:
        schema += f".min({field_def['min']})"
    if "max" in field_def:
        schema += f".max({field_def['max']})"
    
    return schema


def prepare_field_for_zod(field_name: str, field_def: Dict[str, Any]) -> Dict[str, Any]:
    """Prepare field data for Zod schema generation."""
    return {
        "zod_schema": zod_schema_from_field(field_def),
        "description": field_def.get("description", "")
    }


def prepare_nodes_data(schema: Dict[str, Any]) -> Dict[str, Any]:
    """Prepare node data for template rendering."""
    nodes = {}
    for node_name, node_def in schema.get("nodes", {}).items():
        fields = {}
        for field_name, field_def in node_def.get("fields", {}).items():
            fields[field_name] = prepare_field_for_zod(field_name, field_def)
        
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
            fields[field_name] = prepare_field_for_zod(field_name, field_def)
        
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
    output_dir = version_dir / "typescript"
    src_dir = output_dir / "src"
    templates_dir = codegen_dir / "codegen" / "templates" / "typescript"
    
    print(f"Generating TypeScript code for version {version_arg}...")
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
    src_dir.mkdir(parents=True, exist_ok=True)
    
    # Setup Jinja2 environment
    env = Environment(loader=FileSystemLoader(templates_dir), trim_blocks=True, lstrip_blocks=True)
    
    # Prepare data for templates
    nodes_data = prepare_nodes_data(schema)
    edges_data = prepare_edges_data(schema)
    
    # Generate files
    print("  Generating package.json...")
    package_template = env.get_template("package.json.j2")
    package_json = package_template.render(version=schema_version)
    (output_dir / "package.json").write_text(package_json)
    
    print("  Generating tsconfig.json...")
    tsconfig_template = env.get_template("tsconfig.json.j2")
    tsconfig = tsconfig_template.render()
    (output_dir / "tsconfig.json").write_text(tsconfig)
    
    print("  Generating src/schemas.ts...")
    schemas_template = env.get_template("schemas.ts.j2")
    schemas_content = schemas_template.render(nodes=nodes_data, edges=edges_data)
    (src_dir / "schemas.ts").write_text(schemas_content)
    
    print("  Generating src/index.ts...")
    index_template = env.get_template("index.ts.j2")
    index_content = index_template.render(version=schema_version)
    (src_dir / "index.ts").write_text(index_content)
    
    print(f"✓ TypeScript code generation complete!")
    print(f"  Generated {len(nodes_data)} node schemas")
    print(f"  Generated {len(edges_data)} edge schemas")


if __name__ == "__main__":
    main()
