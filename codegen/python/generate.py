#!/usr/bin/env python
"""
Python code generator for pentagi-taxonomy.
Generates Pydantic models from YAML entity definitions using Jinja2 templates.
"""

import sys
import yaml
from pathlib import Path
from typing import Any, Dict, List
from jinja2 import Environment, FileSystemLoader


# Add shared validator to path
sys.path.insert(0, str(Path(__file__).parent.parent / "shared"))
from validator import validate_schema, SchemaValidationError


def python_type_from_yaml(yaml_type: str) -> str:
    """Convert YAML type to Python type hint."""
    if yaml_type.endswith("[]"):
        base_type = yaml_type[:-2]
        python_base = python_type_from_yaml(base_type)
        return f"list[{python_base}]"
    
    type_map = {
        "string": "str",
        "int": "int",
        "float": "float",
        "boolean": "bool",
        "timestamp": "float",
    }
    return type_map.get(yaml_type, "str")


def prepare_field_for_pydantic(field_name: str, field_def: Dict[str, Any]) -> Dict[str, Any]:
    """Prepare field data for Pydantic Field definition."""
    yaml_type = field_def.get("type", "string")
    python_type = python_type_from_yaml(yaml_type)
    description = field_def.get("description", "")
    
    # Build Field() arguments
    field_args = ["None"]
    field_kwargs = []
    
    if description:
        field_kwargs.append(f"description={repr(description)}")
    
    # Add validation constraints
    if "min" in field_def:
        field_kwargs.append(f"ge={field_def['min']}")
    if "max" in field_def:
        field_kwargs.append(f"le={field_def['max']}")
    
    # Handle enum as Literal type
    if "enum" in field_def:
        enum_values = field_def["enum"]
        enum_str = ", ".join(repr(v) for v in enum_values)
        python_type = f"Literal[{enum_str}]"
    
    field_call = ", ".join(field_args + field_kwargs)
    
    return {
        "python_type": python_type,
        "field_args": field_call,
        "description": description
    }


def prepare_nodes_data(schema: Dict[str, Any]) -> Dict[str, Any]:
    """Prepare node data for template rendering."""
    nodes = {}
    for node_name, node_def in schema.get("nodes", {}).items():
        fields = {}
        for field_name, field_def in node_def.get("fields", {}).items():
            fields[field_name] = prepare_field_for_pydantic(field_name, field_def)
        
        nodes[node_name] = {
            "description": node_def.get("description", ""),
            "fields": fields
        }
    
    return nodes


def prepare_edges_data(schema: Dict[str, Any]) -> Dict[str, Any]:
    """Prepare edge data for template rendering."""
    edges = {}
    for edge_name, edge_def in schema.get("edges", {}).items():
        # Convert SCREAMING_SNAKE_CASE to PascalCase for class name
        class_name = ''.join(word.capitalize() for word in edge_name.split('_'))
        
        fields = {}
        for field_name, field_def in edge_def.get("fields", {}).items():
            fields[field_name] = prepare_field_for_pydantic(field_name, field_def)
        
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
    output_dir = version_dir / "python" / "pentagi_taxonomy"
    templates_dir = codegen_dir / "codegen" / "templates" / "python"
    
    print(f"Generating Python code for version {version_arg}...")
    print(f"  Schema: {schema_path}")
    print(f"  Output: {output_dir}")
    
    # Validate schema
    try:
        schema = validate_schema(schema_path)
    except SchemaValidationError as e:
        print(f"✗ Schema validation failed: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Read global version from version.yml
    version_yml_path = codegen_dir / "version.yml"
    with open(version_yml_path, 'r') as f:
        version_data = yaml.safe_load(f)
        global_version = version_data.get("version", int(version_arg))
    
    # Use the version from the schema file itself
    schema_version = schema.get("version", int(version_arg))
    
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Setup Jinja2 environment
    env = Environment(loader=FileSystemLoader(templates_dir), trim_blocks=True, lstrip_blocks=True)
    
    # Prepare data for templates
    nodes_data = prepare_nodes_data(schema)
    edges_data = prepare_edges_data(schema)
    
    # Generate files
    print("  Generating __init__.py...")
    init_template = env.get_template("__init__.py.j2")
    init_content = init_template.render(version=schema_version)
    (output_dir / "__init__.py").write_text(init_content)
    
    print("  Generating nodes.py...")
    nodes_template = env.get_template("nodes.py.j2")
    nodes_content = nodes_template.render(nodes=nodes_data)
    (output_dir / "nodes.py").write_text(nodes_content)
    
    print("  Generating edges.py...")
    edges_template = env.get_template("edges.py.j2")
    edges_content = edges_template.render(edges=edges_data)
    (output_dir / "edges.py").write_text(edges_content)
    
    print("  Generating entity_map.py...")
    entity_map_template = env.get_template("entity_map.py.j2")
    entity_map_content = entity_map_template.render(
        nodes=nodes_data,
        edges=edges_data,
        relationships=schema.get("relationships", [])
    )
    (output_dir / "entity_map.py").write_text(entity_map_content)
    
    print(f"✓ Python code generation complete!")
    print(f"  Generated {len(nodes_data)} node models")
    print(f"  Generated {len(edges_data)} edge models")


if __name__ == "__main__":
    main()
