# Pentagi Taxonomy Python Package (v1)

Auto-generated Python package containing Pydantic models for pentesting entities.

## Installation

Install directly from GitHub:

```bash
pip install git+https://github.com/vxcontrol/pentagi-taxonomy.git#subdirectory=v1/python
```

## Usage

```python
from pentagi_taxonomy import TAXONOMY_VERSION
from pentagi_taxonomy.nodes import Target, Port
from pentagi_taxonomy.edges import HasPort

# Create a target
target = Target(
    hostname="example.com",
    ip_address="192.168.1.1",
    target_type="host",
    risk_score=7.5
)

# Create a port
port = Port(
    port_number=443,
    protocol="tcp",
    state="open"
)

print(f"Using taxonomy version: {TAXONOMY_VERSION}")
```

## Development

Run tests:

```bash
pip install -e .[dev]
pytest tests/
```

