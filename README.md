# Pentagi Taxonomy

A versioned, multi-language entity taxonomy for penetration testing and security assessment tools. Define your entity schema once in YAML, and automatically generate type-safe code for Python, Go, and TypeScript.

## Overview

Pentagi Taxonomy is a code generation framework that helps you maintain consistent entity definitions across multiple programming languages. It's designed for penetration testing tools but can be adapted for any domain that requires versioned entity schemas.

**Key Features:**
- 🔄 **Single Source of Truth**: Define entities, fields, and relationships once in YAML
- 🛡️ **Type Safety**: Generate Pydantic models (Python), structs with validation (Go), and Zod schemas (TypeScript)
- 📦 **Multi-Version Support**: Maintain multiple schema versions simultaneously
- ✅ **Built-in Validation**: Comprehensive schema validation with field constraints
- 🚀 **Easy to Use**: Simple Makefile-based workflow

## Project Structure

```
pentagi-taxonomy/
├── version.yml              # Current global taxonomy version
├── v1/                      # Version 1 of the taxonomy
│   ├── entities.yml         # Entity definitions (nodes, edges, relationships)
│   ├── python/              # Generated Python package
│   ├── go/                  # Generated Go package
│   └── typescript/          # Generated TypeScript package
├── codegen/                 # Code generation infrastructure
│   ├── python/
│   │   └── generate.py      # Python code generator
│   ├── go/
│   │   └── generate.py      # Go code generator
│   ├── typescript/
│   │   └── generate.py      # TypeScript code generator
│   ├── shared/
│   │   └── validator.py     # Schema validation logic
│   └── templates/           # Jinja2 templates for each language
│       ├── python/
│       ├── go/
│       └── typescript/
└── Makefile                 # Convenience commands for common tasks
```

## How It Works

1. **Define Schema**: Create or modify `entities.yml` in a version directory (e.g., `v1/entities.yml`)
2. **Validate**: Run validation to ensure schema correctness
3. **Generate Code**: Generate type-safe code for Python, Go, and TypeScript
4. **Use**: Import and use the generated packages in your projects

### Entity Schema Format

The `entities.yml` file defines three main sections:

#### 1. Nodes (Entities)

Nodes represent primary entities in your domain:

```yaml
nodes:
  Target:
    description: "A target system being assessed"
    fields:
      uuid:
        type: string
        description: "Unique identifier"
      hostname:
        type: string
        description: "DNS hostname if known"
      ip_address:
        type: string
        description: "IP address"
        regex: "^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$"
      status:
        type: string
        description: "Current status"
        enum: [active, inactive, scanning]
      risk_score:
        type: float
        description: "Risk score"
        min: 0.0
        max: 10.0
```

#### 2. Edges (Relationships)

Edges represent relationships between nodes:

```yaml
edges:
  HAS_PORT:
    description: "A target has a port"
    fields:
      timestamp:
        type: timestamp
        description: "When association was established"
  
  AFFECTS:
    description: "A vulnerability affects a target"
    fields:
      timestamp:
        type: timestamp
        description: "When identified"
      impact:
        type: string
        enum: [direct, indirect]
```

#### 3. Relationships

Define which nodes can be connected by which edges:

```yaml
relationships:
  - source: Target
    target: Port
    edges: [HAS_PORT]
  
  - source: Vulnerability
    target: Target
    edges: [AFFECTS]
```

### Supported Field Types

- `string` - Text values
- `int` - Integer numbers
- `float` - Floating-point numbers
- `boolean` - True/false values
- `timestamp` - Unix timestamps (float)
- Arrays: Add `[]` suffix (e.g., `string[]`, `int[]`)

### Field Constraints

- `enum: [value1, value2]` - Restrict to enumerated values (string only)
- `regex: "pattern"` - Validate against regex pattern (string only)
- `min: value` - Minimum value (numeric types only)
- `max: value` - Maximum value (numeric types only)
- `description: "text"` - Field documentation

## Quick Start

### Prerequisites

- Python 3.8+ (for code generation)
- Make (for convenience commands)
- Language-specific tools for using generated code:
  - Python: `pip`
  - Go: Go 1.19+
  - TypeScript: Node.js 16+

### Installation

1. Clone the repository:
```bash
git clone https://github.com/vxcontrol/pentagi-taxonomy.git
cd pentagi-taxonomy
```

2. Install code generation dependencies:
```bash
pip install -r codegen/requirements.txt
```

### Basic Usage

Generate code for the latest version (v1):

```bash
# Full workflow: validate → generate → test
make all VERSION=1

# Or step by step:
make validate VERSION=1      # Validate schema
make generate VERSION=1      # Generate code for all languages
make test VERSION=1          # Run tests
```

Generate code for a specific language:

```bash
make generate-python VERSION=1
make generate-go VERSION=1
make generate-typescript VERSION=1
```

## Makefile Commands

| Command | Description | Example |
|---------|-------------|---------|
| `make help` | Show all available commands | `make help` |
| `make all VERSION=N` | Run full cycle (validate → generate → test) | `make all VERSION=1` |
| `make validate VERSION=N` | Validate schema for version N | `make validate VERSION=1` |
| `make validate-all` | Validate all version schemas | `make validate-all` |
| `make generate VERSION=N` | Generate code for all languages | `make generate VERSION=1` |
| `make generate-python VERSION=N` | Generate only Python code | `make generate-python VERSION=1` |
| `make generate-go VERSION=N` | Generate only Go code | `make generate-go VERSION=1` |
| `make generate-typescript VERSION=N` | Generate only TypeScript code | `make generate-typescript VERSION=1` |
| `make test VERSION=N` | Run Python tests | `make test VERSION=1` |
| `make test-all` | Run tests for all versions | `make test-all` |
| `make clean VERSION=N` | Remove generated files for version N | `make clean VERSION=1` |
| `make clean-all` | Remove all generated files | `make clean-all` |
| `make bump-version` | Create new major version | `make bump-version` |

## Using Generated Code

### Python

```python
from pentagi_taxonomy import TAXONOMY_VERSION
from pentagi_taxonomy.nodes import Target, Port, Vulnerability
from pentagi_taxonomy.edges import HasPort, Affects

# Create entities with type checking and validation
target = Target(
    uuid="target-123",
    hostname="example.com",
    ip_address="192.168.1.1",
    status="active",
    risk_score=7.5
)

vulnerability = Vulnerability(
    uuid="vuln-456",
    title="SQL Injection",
    severity="critical",
    cvss_score=9.8,
    exploitable=True
)

# Validation happens automatically
print(f"Using taxonomy version: {TAXONOMY_VERSION}")
print(target.model_dump_json())
```

Install the Python package:
```bash
# Development mode
cd v1/python
pip install -e .

# Or from Git
pip install git+https://github.com/vxcontrol/pentagi-taxonomy.git@f08fc9160ab46feb21408a5e641c22c6cda48e45#subdirectory=v1/python
```

### Go

```go
package main

import (
    "fmt"
    "github.com/vxcontrol/pentagi-taxonomy/v1/go/entities"
)

func main() {
    target := entities.Target{
        UUID:      "target-123",
        Hostname:  "example.com",
        IPAddress: "192.168.1.1",
        Status:    "active",
        RiskScore: 7.5,
    }
    
    // Validate the entity
    if err := target.Validate(); err != nil {
        panic(err)
    }
    
    fmt.Printf("Target: %+v\n", target)
}
```

## TypeScript Installation with gitpkg

### gitpkg URL Format

```
https://gitpkg.now.sh/<owner>/<repo>/<path/to/package>?<branch-or-tag>&<custom-scripts>
```

**Components:**
- `<owner>/<repo>` - GitHub repository (e.g., `vxcontrol/pentagi-taxonomy`)
- `<path/to/package>` - Subdirectory path containing `package.json` (e.g., `v1/typescript`)
- `?<branch-or-tag>` - Git reference: branch name (`main`) or tag (`v1.1.0`)
- `&<custom-scripts>` - Optional custom npm scripts to run after installation

### Automatic Build Configuration

Since gitpkg fetches source code (not compiled JavaScript), we use the `scripts.postinstall` parameter to automatically build the package after installation:

```
scripts.postinstall=npm%20install%20--ignore-scripts%20%26%26%20npm%20run%20build
```

This eliminates manual build steps - the package compiles automatically after `npm install`.

### Installation Examples

```bash
# Install from specific tag (pinned version) with automatic build
npm install 'https://gitpkg.now.sh/vxcontrol/pentagi-taxonomy/v1/typescript?v1.1.0&scripts.postinstall=npm%20install%20--ignore-scripts%20%26%26%20npm%20run%20build'
```

### Using Multiple Versions with Aliases

Add to your `package.json` with npm aliases to use multiple versions simultaneously:

```json
{
  "dependencies": {
    "@pentagi/taxonomy-v1": "https://gitpkg.now.sh/vxcontrol/pentagi-taxonomy/v1/typescript?main&scripts.postinstall=npm%20install%20--ignore-scripts%20%26%26%20npm%20run%20build"
  }
}
```

Then import from aliased packages:

```typescript
import { TargetSchema as TargetV1 } from '@pentagi/taxonomy-v1';
```

### Updating Packages

When the taxonomy is updated on GitHub, refresh your installation:

```bash
# Clear npm cache (gitpkg caches packages)
npm cache clean --force

# Remove node_modules and reinstall
rm -rf node_modules package-lock.json
npm install
```

The `scripts.postinstall` parameter automatically rebuilds the packages after installation.

## Version Management

### Creating a New Version

To create a new major version of the taxonomy:

```bash
make bump-version
```

This will:
1. Read the current version from `version.yml`
2. Create a new version directory (e.g., `v3/`)
3. Copy the previous version's `entities.yml` as a starting point
4. Update the version number in the new `entities.yml`
5. Update `version.yml` to point to the new version

After creating a new version:
1. Edit `vN/entities.yml` with your changes
2. Validate: `make validate VERSION=N`
3. Generate code: `make generate VERSION=N`
4. Test: `make test VERSION=N`
5. Commit the new version

### Version Compatibility

Each version is independent and can be used simultaneously. This allows:
- Gradual migration between versions
- Supporting multiple API versions
- Maintaining backward compatibility

## Development Workflow

### Adding a New Entity

1. Edit `vN/entities.yml` to add your node definition
2. Validate the schema:
   ```bash
   make validate VERSION=N
   ```
3. Generate code:
   ```bash
   make generate VERSION=N
   ```
4. Review generated code in `vN/python/`, `vN/go/`, and `vN/typescript/`
5. Run tests:
   ```bash
   make test VERSION=N
   ```

### Modifying Existing Entities

For **backward-compatible changes** (adding optional fields):
- Modify the current version's `entities.yml`
- Regenerate code

For **breaking changes** (removing fields, changing types):
- Create a new major version with `make bump-version`
- Make changes in the new version
- Keep the old version for backward compatibility

### Adding Custom Validation

You can extend the generated code with custom validation:

**Python**: Subclass the generated models and add Pydantic validators
**Go**: Add methods to the generated structs
**TypeScript**: Use Zod's refinement methods

## Testing

The Python packages include basic tests. Run them with:

```bash
# Test specific version
make test VERSION=1

# Test all versions
make test-all

# Or manually
cd 1/python
pytest tests/ -v
```
