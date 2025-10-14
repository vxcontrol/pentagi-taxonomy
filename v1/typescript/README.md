# Pentagi Taxonomy TypeScript Package (v1)

Auto-generated TypeScript package with Zod schemas for pentesting entities.

## Installation

Install via gitpkg (with automatic build):

```bash
npm install 'https://gitpkg.now.sh/vxcontrol/pentagi-taxonomy/v1/typescript?main&scripts.postinstall=npm%20install%20--ignore-scripts%20%26%26%20npm%20run%20build'
```

Or add to package.json with an alias:

```json
{
  "dependencies": {
    "@pentagi/taxonomy-v1": "https://gitpkg.now.sh/vxcontrol/pentagi-taxonomy/v1/typescript?main&scripts.postinstall=npm%20install%20--ignore-scripts%20%26%26%20npm%20run%20build"
  }
}
```

## Usage

```typescript
import { TargetSchema, Target, PortSchema } from 'pentagi-taxonomy';
import { TAXONOMY_VERSION } from 'pentagi-taxonomy';

// Create and validate a target
const target: Target = {
  hostname: 'example.com',
  ip_address: '192.168.1.1',
  target_type: 'host',
  risk_score: 7.5
};

// Runtime validation
const result = TargetSchema.safeParse(target);
if (result.success) {
  console.log('Valid target:', result.data);
} else {
  console.error('Validation errors:', result.error.errors);
}

console.log(`Using taxonomy version: ${TAXONOMY_VERSION}`);
```

## Development

Build the package:

```bash
npm install
npm run build
```

