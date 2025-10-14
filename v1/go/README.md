# Pentagi Taxonomy Go Package (v1)

Auto-generated Go package containing structs with validation for pentesting entities.

## Installation

```bash
go get github.com/vxcontrol/pentagi-taxonomy/v1/go/entities
```

## Usage

```go
package main

import (
    "fmt"
    "github.com/vxcontrol/pentagi-taxonomy/v1/go/entities"
)

func main() {
    hostname := "example.com"
    ipAddr := "192.168.1.1"
    targetType := "host"
    riskScore := 7.5
    
    target := entities.Target{
        Hostname:   &hostname,
        IPAddress:  &ipAddr,
        TargetType: &targetType,
        RiskScore:  &riskScore,
    }
    
    // Validate the entity
    if err := target.Validate(); err != nil {
        fmt.Printf("Validation error: %v\n", err)
        return
    }
    
    fmt.Println("Target is valid!")
}
```

## Development

Run tests:

```bash
go test ./... -v
```

