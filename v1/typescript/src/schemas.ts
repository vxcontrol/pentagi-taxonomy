/**
 * Auto-generated Zod schemas for pentagi-taxonomy.
 * DO NOT EDIT - this file is generated from entities.yml
 */

import { z } from 'zod';

// A target system being assessed during penetration testing
export const TargetSchema = z.object({
  // Taxonomy schema version (auto-injected by Graphiti fork)
  version: z.number().int().optional(),
  // Unique identifier
  entity_uuid: z.string().optional(),
  // DNS hostname if known
  hostname: z.string().optional(),
  // IP address of the target
  ip_address: z.string().regex(/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/).optional(),
  // Classification of target
  target_type: z.enum(["host", "web_service", "api"]).optional(),
  // Calculated risk score
  risk_score: z.number().min(0.0).max(10.0).optional(),
  // Current status
  status: z.enum(["active", "inactive"]).optional(),
});

export type Target = z.infer<typeof TargetSchema>;

// A network port on a target system
export const PortSchema = z.object({
  // Taxonomy schema version (auto-injected by Graphiti fork)
  version: z.number().int().optional(),
  // Unique identifier
  entity_uuid: z.string().optional(),
  // Port number
  port_number: z.number().int().min(1).max(65535).optional(),
  // Network protocol
  protocol: z.enum(["tcp", "udp"]).optional(),
  // Port state
  state: z.enum(["open", "closed", "filtered"]).optional(),
});

export type Port = z.infer<typeof PortSchema>;

// A target has a port
export const HasPortSchema = z.object({
  // Taxonomy schema version (auto-injected by Graphiti fork)
  version: z.number().int().optional(),
  // When association was established
  timestamp: z.number().optional(),
});

export type HasPort = z.infer<typeof HasPortSchema>;

// An action discovered an entity
export const DiscoveredSchema = z.object({
  // Taxonomy schema version (auto-injected by Graphiti fork)
  version: z.number().int().optional(),
  // Discovery timestamp
  timestamp: z.number().optional(),
  // Confidence score
  confidence: z.number().min(0.0).max(1.0).optional(),
  // Discovery method
  method: z.enum(["active", "passive"]).optional(),
});

export type Discovered = z.infer<typeof DiscoveredSchema>;


