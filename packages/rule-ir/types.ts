export type Field =
  | "path"
  | "method"
  | "header"
  | "query"
  | "body"
  | "identity"
  | "client.ip"
  | "client.class"
  | "risk.score";
export type Transform = "lowercase" | "trim" | "urlDecode";
export interface Match {
  field: Field;
  key?: string;
  op: "eq" | "contains" | "prefix" | "regex" | "exists" | "range";
  value?: string | number | boolean;
  min?: number;
  max?: number;
  transforms?: Transform[];
}
export type Expression =
  | Match
  | { all: Expression[] }
  | { any: Expression[] }
  | { not: Expression };
export interface Rate {
  moreThan: number;
  within: string;
  groupBy: "verifiedClientIp" | "identity";
}
export interface Rule {
  id: string;
  name: string;
  description?: string;
  enabled: boolean;
  service: string;
  priority: number;
  phase: "request-headers" | "request-body" | "response-headers";
  placement: "edge-required" | "edge-preferred" | "runtime-required" | "upstream-required";
  when: Expression;
  requests?: Rate;
  then: {
    action: "block" | "detect" | "rate-limit" | "challenge";
    duration?: string;
    score?: number;
  };
  cache: { enabled: boolean; ttl: string };
  community: { report: boolean };
  expiresAt?: string;
  provenance?: {
    source: string;
    version: string;
    license: string;
    sha256: string;
    limitations: string[];
  };
}
export interface Policy {
  version: "1";
  rules: Rule[];
}
