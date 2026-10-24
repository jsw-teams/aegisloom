export interface Observation {
  tenant: string;
  /** Use route templates when available; never send query strings or tokens here. */
  path: string;
  method: string;
  at: number;
  source: string;
  trust: "verified" | "candidate";
  bodyBytes: number;
  status: number;
  fields: Record<string, "string" | "number" | "boolean" | "object" | "array" | "null">;
}
export interface RouteBaseline {
  path: string;
  method: string;
  samples: number;
  sources: number;
  meanBytes: number;
  variance: number;
  errorRate: number;
  fields: Record<string, string[]>;
}
export interface LearningModel {
  version: number;
  tenant: string;
  frozen: boolean;
  routes: RouteBaseline[];
  createdAt: number;
}
export interface Anomaly {
  score: number;
  reasons: string[];
  modelVersion: number;
}
