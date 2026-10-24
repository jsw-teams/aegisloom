import { DatabaseSync } from "node:sqlite";
import type { DecisionStore, SecurityDecision } from "../decision-cache/model.js";
import { loadPolicy, type Policy, policyVersion } from "../rule-ir/index.js";

/** Durable single-node L3. SQLite WAL transactions provide tenant epoch/write serialization. */
export class SqliteAuthority implements DecisionStore {
  private readonly db: DatabaseSync;
  constructor(
    path: string,
    private readonly capacity = 100000,
  ) {
    if (!Number.isSafeInteger(capacity) || capacity < 1)
      throw new Error("Invalid authority capacity");
    this.db = new DatabaseSync(path);
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS epochs (tenant TEXT PRIMARY KEY, generation INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS decisions (tenant TEXT NOT NULL, cache_key TEXT NOT NULL, id TEXT NOT NULL, generation INTEGER NOT NULL, version INTEGER NOT NULL, expires INTEGER NOT NULL, data TEXT NOT NULL, PRIMARY KEY(tenant,cache_key));
      CREATE INDEX IF NOT EXISTS decision_id ON decisions(tenant,id);
      CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, tenant TEXT NOT NULL, at INTEGER NOT NULL, action TEXT NOT NULL, subject TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS policies (tenant TEXT NOT NULL, hash TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(tenant,hash));
      CREATE TABLE IF NOT EXISTS active_policy (tenant TEXT PRIMARY KEY, hash TEXT NOT NULL);`);
  }
  close(): void {
    this.db.close();
  }
  private epoch(tenant: string): number {
    this.db.prepare("INSERT OR IGNORE INTO epochs VALUES (?,0)").run(tenant);
    return Number(
      (
        this.db.prepare("SELECT generation FROM epochs WHERE tenant=?").get(tenant) as {
          generation: number;
        }
      ).generation,
    );
  }
  private transaction<T>(work: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = work();
      this.db.exec("COMMIT");
      return result;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }
  private audit(tenant: string, now: number, action: string, subject: string): void {
    const count = Number(this.db.prepare("SELECT count(*) AS n FROM audit").get()?.n);
    if (count >= this.capacity * 10)
      throw new Error("Audit capacity reached; archive audit records before further mutations");
    this.db
      .prepare("INSERT INTO audit(tenant,at,action,subject) VALUES (?,?,?,?)")
      .run(tenant, now, action, subject);
  }
  async generation(tenant: string): Promise<number> {
    return this.epoch(tenant);
  }
  async get(tenant: string, key: string, now: number): Promise<SecurityDecision | undefined> {
    const row = this.db
      .prepare(
        "SELECT data FROM decisions WHERE tenant=? AND cache_key=? AND expires>? AND generation=?",
      )
      .get(tenant, key, now, this.epoch(tenant));
    if (!row) return undefined;
    const d = JSON.parse(String(row.data)) as SecurityDecision;
    return d.revoked ? undefined : d;
  }
  async put(d: SecurityDecision, expected: number): Promise<boolean> {
    return this.transaction(() => {
      if (this.epoch(d.tenant) !== expected || d.generation !== expected || d.revoked) return false;
      const old = this.db
        .prepare("SELECT version,generation,expires FROM decisions WHERE tenant=? AND cache_key=?")
        .get(d.tenant, d.key);
      if (
        old &&
        Number(old.generation) === expected &&
        Number(old.expires) > d.firstSeen &&
        Number(old.version) >= d.version
      )
        return false;
      this.db
        .prepare("DELETE FROM decisions WHERE expires<=? OR (tenant=? AND generation<>?)")
        .run(d.firstSeen, d.tenant, expected);
      if (
        !old &&
        Number(this.db.prepare("SELECT count(*) AS n FROM decisions").get()?.n) >= this.capacity
      )
        return false;
      this.db
        .prepare(
          "INSERT INTO decisions VALUES (?,?,?,?,?,?,?) ON CONFLICT(tenant,cache_key) DO UPDATE SET id=excluded.id,generation=excluded.generation,version=excluded.version,expires=excluded.expires,data=excluded.data",
        )
        .run(d.tenant, d.key, d.id, d.generation, d.version, d.expiresAt, JSON.stringify(d));
      this.audit(d.tenant, d.firstSeen, "decision.put", d.id);
      return true;
    });
  }
  async revoke(tenant: string, id: string, now: number): Promise<number> {
    return this.transaction(() => {
      const generation = this.epoch(tenant) + 1;
      this.db.prepare("UPDATE epochs SET generation=? WHERE tenant=?").run(generation, tenant);
      const row = this.db
        .prepare("SELECT cache_key,data FROM decisions WHERE tenant=? AND id=?")
        .get(tenant, id);
      if (row) {
        const d = JSON.parse(String(row.data)) as SecurityDecision;
        d.revoked = true;
        d.cloud = "revoked";
        d.version++;
        d.lastSeen = now;
        this.db
          .prepare("UPDATE decisions SET data=?,version=? WHERE tenant=? AND cache_key=?")
          .run(JSON.stringify(d), d.version, tenant, String(row.cache_key));
      }
      this.audit(tenant, now, "decision.revoke", id);
      return generation;
    });
  }
  async list(tenant: string, now: number): Promise<SecurityDecision[]> {
    return this.db
      .prepare(
        "SELECT data FROM decisions WHERE tenant=? AND generation=? AND expires>? ORDER BY id LIMIT 1000",
      )
      .all(tenant, this.epoch(tenant), now)
      .map((r) => JSON.parse(String(r.data)) as SecurityDecision)
      .filter((d) => !d.revoked);
  }
  auditLog(tenant: string, after = 0): Record<string, unknown>[] {
    return this.db
      .prepare(
        "SELECT seq,at,action,subject FROM audit WHERE tenant=? AND seq>? ORDER BY seq LIMIT 1000",
      )
      .all(tenant, after);
  }
  async savePolicy(tenant: string, source: unknown): Promise<string> {
    const policy = loadPolicy(source);
    const hash = await policyVersion(policy);
    this.transaction(() => {
      if (
        Number(
          this.db.prepare("SELECT count(*) AS n FROM policies WHERE tenant=?").get(tenant)?.n,
        ) >= 1000
      )
        throw new Error("Policy history capacity reached");
      this.db
        .prepare("INSERT OR IGNORE INTO policies VALUES (?,?,?)")
        .run(tenant, hash, JSON.stringify(policy));
      this.audit(tenant, Date.now(), "policy.save", hash);
    });
    return hash;
  }
  activatePolicy(tenant: string, hash: string): void {
    this.transaction(() => {
      if (!this.db.prepare("SELECT 1 FROM policies WHERE tenant=? AND hash=?").get(tenant, hash))
        throw new Error("Unknown tenant policy version");
      this.db
        .prepare(
          "INSERT INTO active_policy VALUES (?,?) ON CONFLICT(tenant) DO UPDATE SET hash=excluded.hash",
        )
        .run(tenant, hash);
      this.db.prepare("UPDATE epochs SET generation=generation+1 WHERE tenant=?").run(tenant);
      this.audit(tenant, Date.now(), "policy.activate", hash);
    });
  }
  activePolicy(tenant: string): { hash: string; policy: Policy } | undefined {
    const row = this.db
      .prepare(
        "SELECT p.hash,p.data FROM active_policy a JOIN policies p ON a.tenant=p.tenant AND a.hash=p.hash WHERE a.tenant=?",
      )
      .get(tenant);
    return row
      ? { hash: String(row.hash), policy: JSON.parse(String(row.data)) as Policy }
      : undefined;
  }
}
