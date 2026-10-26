import { DatabaseSync } from "node:sqlite";
import type { Policy } from "../rule-ir/index.js";

export type CandidateStatus = "needs-conversion" | "needs-regression" | "verified";
export interface SourceCandidate {
  source: string;
  hash: string;
  status: CandidateStatus;
  version: string;
  license: string;
  policy?: Policy;
  tests: number;
}

/** Durable bounded candidate archive; contains private rule bytes, never serve it as a public feed. */
export class SourceSyncStore {
  private db: DatabaseSync;
  constructor(
    path: string,
    private capacity = 1000,
  ) {
    if (!Number.isSafeInteger(capacity) || capacity < 1 || capacity > 10000)
      throw new Error("Invalid sync capacity");
    this.db = new DatabaseSync(path);
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS source_candidates(source TEXT NOT NULL, hash TEXT NOT NULL, data TEXT NOT NULL, bytes BLOB NOT NULL, PRIMARY KEY(source,hash));
      CREATE TABLE IF NOT EXISTS source_sync_audit(seq INTEGER PRIMARY KEY, at INTEGER NOT NULL, source TEXT NOT NULL, result TEXT NOT NULL, hash TEXT);
      CREATE TABLE IF NOT EXISTS source_sync_due(source TEXT PRIMARY KEY, checked INTEGER NOT NULL);`);
  }
  close() {
    this.db.close();
  }
  due(source: string, now: number, interval: number) {
    const row = this.db.prepare("SELECT checked FROM source_sync_due WHERE source=?").get(source);
    return !row || now - Number(row.checked) >= interval;
  }
  record(
    source: string,
    now: number,
    result: string,
    candidate?: SourceCandidate,
    bytes?: Uint8Array,
  ) {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      if (
        Number(this.db.prepare("SELECT count(*) AS n FROM source_sync_audit").get()?.n) >=
        this.capacity * 10
      )
        throw new Error("Sync audit capacity reached; archive before continuing");
      if (candidate) {
        const exists = this.db
          .prepare("SELECT 1 FROM source_candidates WHERE source=? AND hash=?")
          .get(source, candidate.hash);
        if (
          !exists &&
          Number(this.db.prepare("SELECT count(*) AS n FROM source_candidates").get()?.n) >=
            this.capacity
        )
          throw new Error("Sync candidate capacity reached");
        if (!bytes || bytes.length > 131072 || JSON.stringify(candidate).length > 1048576)
          throw new Error("Invalid candidate size");
        this.db
          .prepare(
            "INSERT INTO source_candidates VALUES(?,?,?,?) ON CONFLICT(source,hash) DO UPDATE SET data=excluded.data",
          )
          .run(source, candidate.hash, JSON.stringify(candidate), bytes);
      }
      this.db
        .prepare("INSERT INTO source_sync_audit(at,source,result,hash) VALUES(?,?,?,?)")
        .run(now, source, result, candidate?.hash ?? null);
      this.db
        .prepare(
          "INSERT INTO source_sync_due VALUES(?,?) ON CONFLICT(source) DO UPDATE SET checked=excluded.checked",
        )
        .run(source, now);
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }
  candidate(source: string, hash: string): SourceCandidate | undefined {
    const row = this.db
      .prepare("SELECT data FROM source_candidates WHERE source=? AND hash=?")
      .get(source, hash);
    return row ? JSON.parse(String(row.data)) : undefined;
  }
  audit() {
    return this.db.prepare("SELECT * FROM source_sync_audit ORDER BY seq DESC LIMIT 1000").all();
  }
}
