import { DatabaseSync } from "node:sqlite";
export class SqliteReplayStore {
  private database: DatabaseSync;
  constructor(
    path: string,
    private capacity = 4096,
    private now = Date.now,
  ) {
    this.database = new DatabaseSync(path);
    this.database.exec(
      "PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS replay (id TEXT PRIMARY KEY, expires INTEGER NOT NULL); CREATE INDEX IF NOT EXISTS expiry ON replay(expires)",
    );
  }
  async claim(id: string, expiresAt: number): Promise<boolean> {
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database.prepare("DELETE FROM replay WHERE expires <= ?").run(this.now());
      if (this.database.prepare("SELECT id FROM replay WHERE id=?").get(id)) {
        this.database.exec("COMMIT");
        return false;
      }
      const count = this.database.prepare("SELECT count(*) AS n FROM replay").get() as {
        n: number;
      };
      if (count.n >= this.capacity) throw new Error("Relay replay store capacity exceeded");
      this.database.prepare("INSERT INTO replay VALUES (?,?)").run(id, expiresAt);
      this.database.exec("COMMIT");
      return true;
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }
  close() {
    this.database.close();
  }
}
