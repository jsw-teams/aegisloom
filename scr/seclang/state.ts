export interface CollectionRecord {
  values: Map<string, string | number>;
  expires: Map<string, number>;
  decay: Map<string, number>;
  touched: number;
}
export function collectionRecord(
  now: number,
  values = new Map<string, string | number>(),
): CollectionRecord {
  return { values, expires: new Map(), decay: new Map(), touched: now };
}
/** Synchronous per-engine state; expiry never relies on an isolate surviving a timer. */
export class CollectionStore {
  private records = new Map<string, CollectionRecord>();
  constructor(
    private clock: () => number,
    private timeoutSeconds = 3600,
  ) {}
  clear() {
    this.records.clear();
  }
  refresh(record: CollectionRecord) {
    const now = this.clock();
    for (const [name, at] of record.expires)
      if (now >= at) {
        record.values.delete(name);
        record.expires.delete(name);
        record.decay.delete(name);
      }
  }
  get(key: string) {
    if (key.length > 4096) throw new Error("Collection key exceeds limit");
    const now = this.clock();
    let record = this.records.get(key);
    if (record && now - record.touched >= this.timeoutSeconds * 1000) {
      this.records.delete(key);
      record = undefined;
    }
    if (record) this.refresh(record);
    if (!record) {
      // Expired empty entries can be reclaimed; live values are never silently evicted.
      if (this.records.size >= 1024)
        for (const [name, entry] of this.records) {
          this.refresh(entry);
          if (entry.values.size === 0 || now - entry.touched >= this.timeoutSeconds * 1000)
            this.records.delete(name);
        }
      if (this.records.size >= 1024) throw new Error("Persistent collection capacity exceeded");
      record = collectionRecord(now);
      this.records.set(key, record);
    }
    record.touched = now;
    return record;
  }
}
