import { requireInteger } from "../core/types.js";

export class LruTtl<T> {
  private readonly entries = new Map<string, { value: T; expires: number }>();
  hits = 0;
  misses = 0;
  constructor(readonly capacity = 2048) {
    requireInteger(capacity, 1, 1000000, "cache capacity");
  }
  get(key: string, now: number): T | undefined {
    const entry = this.entries.get(key);
    if (!entry || entry.expires <= now) {
      this.entries.delete(key);
      this.misses++;
      return undefined;
    }
    this.entries.delete(key);
    this.entries.set(key, entry);
    this.hits++;
    return entry.value;
  }
  set(key: string, value: T, expires: number): void {
    this.entries.delete(key);
    if (this.entries.size >= this.capacity) {
      const first = this.entries.keys().next().value;
      if (first !== undefined) this.entries.delete(first);
    }
    this.entries.set(key, { value, expires });
  }
  delete(key: string): void {
    this.entries.delete(key);
  }
  clear(): void {
    this.entries.clear();
  }
  get size(): number {
    return this.entries.size;
  }
}
