import { requireInteger, ShieldError } from "./types.js";

/** Bounded per-instance fixed windows. Saturation fails closed, never evicts active counters. */
export class RateWindows {
  private readonly entries = new Map<
    string,
    { hits: number; expires: number; blockedUntil: number }
  >();
  constructor(private readonly capacity = 10000) {
    requireInteger(capacity, 1, 1000000, "rate capacity");
  }
  hit(key: string, threshold: number, within: number, penalty: number, now: number): boolean {
    let entry = this.entries.get(key);
    if (entry && entry.blockedUntil > now) return true;
    if (entry && entry.expires <= now) {
      this.entries.delete(key);
      entry = undefined;
    }
    if (!entry) {
      if (this.entries.size >= this.capacity)
        for (const [k, v] of this.entries)
          if (Math.max(v.expires, v.blockedUntil) <= now) this.entries.delete(k);
      if (this.entries.size >= this.capacity) throw new ShieldError("rate-state-capacity", 503);
      entry = { hits: 0, expires: now + within, blockedUntil: 0 };
      this.entries.set(key, entry);
    }
    entry.hits++;
    if (entry.hits > threshold) {
      entry.blockedUntil = now + penalty;
      return true;
    }
    return false;
  }
  get size(): number {
    return this.entries.size;
  }
}
