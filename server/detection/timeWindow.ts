/**
 * NetHunterSOC - Deterministic Time Window Aggregation Engine
 * Evaluates streaming and batch canonical events within bounded temporal slices
 */

export interface EventTimeWindow<T> {
  key: string;
  windowStart: string;
  windowEnd: string;
  windowStartMs: number;
  windowEndMs: number;
  events: T[];
}

/**
 * Groups events by a grouping key and evaluates them within deterministic sliding time windows.
 * 
 * When a window reaches the threshold condition, it emits the window and advances to ensure
 * clean, reproducible boundaries without producing unbounded combinatorial duplicates.
 */
export function evaluateSlidingWindows<T extends { timestamp: string }>(
  events: T[],
  groupKeyFn: (event: T) => string | null,
  windowSeconds: number,
  conditionFn: (windowEvents: T[]) => boolean
): EventTimeWindow<T>[] {
  const windowMs = windowSeconds * 1000;
  const groups = new Map<string, T[]>();

  // 1. Group events by key
  for (const event of events) {
    const key = groupKeyFn(event);
    if (!key) continue;
    let group = groups.get(key);
    if (!group) {
      group = [];
      groups.set(key, group);
    }
    group.push(event);
  }

  const triggeredWindows: EventTimeWindow<T>[] = [];

  // 2. Evaluate windows for each group
  for (const [key, groupEvents] of groups.entries()) {
    // Ensure chronological sorting
    const sorted = [...groupEvents].sort((a, b) => {
      const ta = Date.parse(a.timestamp) || 0;
      const tb = Date.parse(b.timestamp) || 0;
      return ta - tb;
    });

    let i = 0;
    while (i < sorted.length) {
      const windowStartMs = Date.parse(sorted[i].timestamp);
      if (isNaN(windowStartMs)) {
        i++;
        continue;
      }
      const windowEndLimitMs = windowStartMs + windowMs;

      // Accumulate all events falling within this window
      const windowEvents: T[] = [];
      let j = i;
      while (j < sorted.length) {
        const eventMs = Date.parse(sorted[j].timestamp);
        if (isNaN(eventMs) || eventMs > windowEndLimitMs) {
          break;
        }
        windowEvents.push(sorted[j]);
        j++;
      }

      // Check if threshold condition is met
      if (conditionFn(windowEvents)) {
        const firstEvent = windowEvents[0];
        const lastEvent = windowEvents[windowEvents.length - 1];

        triggeredWindows.push({
          key,
          windowStart: firstEvent.timestamp,
          windowEnd: lastEvent.timestamp,
          windowStartMs,
          windowEndMs: Date.parse(lastEvent.timestamp),
          events: windowEvents,
        });

        // Advance to the end of this triggered window to prevent spamming
        i = j;
      } else {
        i++;
      }
    }
  }

  return triggeredWindows;
}
