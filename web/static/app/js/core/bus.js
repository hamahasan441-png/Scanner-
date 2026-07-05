/**
 * Tiny synchronous event bus (pub/sub).
 *
 * Used to decouple the WebSocket layer, the API layer and the views:
 * views subscribe to `ws:*` and `app:*` topics instead of holding
 * references to the socket or polling timers. Handlers are isolated so
 * one throwing listener never breaks the others.
 */
export class Bus {
  constructor() {
    /** @type {Map<string, Set<Function>>} */
    this._topics = new Map();
  }

  /**
   * Subscribe to a topic. Returns an unsubscribe function.
   * @param {string} topic
   * @param {(data:any)=>void} handler
   * @returns {() => void}
   */
  on(topic, handler) {
    let set = this._topics.get(topic);
    if (!set) {
      set = new Set();
      this._topics.set(topic, set);
    }
    set.add(handler);
    return () => this.off(topic, handler);
  }

  off(topic, handler) {
    const set = this._topics.get(topic);
    if (set) {
      set.delete(handler);
      if (set.size === 0) this._topics.delete(topic);
    }
  }

  emit(topic, data) {
    const set = this._topics.get(topic);
    if (!set) return;
    // Snapshot so handlers can unsubscribe during dispatch safely.
    for (const handler of [...set]) {
      try {
        handler(data);
      } catch (err) {
        console.error(`[bus] handler for "${topic}" threw:`, err);
      }
    }
  }
}

export const bus = new Bus();
