/**
 * WebSocket connection manager.
 *
 * The legacy dashboard ran 7 independent `setInterval` polling loops
 * (scan status, pipeline events, live feed, ollama pull, ...). The
 * backend already emits Socket.IO events for everything that matters
 * (scan_started, scan_completed, pipeline_event, pipeline_state,
 * active_scans, shell_output, chat_message). This module maintains a
 * single resilient connection and re-broadcasts those events onto the
 * internal `bus` as `ws:<event>` topics. Views subscribe to the bus and
 * never poll unless the socket is down.
 */
import { bus } from "./bus.js";

const FORWARD = [
  "active_scans",
  "scan_started",
  "scan_completed",
  "scan_log",
  "pipeline_event",
  "pipeline_state",
  "shell_output",
  "chat_message",
  "chat_cleared",
];

let socket = null;
let connected = false;

export function initWs() {
  // `io` is provided by the Socket.IO client script. If it failed to
  // load (offline / CDN blocked), degrade gracefully to polling.
  if (typeof window.io === "undefined") {
    bus.emit("ws:status", { connected: false, available: false });
    return;
  }

  socket = window.io("", {
    transports: ["websocket", "polling"],
    reconnection: true,
    reconnectionAttempts: Infinity,
    reconnectionDelay: 1000,
    reconnectionDelayMax: 8000,
  });

  socket.on("connect", () => {
    connected = true;
    bus.emit("ws:status", { connected: true, available: true });
  });
  socket.on("disconnect", () => {
    connected = false;
    bus.emit("ws:status", { connected: false, available: true });
  });
  socket.on("connect_error", () => {
    connected = false;
    bus.emit("ws:status", { connected: false, available: true });
  });

  for (const evt of FORWARD) {
    socket.on(evt, (data) => bus.emit("ws:" + evt, data));
  }
}

/** Ask the server to push live pipeline state for a scan. */
export function subscribeScan(scanId) {
  if (socket && connected && scanId) socket.emit("subscribe_scan", { scan_id: scanId });
}

/** Send an arbitrary event; returns false if the socket is unavailable. */
export function wsEmit(event, data) {
  if (socket && connected) {
    socket.emit(event, data);
    return true;
  }
  return false;
}

export function isWsConnected() {
  return connected;
}
