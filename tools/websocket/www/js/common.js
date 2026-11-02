// Shared by every page: formatting, the observer status line and the
// websocket connection with its subscriptions.
"use strict";

const ASMAP_WEB = "https://0xb10c.github.io/asmap-web/?ip=";
const BGP_TOOLS = "https://bgp.tools/as/";
const SERVICE_NAMES = [
  [1n, "NETWORK"],
  [2n, "GETUTXO"],
  [4n, "BLOOM"],
  [8n, "WITNESS"],
  [64n, "COMPACT_FILTERS"],
  [1n << 10n, "NETWORK_LIMITED"],
  [1n << 11n, "P2P_V2"],
];

let clockOffsetMs = 0; // server clock minus browser clock

function nowMs() {
  return Date.now() + clockOffsetMs;
}

function syncClock(serverTimeMs) {
  if (serverTimeMs) clockOffsetMs = serverTimeMs - Date.now();
}

function duration(ms) {
  if (ms === null || ms === undefined || ms < 0) return "";
  if (ms < 1000) return ms + "ms";
  const s = Math.floor(ms / 1000);
  if (s < 60) return s + "s";
  if (s < 3600) return Math.floor(s / 60) + "m" + (s % 60) + "s";
  if (s < 86_400) return Math.floor(s / 3600) + "h" + Math.floor((s % 3600) / 60) + "m";
  return Math.floor(s / 86_400) + "d" + Math.floor((s % 86_400) / 3600) + "h";
}

function time(ms) {
  if (!ms) return "";
  return new Date(ms).toISOString().slice(11, 19);
}

function num(n) {
  return n === null || n === undefined ? "" : String(n);
}

function shortHash(hash) {
  if (!hash) return "";
  return hash.replace(/^0+/, "").slice(0, 12) || "0";
}

function services(hex) {
  let rest;
  try {
    rest = BigInt(hex || "0x0");
  } catch (e) {
    return hex;
  }
  if (rest === 0n) return "NONE";
  const names = [];
  for (const [bit, name] of SERVICE_NAMES) {
    if (rest & bit) {
      names.push(name);
      rest &= ~bit;
    }
  }
  if (rest !== 0n) names.push("0x" + rest.toString(16));
  return names.join("|");
}

function hasService(hex, bit) {
  try {
    return (BigInt(hex || "0x0") & bit) !== 0n;
  } catch (e) {
    return false;
  }
}

function uaFamily(ua) {
  if (!ua) return "unknown";
  if (/knots/i.test(ua)) return "knots";
  if (/^\/Satoshi:/.test(ua)) return "core";
  if (/btcd/i.test(ua)) return "btcd";
  return "other";
}

function coreVersion(ua) {
  const m = (ua || "").match(/^\/Satoshi:(\d+)\.(\d+)\./);
  return m ? m[1] + "." + m[2] : "";
}

// `sorted` ascending; p in [0, 1].
function percentile(sorted, p) {
  if (!sorted.length) return null;
  return sorted[Math.min(sorted.length - 1, Math.floor((sorted.length - 1) * p))];
}

// What a peer's start height says about the chain it follows.
function heightTag(delta) {
  if (delta === null || delta === undefined) return null;
  if (delta < -1000) return { label: "syncing " + delta, cls: "syncing" };
  if (delta < -1) return { label: "behind " + delta, cls: "behind" };
  if (delta <= 1) return null;
  if (delta <= 100) return { label: "ahead +" + delta, cls: "ahead" };
  return { label: "other chain +" + delta, cls: "ahead" };
}

function asName(ip) {
  if (!ip) return "";
  if (ip.asn === 0) return "unmapped";
  if (!ip.description) return "unknown AS";
  return ip.description + (ip.country ? " [" + ip.country + "]" : "");
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = text;
  return e;
}

// A spinner, for a value no message has carried yet.
function spinner(cls, title) {
  const s = el("span", cls ? "spinner " + cls : "spinner");
  s.title = title || "no message about this yet";
  s.setAttribute("aria-label", "waiting");
  return s;
}

function spinnerCell(row, cls, title) {
  const td = row.insertCell();
  if (cls) td.className = cls;
  td.append(spinner(null, title));
  return td;
}

// The placeholder of an area with nothing in it, in one of two states:
// `waiting` for a first message that should come, or `empty` for a question
// the stream has answered with nothing. Rebuilding the node would restart the
// animation, so the same state and text twice leaves it alone -- which also
// keeps this out of the per-second render cost.
function placeholder(container, state, text) {
  if (!container) return;
  const key = state + ":" + text;
  if (container.dataset.placeholder === key) return;
  container.dataset.placeholder = key;
  if (state === "waiting") container.replaceChildren(spinner("big", text), el("span", null, " " + text));
  else container.replaceChildren(document.createTextNode(text));
}

function textCell(row, text, cls, title) {
  const td = row.insertCell();
  td.textContent = text === null || text === undefined ? "" : text;
  if (cls) td.className = cls;
  if (title) td.title = title;
  return td;
}

function linkCell(row, text, href, cls, title) {
  const td = row.insertCell();
  if (cls) td.className = cls;
  if (text === "" || text === null || text === undefined) return td;
  const a = document.createElement("a");
  a.href = href;
  a.target = "_blank";
  a.rel = "noopener noreferrer";
  a.textContent = text;
  if (title) a.title = title;
  td.append(a);
  return td;
}

function peerCell(row, peer) {
  const td = linkCell(row, peer.peer_ip, ASMAP_WEB + peer.peer_ip, null, peer.peer_addr);
  const port = el("span", "dim", ":" + peer.peer_port);
  td.append(port);
  return td;
}

function asnCell(row, peer) {
  if (!peer.ip || peer.ip.asn === 0) return textCell(row, "", "num dim");
  return linkCell(row, "AS" + peer.ip.asn, BGP_TOOLS + peer.ip.asn, "num", peer.ip.handle);
}

function asCell(row, peer) {
  const td = textCell(row, asName(peer.ip), "as", peer.ip ? peer.ip.handle : "");
  if (!peer.ip || peer.ip.asn === 0 || !peer.ip.description) td.classList.add("dim");
  return td;
}

function topEntries(counts, n) {
  return Object.entries(counts || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([k, v]) => k + "×" + v)
    .join(" ");
}

// Sum of the values of a {name: count} object.
function sumValues(obj) {
  return Object.values(obj || {}).reduce((a, b) => a + b, 0);
}

// `<network>/<instance>/<connection>`, unique across observer restarts.
// The instance id is a 64 bit number and loses its last digits in JSON, but
// the same id always reads back the same way, which is all a key needs.
function peerKey(ev) {
  return ev.network + "/" + ev.instance_id + "/" + ev.connection_id;
}

// "1.2.3.4:8333" and "[2001:db8::1]:8333" into host and port.
function splitAddr(addr) {
  const colon = (addr || "").lastIndexOf(":");
  if (colon < 0) return { ip: addr || "", port: 0 };
  const host = addr.slice(0, colon);
  return {
    ip: host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host,
    port: Number(addr.slice(colon + 1)) || 0,
  };
}

// Where the stream comes from, counted from the events themselves: one line
// per observer run, since the tool keeps no account of its own.
function sourceTracker() {
  const seen = new Map(); // network/instance -> entry
  return {
    note(ev) {
      const id = ev.network + "/" + ev.instance_id;
      let entry = seen.get(id);
      if (!entry) {
        entry = { network: ev.network, instance: String(ev.instance_id), events: 0, last_ms: 0, dropped: 0 };
        seen.set(id, entry);
      }
      entry.events += 1;
      entry.dropped = ev.dropped_events || 0;
      if (ev.timestamp_ms > entry.last_ms) entry.last_ms = ev.timestamp_ms;
    },
    clear() {
      seen.clear();
    },
    render(container) {
      if (!container) return;
      const now = nowMs();
      const entries = [...seen.values()].sort((a, b) => a.network.localeCompare(b.network));
      if (entries.length === 0) {
        placeholder(container, "waiting", "waiting for the first event");
        return;
      }
      delete container.dataset.placeholder;
      container.replaceChildren();
      for (const e of entries) {
        const age = now - e.last_ms;
        const div = el("div", "observer" + (age > 600_000 ? " stale" : ""));
        div.append(el("b", null, e.network), " instance " + e.instance.slice(-6));
        const parts = ["events " + num(e.events)];
        if (e.dropped) parts.push("observer dropped " + num(e.dropped));
        if (age > 60_000) parts.push("last event " + duration(age) + " ago");
        div.append(" · " + parts.join(" · "));
        container.append(div);
      }
    },
  };
}

function onStatus(text, isError) {
  const statusEl = document.getElementById("status");
  if (!statusEl) return;
  statusEl.classList.toggle("error", isError);
  if (!isError && /^connecting/.test(text)) {
    statusEl.replaceChildren(spinner(null, text), el("span", null, " " + text));
  } else {
    statusEl.textContent = text;
  }
}

function parseMessage(e) {
  try {
    return JSON.parse(e.data);
  } catch (err) {
    console.warn("ignoring non-JSON message", err);
    return null;
  }
}

// Coalesces renders into one per animation frame.
function renderer(fn) {
  let queued = false;
  return () => {
    if (queued) return;
    queued = true;
    requestAnimationFrame(() => {
      queued = false;
      fn();
    });
  };
}

function connect(subscriptions, onMessage, onReset) {
  updateSubscriptions(subscriptions);
  initWebsocketPicker("websockets.json", "websocket-picker", onMessage, onReset, onStatus);
}

// Sortable table headers: calls `onSort(key, asc)` and marks the header.
function sortableHeaders(table, defaultKey, defaultAsc, textKeys, onSort) {
  let sortKey = defaultKey;
  let sortAsc = defaultAsc;
  const headers = table.querySelectorAll("th[data-key]");
  for (const th of headers) {
    th.addEventListener("click", () => {
      const key = th.dataset.key;
      if (sortKey === key) {
        sortAsc = !sortAsc;
      } else {
        sortKey = key;
        sortAsc = textKeys.includes(key);
      }
      for (const other of headers) {
        other.classList.toggle("sorted", other === th);
        other.classList.toggle("asc", other === th && sortAsc);
      }
      onSort(sortKey, sortAsc);
    });
  }
  return () => ({ key: sortKey, asc: sortAsc });
}

function compareBy(value, key, asc, tieKey) {
  return (a, b) => {
    const va = value(a, key);
    const vb = value(b, key);
    let c;
    if (typeof va === "number" && typeof vb === "number") c = va - vb;
    else c = String(va).localeCompare(String(vb));
    if (c === 0) c = String(a[tieKey]).localeCompare(String(b[tieKey]));
    return asc ? c : -c;
  };
}
