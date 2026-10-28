// Connections page: builds the set of open connections from the event
// stream and shows it in a table that renders only the rows in view.
//
// Two things keep this usable at tens of thousands of connections. The
// table is virtualised: the body holds the visible rows between two spacer
// rows, so the DOM cost is the viewport, not the population. And the heavy
// event kinds are off by default -- a block reaches every connection at
// once, so counting block announcements means one message per connection
// per block, which is the whole firehose for one column.
"use strict";

// Row height in pixels; must match `.scroller tbody tr` in the stylesheet,
// since the scroll offset is turned into a row index with it.
const ROW_H = 22;
// Rows rendered above and below the viewport, so a fast scroll does not
// show empty space before the next frame.
const OVERSCAN = 12;
// A connection whose last event is older than this is dropped: the observer
// pings every two minutes, so silence this long means the session ended and
// its connection_result never reached us.
const IDLE_MS = 15 * 60 * 1000;
// How often the table is re-sorted and re-filtered. Events keep updating the
// records in between; only the view waits.
const REFRESH_MS = 1000;
// Columns in the table, so a spacer row spans all of them.
const COLUMNS = 20;

const peers = new Map(); // key -> record
const sources = sourceTracker();
// Best height per network, the yardstick for a peer's start height: the
// highest block announced, and failing that the highest start height any
// peer claimed. Without an observer RPC this is what the stream offers.
const bestHeight = new Map();
let pendingDeltas = false;
let asmapLoaded = false;
// Whether any event has arrived, which is what separates "waiting" from
// "nothing to show" everywhere on this page.
let seenEvent = false;
let rows = [];

const filterEl = document.getElementById("filter");
const onlyHandshakeEl = document.getElementById("only-handshake");
const onlyOtherChainEl = document.getElementById("only-otherchain");
const countBlocksEl = document.getElementById("count-blocks");
const summaryEl = document.getElementById("summary");
const sourcesEl = document.getElementById("sources");
const scrollEl = document.getElementById("peers-scroll");
const peersTable = document.getElementById("peers");
const peersBody = peersTable.querySelector("tbody");

const TEXT_KEYS = ["network", "peer_ip", "as_name", "transport", "user_agent", "flags", "cmpct"];
const sortState = sortableHeaders(peersTable, "first_seen_ms", false, TEXT_KEYS, () => refresh());

function subscriptions() {
  return {
    handshakes: true,
    ping_rtt: true,
    connection_results: true,
    fee_filters: true,
    send_cmpcts: true,
    block_announcements: countBlocksEl.checked,
  };
}

function flags(peer) {
  if (!peer.handshake) return "";
  return (peer.relay ? "R" : "-") + (peer.sendaddrv2 ? "A" : "-") + (peer.wtxid_relay ? "W" : "-");
}

function cmpct(peer) {
  if (!peer.sendcmpct) return "";
  return (peer.sendcmpct.high_bandwidth ? "hb" : "lb") + " v" + peer.sendcmpct.version;
}

function servicesHex(peer) {
  return peer.handshake ? "0x" + Number(peer.services).toString(16) : "";
}

// The record a connection gets on its first event, whichever kind that is.
function record(ev) {
  const { ip, port } = splitAddr(ev.peer_addr);
  return {
    key: peerKey(ev),
    network: ev.network,
    instance_id: String(ev.instance_id),
    connection_id: ev.connection_id,
    peer_addr: ev.peer_addr,
    peer_ip: ip,
    peer_port: port,
    user_agent: ev.user_agent || "",
    transport: ev.transport_version === 1 ? "v1" : ev.transport_version === 2 ? "v2" : "unknown",
    first_seen_ms: ev.timestamp_ms,
    last_seen_ms: ev.timestamp_ms,
    handshake: false,
    protocol_version: 0,
    services: 0,
    start_height: 0,
    height_delta: null,
    relay: false,
    sendaddrv2: false,
    wtxid_relay: false,
    addr_recv: "",
    clock_skew_s: 0,
    fee_filter: null,
    sendcmpct: null,
    pings: 0,
    rtt_ms: null,
    min_rtt_ms: null,
    tcp: null,
    blocks: 0,
    blocks_new: 0,
    ip: ev.ip || null,
  };
}

function noteHeight(network, height) {
  if (height === null || height === undefined) return;
  const best = bestHeight.get(network);
  if (best === undefined || height > best) {
    bestHeight.set(network, height);
    pendingDeltas = true;
  }
}

function apply(ev) {
  if (!ev || !ev.event) return;
  seenEvent = true;
  sources.note(ev);
  const key = peerKey(ev);
  const kind = Object.keys(ev.event)[0];
  const body = ev.event[kind];

  if (kind === "ConnectionResult") {
    // The session is over, whatever it did before.
    peers.delete(key);
    return;
  }

  let peer = peers.get(key);
  if (!peer) {
    peer = record(ev);
    peers.set(key, peer);
  }
  if (ev.timestamp_ms > peer.last_seen_ms) peer.last_seen_ms = ev.timestamp_ms;
  if (ev.user_agent && !peer.user_agent) peer.user_agent = ev.user_agent;
  if (ev.ip && !peer.ip) peer.ip = ev.ip;

  switch (kind) {
    case "Handshake":
      peer.handshake = true;
      peer.protocol_version = body.protocol_version;
      peer.services = body.services;
      peer.start_height = body.start_height;
      peer.relay = body.relay;
      peer.sendaddrv2 = body.sendaddrv2;
      peer.wtxid_relay = body.wtxid_relay;
      peer.addr_recv = body.addr_recv || "";
      peer.clock_skew_s = Math.round(body.peer_timestamp - ev.timestamp_ms / 1000);
      if (body.user_agent) peer.user_agent = body.user_agent;
      noteHeight(ev.network, body.start_height);
      // Frozen here rather than recomputed: the claim is about the moment
      // of the handshake, and the chain moves on afterwards.
      peer.height_delta = heightDelta(ev.network, body.start_height);
      break;
    case "PingRtt":
      peer.pings += 1;
      peer.rtt_ms = body.rtt_ms;
      if (peer.min_rtt_ms === null || body.rtt_ms < peer.min_rtt_ms) peer.min_rtt_ms = body.rtt_ms;
      if (body.tcp_stats) peer.tcp = body.tcp_stats;
      break;
    case "BlockAnnouncement":
      peer.blocks += 1;
      if (body.new_to_us) peer.blocks_new += 1;
      if (body.tcp_stats) peer.tcp = body.tcp_stats;
      noteHeight(ev.network, body.height);
      break;
    case "FeeFilter":
      peer.fee_filter = body.feerate_sat_per_kvb;
      break;
    case "SendCmpct":
      peer.sendcmpct = { high_bandwidth: body.high_bandwidth, version: body.version };
      break;
    default:
      break;
  }
}

function heightDelta(network, startHeight) {
  const best = bestHeight.get(network);
  return best === undefined ? null : startHeight - best;
}

// Peers that handshook before anything said where the chain was.
function backfillDeltas() {
  if (!pendingDeltas) return;
  pendingDeltas = false;
  for (const peer of peers.values()) {
    if (peer.handshake && peer.height_delta === null) {
      peer.height_delta = heightDelta(peer.network, peer.start_height);
    }
  }
}

function expire(now) {
  for (const [key, peer] of peers) {
    if (now - peer.last_seen_ms > IDLE_MS) peers.delete(key);
  }
}

function sortValue(peer, key) {
  switch (key) {
    case "asn":
      return peer.ip ? peer.ip.asn : -1;
    case "as_name":
      return asName(peer.ip);
    case "flags":
      return flags(peer);
    case "cmpct":
      return cmpct(peer);
    case "height_delta":
      return peer.height_delta ?? -1e12;
    case "rtt_ms":
    case "min_rtt_ms":
    case "fee_filter":
      return peer[key] ?? -1;
    case "srtt":
      return peer.tcp ? peer.tcp.srtt_us : -1;
    default:
      return peer[key] ?? "";
  }
}

function matchesFilter(peer, needle) {
  if (onlyHandshakeEl.checked && !peer.handshake) return false;
  if (onlyOtherChainEl.checked && !(peer.height_delta > 100)) return false;
  if (needle === "") return true;
  const hay = [
    peer.network,
    peer.peer_addr,
    peer.user_agent,
    peer.transport,
    peer.ip ? "as" + peer.ip.asn + " " + peer.ip.handle + " " + peer.ip.description + " " + peer.ip.country : "",
  ]
    .join(" ")
    .toLowerCase();
  return needle.split(/\s+/).every((word) => hay.includes(word));
}

function fillRow(row, peer, now) {
  row.className = "";
  if (!peer.handshake) row.classList.add("nohandshake");
  if (peer.height_delta > 100) row.classList.add("otherchain");
  textCell(row, peer.network);
  peerCell(row, peer);
  asnCell(row, peer);
  asCell(row, peer);
  textCell(row, peer.transport, peer.transport === "unknown" ? "dim" : null);
  textCell(row, peer.user_agent, "ua", peer.user_agent);
  textCell(row, peer.handshake ? peer.protocol_version : "", "num");
  textCell(row, peer.handshake ? services(peer.services) : "", null, servicesHex(peer));
  textCell(row, peer.handshake ? peer.start_height : "", "num");
  const chain = row.insertCell();
  const tag = heightTag(peer.height_delta);
  if (tag) chain.append(el("span", "tag " + tag.cls, tag.label));
  textCell(row, flags(peer), null, peer.handshake ? "relay / sendaddrv2 / wtxidrelay; sees us as " + peer.addr_recv : "");
  textCell(row, peer.handshake ? peer.clock_skew_s + "s" : "", "num");
  textCell(row, peer.fee_filter === null ? "" : peer.fee_filter, "num", "sat/kvB");
  textCell(row, cmpct(peer));
  textCell(row, duration(now - peer.first_seen_ms), "num", time(peer.first_seen_ms));
  textCell(row, peer.pings || "", "num");
  // A connection we met at its handshake has not been pinged yet, and will be
  // within the ping interval. One that was already open when this page
  // connected arrived with a ping, so it has a round trip from the start, and
  // its handshake is in the past and never coming: those cells stay blank.
  if (peer.handshake && peer.pings === 0) {
    spinnerCell(row, "num", "no ping yet; the observer pings every two minutes");
  } else {
    textCell(row, peer.rtt_ms === null ? "" : peer.rtt_ms + "ms", "num");
  }
  textCell(row, peer.min_rtt_ms === null ? "" : peer.min_rtt_ms + "ms", "num");
  const t = peer.tcp;
  textCell(
    row,
    t ? (t.srtt_us / 1000).toFixed(1) + "ms" : "",
    "num",
    t
      ? "rttvar " + t.rttvar_us + "µs, kernel min rtt " + num(t.min_rtt_us) + "µs, cwnd " + t.snd_cwnd +
        ", retransmitted " + t.total_retrans + ", lost " + num(t.lost) + ", delivery rate " + num(t.delivery_rate) + " B/s"
      : "",
  );
  textCell(row, countBlocksEl.checked ? peer.blocks + (peer.blocks_new ? " (" + peer.blocks_new + " new)" : "") : "", "num");
}

function spacer(height) {
  const row = document.createElement("tr");
  row.className = "spacer";
  const td = document.createElement("td");
  td.colSpan = COLUMNS;
  td.style.height = height + "px";
  row.append(td);
  return row;
}

// Renders the rows the viewport shows, between two spacers that stand in for
// the rest. The scroll height does not depend on what is rendered, so the
// position under the user does not move.
function renderWindow() {
  const now = nowMs();
  const total = rows.length;
  const first = Math.max(0, Math.floor(scrollEl.scrollTop / ROW_H) - OVERSCAN);
  const fit = Math.ceil(scrollEl.clientHeight / ROW_H) + 2 * OVERSCAN;
  const last = Math.min(total, first + fit);

  const body = document.createDocumentFragment();
  if (first > 0) body.append(spacer(first * ROW_H));
  for (let i = first; i < last; i++) {
    const row = document.createElement("tr");
    fillRow(row, rows[i], now);
    body.append(row);
  }
  if (last < total) body.append(spacer((total - last) * ROW_H));
  peersBody.replaceChildren(body);
  emptyState(total);
}

// Nothing to show is either "no event has arrived yet", which a spinner
// says, or an answer: no connection at all, or none matching the filter.
function emptyState(total) {
  const node = document.getElementById("peers-empty");
  node.hidden = total > 0;
  if (total > 0) return;
  if (!seenEvent) placeholder(node, "waiting", "waiting for the first event");
  else if (peers.size === 0) placeholder(node, "empty", "no connection seen yet");
  else placeholder(node, "empty", "no connection matches the filter");
}

const scheduleWindow = renderer(renderWindow);

// Re-sorts and re-filters, then redraws the window. The records themselves
// are updated by the event handler as events arrive.
function refresh() {
  const now = nowMs();
  expire(now);
  backfillDeltas();
  const needle = filterEl.value.trim().toLowerCase();
  const { key, asc } = sortState();
  rows = [];
  let handshaked = 0;
  let other = 0;
  for (const peer of peers.values()) {
    if (peer.handshake) handshaked += 1;
    if (peer.height_delta > 100) other += 1;
    if (matchesFilter(peer, needle)) rows.push(peer);
  }
  rows.sort(compareBy(sortValue, key, asc, "key"));
  summaryEl.textContent = seenEvent
    ? rows.length + " of " + peers.size + " connections shown, " + handshaked + " with handshake" +
      (other ? ", " + other + " on another chain" : "") +
      (asmapLoaded ? "" : " · no asmap loaded (start websocket with --asmap)")
    : "";
  sources.render(sourcesEl);
  renderWindow();
}

function onMessage(e) {
  const msg = parseMessage(e);
  if (!msg) return;
  if (msg.hello) {
    syncClock(msg.hello.server_time_ms);
    asmapLoaded = msg.hello.asmap;
    return;
  }
  if (msg.event) apply(msg.event);
}

function onReset() {
  peers.clear();
  bestHeight.clear();
  sources.clear();
  seenEvent = false;
  rows = [];
  refresh();
}

filterEl.addEventListener("input", refresh);
onlyHandshakeEl.addEventListener("change", refresh);
onlyOtherChainEl.addEventListener("change", refresh);
countBlocksEl.addEventListener("change", () => {
  updateSubscriptions(subscriptions());
  refresh();
});
scrollEl.addEventListener("scroll", scheduleWindow, { passive: true });
window.addEventListener("resize", scheduleWindow);
setInterval(refresh, REFRESH_MS);

connect(subscriptions(), onMessage, onReset);
