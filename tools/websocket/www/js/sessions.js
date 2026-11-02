// Ended sessions page: the sessions whose end the observer reported while
// this page was open, newest first.
//
// Its own page rather than a second table on the connections page, because
// the two are different things: that one is a census of what is connected
// now, this one a log of what has stopped being connected. One is bounded by
// the network and one by time, they want opposite sort orders, and the
// virtualised table over there cannot hold both.
"use strict";

// Sessions kept. A log has to forget something: peers that complete the
// handshake and hang up on a one-minute timer ended two thirds of all
// sessions on mainnet, so anything unbounded here is a leak.
const MAX_ENDED = 500;

// Handshakes remembered for connections still open, so an ended session can
// show what the peer claimed when it arrived -- the result event does not
// carry it. Bounded as well: the observer holds some connections for days,
// and a handshake whose result never comes would otherwise be kept forever.
// Past the cap the oldest is dropped, and its session ends with those
// columns empty, like one that handshook before this page connected.
const MAX_OPEN = 20_000;

// How often the table is redrawn while events keep arriving.
const REFRESH_MS = 1000;

// DisconnectReason, which arrives as the protobuf number.
const REASONS = {
  0: "unknown",
  1: "peer closed",
  2: "truncated",
  3: "connection reset",
  4: "decode error",
  5: "v2 decrypt error",
  6: "write error",
  7: "other",
};
// A peer closing at a message boundary is the ordinary way a session ends.
// Every other reason means something went wrong, on one side or the other.
const CLEAN_REASON = 1;

const open = new Map(); // peer key -> what the handshake said
const ended = []; // newest first
const sources = sourceTracker();

let asmapLoaded = false;
let seenEvent = false;
let dirty = true;
let rows = [];

const filterEl = document.getElementById("filter");
const onlySilentEl = document.getElementById("only-silent");
const onlyUncleanEl = document.getElementById("only-unclean");
const summaryEl = document.getElementById("summary");
const sourcesEl = document.getElementById("sources");
const sessionsTable = document.getElementById("sessions");
const sessionsBody = sessionsTable.querySelector("tbody");

const TEXT_KEYS = ["network", "peer_ip", "as_name", "transport", "user_agent", "reason"];
const sortState = sortableHeaders(sessionsTable, "ended_at_ms", false, TEXT_KEYS, () => refresh(true));

// The handshake for what the peer claimed, and the results themselves. The
// heavier kinds say nothing about how a session ended.
function subscriptions() {
  return { handshakes: true, connection_results: true };
}

function noteHandshake(ev, body) {
  open.set(peerKey(ev), {
    start_height: body.start_height,
    user_agent: body.user_agent || ev.user_agent || "",
  });
  // Insertion order, so the first key is the oldest handshake.
  while (open.size > MAX_OPEN) {
    open.delete(open.keys().next().value);
  }
}

function noteResult(ev, body) {
  const result = body.result || {};
  const kind = Object.keys(result)[0];
  // Only a session that ran. An attempt that never reached one has no peer
  // to report on, and the reachability of addresses is a counter rather than
  // a log line.
  if (kind !== "Disconnected") return;
  const d = result[kind];
  const key = peerKey(ev);
  const claimed = open.get(key);
  open.delete(key);
  const { ip, port } = splitAddr(ev.peer_addr);
  const messages = d.messages_by_command || {};
  const other = d.messages_other || 0;

  ended.unshift({
    key,
    network: ev.network,
    peer_addr: ev.peer_addr,
    peer_ip: ip,
    peer_port: port,
    ip: ev.ip || null,
    transport: ev.transport_version === 1 ? "v1" : ev.transport_version === 2 ? "v2" : "unknown",
    user_agent: (claimed && claimed.user_agent) || ev.user_agent || "",
    start_height: claimed ? claimed.start_height : null,
    uptime_ms: d.uptime_ms || 0,
    setup_ms: d.setup_ms || 0,
    reason_code: d.reason || 0,
    reason: REASONS[d.reason || 0] || "unknown",
    messages,
    messages_other: other,
    // The handshake is what made this a session, so it does not count: this
    // is whether the peer said anything afterwards.
    silent: Object.keys(messages).length === 0 && other === 0,
    unsolicited_pongs: d.unsolicited_pongs || 0,
    ended_at_ms: ev.timestamp_ms,
  });
  ended.length = Math.min(ended.length, MAX_ENDED);
  dirty = true;
}

function apply(ev) {
  if (!ev || !ev.event) return;
  seenEvent = true;
  sources.note(ev);
  const kind = Object.keys(ev.event)[0];
  const body = ev.event[kind];
  if (kind === "Handshake") noteHandshake(ev, body);
  else if (kind === "ConnectionResult") noteResult(ev, body);
}

function messageSummary(session) {
  if (session.silent) return "nothing";
  const top = topEntries(session.messages, 6);
  return top + (session.messages_other ? (top ? " " : "") + "other×" + session.messages_other : "");
}

function sortValue(session, key) {
  switch (key) {
    case "asn":
      return session.ip ? session.ip.asn : 0;
    case "as_name":
      return asName(session.ip);
    case "messages":
      return sumValues(session.messages) + session.messages_other;
    // Unknown reads as lower than any claim, rather than as zero among them.
    case "start_height":
      return session.start_height === null ? -1 : session.start_height;
    default: {
      const value = session[key];
      return value === null || value === undefined ? "" : value;
    }
  }
}

function matchesFilter(session, needle) {
  if (onlySilentEl.checked && !session.silent) return false;
  if (onlyUncleanEl.checked && session.reason_code === CLEAN_REASON) return false;
  if (!needle) return true;
  return (
    session.network.toLowerCase().includes(needle) ||
    session.peer_addr.toLowerCase().includes(needle) ||
    session.user_agent.toLowerCase().includes(needle) ||
    session.reason.includes(needle) ||
    asName(session.ip).toLowerCase().includes(needle)
  );
}

function fillRow(row, session) {
  if (session.silent) row.classList.add("nohandshake");
  textCell(row, session.network);
  peerCell(row, session);
  asnCell(row, session);
  asCell(row, session);
  textCell(row, session.transport, session.transport === "unknown" ? "dim" : null);
  textCell(row, session.user_agent, "ua", session.user_agent);
  textCell(row, session.start_height === null ? "" : session.start_height, "num");
  textCell(row, duration(session.uptime_ms), "num", session.uptime_ms + "ms");
  textCell(row, duration(session.setup_ms), "num", session.setup_ms + "ms");
  textCell(row, session.reason, session.reason_code === CLEAN_REASON ? null : "warn");
  textCell(row, messageSummary(session), session.silent ? "dim" : null);
  textCell(row, session.unsolicited_pongs || "", "num");
  textCell(row, time(session.ended_at_ms), "dim");
}

// Nothing to show is either "no event has arrived yet", which a spinner
// says, or an answer: nothing has ended, or nothing matches the filter.
function emptyState(total) {
  const node = document.getElementById("sessions-empty");
  node.hidden = total > 0;
  if (total > 0) return;
  if (!seenEvent) placeholder(node, "waiting", "waiting for the first event");
  else if (ended.length === 0) placeholder(node, "empty", "no session has ended yet");
  else placeholder(node, "empty", "no ended session matches the filter");
}

function renderTable() {
  const body = document.createDocumentFragment();
  for (const session of rows) {
    const row = document.createElement("tr");
    fillRow(row, session);
    body.append(row);
  }
  sessionsBody.replaceChildren(body);
  emptyState(rows.length);
}

const scheduleTable = renderer(renderTable);

// `force` for a new filter or sort order, which changes the rows without an
// event having arrived.
function refresh(force) {
  sources.render(sourcesEl);
  if (!dirty && !force) return;
  dirty = false;

  const needle = filterEl.value.trim().toLowerCase();
  const { key, asc } = sortState();
  let silent = 0;
  rows = [];
  for (const session of ended) {
    if (session.silent) silent += 1;
    if (matchesFilter(session, needle)) rows.push(session);
  }
  rows.sort(compareBy(sortValue, key, asc, "key"));
  summaryEl.textContent = seenEvent
    ? rows.length + " of " + ended.length + " ended sessions shown, " + silent + " sent nothing" +
      (asmapLoaded ? "" : " · no asmap loaded (start websocket with --asmap)")
    : "";
  scheduleTable();
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
  open.clear();
  ended.length = 0;
  sources.clear();
  seenEvent = false;
  rows = [];
  refresh(true);
}

filterEl.addEventListener("input", () => refresh(true));
onlySilentEl.addEventListener("change", () => refresh(true));
onlyUncleanEl.addEventListener("change", () => refresh(true));
setInterval(() => refresh(false), REFRESH_MS);

connect(subscriptions(), onMessage, onReset);
