// Block propagation page: builds, from the announcement events, how quickly
// each block reached the observer's peers.
//
// The time axis follows the data: it ends at the slowest 99th percentile
// among the drawn blocks, so a block that took a minute to reach everyone is
// not squeezed into the left edge and a fast one is not lost in empty space.
// Curves are drawn from a fixed number of samples rather than one point per
// announcement, which at thousands of connections is the difference between
// a chart that redraws in milliseconds and one that stalls the page.
"use strict";

// Blocks kept; the oldest is evicted beyond this.
const HISTORY = 50;
// Announcement offsets kept per block. The counts keep going past it, only
// the curve stops gaining detail it could not show anyway.
const MAX_OFFSETS = 20_000;
// Points per curve.
const SAMPLES = 200;
// How often the chart and the table are redrawn while events keep arriving.
const REFRESH_MS = 1000;
// The axis ends this far beyond the slowest percentile, so the last step of
// a curve is not drawn on the frame.
const HEADROOM = 1.05;

const ANNOUNCEMENT_TYPES = { 1: "inv", 2: "headers", 3: "compact_block" };
const PROBE_REQUESTED = 1;
const PROBE_ANSWERED = 2;

const blocks = new Map(); // key -> block record
const pendingProbes = new Map(); // block/instance/connection -> request ms
const sources = sourceTracker();
// Whether an announcement has arrived, which separates "waiting for the next
// block" from "the blocks we have do not match the filters".
let seenAnnouncement = false;

const sourcesEl = document.getElementById("sources");
const networkEl = document.getElementById("network");
const curvesEl = document.getElementById("curves");
const placedOnlyEl = document.getElementById("placed-only");
const summaryEl = document.getElementById("summary");
const chartEl = document.getElementById("chart");
const legendEl = document.getElementById("legend");
const tableBody = document.querySelector("#blocks tbody");

function label(block) {
  return (block.height !== null && block.height !== undefined ? block.height : shortHash(block.hash)) +
    (networkEl.value === "" ? " " + block.network : "");
}

// Sorted once per render and cached: the curve, the percentiles and the axis
// all want the same sorted offsets.
function sortedOffsets(block) {
  if (!block.sorted || block.sorted.length !== block.offsets_ms.length) {
    block.sorted = [...block.offsets_ms].sort((a, b) => a - b);
  }
  return block.sorted;
}

function apply(ev) {
  if (!ev || !ev.event) return;
  sources.note(ev);
  const kind = Object.keys(ev.event)[0];
  const body = ev.event[kind];
  if (kind === "BlockAnnouncement") announcement(ev, body);
  else if (kind === "CompactBlockProbe") probe(ev, body);
}

function announcement(ev, body) {
  seenAnnouncement = true;
  const key = ev.network + "/" + body.block_hash;
  let block = blocks.get(key);
  if (!block) {
    block = {
      key,
      network: ev.network,
      hash: body.block_hash,
      height: body.height ?? null,
      txs: null,
      first_seen_ms: ev.timestamp_ms,
      first_peer: ev.peer_addr,
      first_user_agent: ev.user_agent || "",
      first_type: ANNOUNCEMENT_TYPES[body.announcement_type] || "unknown",
      announcements: 0,
      inv: 0,
      headers: 0,
      compact_block: 0,
      new_to_us: 0,
      max_batch: 0,
      offsets_ms: [],
      probe_requests: 0,
      probe_answers: 0,
      probe_latency_ms: [],
      sorted: null,
    };
    blocks.set(key, block);
    evict();
  }
  if (block.height === null && body.height !== null && body.height !== undefined) {
    block.height = body.height;
  }
  if (body.compact_block && block.txs === null) {
    block.txs = body.compact_block.short_ids + body.compact_block.prefilled_txs;
  }
  block.announcements += 1;
  const type = ANNOUNCEMENT_TYPES[body.announcement_type];
  if (type === "inv") block.inv += 1;
  else if (type === "headers") block.headers += 1;
  else if (type === "compact_block") block.compact_block += 1;
  if (body.new_to_us) block.new_to_us += 1;
  if (body.batch_size > block.max_batch) block.max_batch = body.batch_size;
  // An event that predates the first one we saw would make the offset
  // negative; the earliest announcement is the reference instead.
  if (ev.timestamp_ms < block.first_seen_ms) {
    const shift = block.first_seen_ms - ev.timestamp_ms;
    for (let i = 0; i < block.offsets_ms.length; i++) block.offsets_ms[i] += shift;
    block.first_seen_ms = ev.timestamp_ms;
    block.first_peer = ev.peer_addr;
    block.first_user_agent = ev.user_agent || "";
    block.first_type = type || "unknown";
  }
  if (block.offsets_ms.length < MAX_OFFSETS) {
    const offset = ev.timestamp_ms - block.first_seen_ms;
    block.offsets_ms.push(offset);
    // Announcements arrive in time order almost always, so the sorted copy
    // is usually extended rather than thrown away and rebuilt.
    if (block.sorted && offset >= block.sorted[block.sorted.length - 1]) block.sorted.push(offset);
    else block.sorted = null;
  }
}

function probe(ev, body) {
  const key = ev.network + "/" + body.block_hash;
  const block = blocks.get(key);
  if (!block) return;
  const id = key + "/" + ev.instance_id + "/" + ev.connection_id;
  if (body.stage === PROBE_REQUESTED) {
    block.probe_requests += 1;
    pendingProbes.set(id, ev.timestamp_ms);
  } else if (body.stage === PROBE_ANSWERED) {
    block.probe_answers += 1;
    const sent = pendingProbes.get(id);
    if (sent !== undefined) {
      pendingProbes.delete(id);
      block.probe_latency_ms.push(Math.max(0, ev.timestamp_ms - sent));
    }
  }
}

function evict() {
  while (blocks.size > HISTORY) {
    let oldest = null;
    for (const block of blocks.values()) {
      if (!oldest || block.first_seen_ms < oldest.first_seen_ms) oldest = block;
    }
    if (!oldest) return;
    blocks.delete(oldest.key);
    for (const id of pendingProbes.keys()) {
      if (id.startsWith(oldest.key + "/")) pendingProbes.delete(id);
    }
  }
}

function selected() {
  const net = networkEl.value;
  return [...blocks.values()]
    .filter((b) => (net === "" || b.network === net) && (!placedOnlyEl.checked || b.height !== null))
    .sort((a, b) => b.first_seen_ms - a.first_seen_ms);
}

function updateNetworks() {
  const nets = [...new Set([...blocks.values()].map((b) => b.network))].sort();
  const current = networkEl.value;
  if (nets.join() === networkEl.dataset.nets) return;
  networkEl.dataset.nets = nets.join();
  networkEl.replaceChildren(el("option", null, "all"));
  networkEl.firstChild.value = "";
  for (const n of nets) {
    const o = el("option", null, n);
    o.value = n;
    networkEl.append(o);
  }
  networkEl.value = nets.includes(current) ? current : "";
}

// At most `SAMPLES` points along the curve, always including its last step,
// so the shape and the end of a 6700-announcement block survive.
function curve(block, name) {
  const offsets = sortedOffsets(block);
  const total = offsets.length;
  const step = Math.max(1, Math.ceil(total / SAMPLES));
  const points = [{ s: 0, share: 0, block: name }];
  for (let i = step - 1; i < total; i += step) {
    points.push({ s: offsets[i] / 1000, share: (i + 1) / total, block: name });
  }
  const last = offsets[total - 1] / 1000;
  if (points[points.length - 1].s !== last) points.push({ s: last, share: 1, block: name });
  return points;
}

function renderChart(rows) {
  const n = Math.max(1, Number(curvesEl.value) || 10);
  const drawn = rows.slice(0, n).filter((b) => sortedOffsets(b).length > 1);
  const points = [];
  let worstP99 = 0;
  for (const block of drawn) {
    const p99 = percentile(sortedOffsets(block), 0.99);
    if (p99 > worstP99) worstP99 = p99;
    points.push(...curve(block, label(block)));
  }
  // Keep the page still: the chart and its legend have a fixed height in the
  // stylesheet, and the scroll position is put back if a redraw moved it.
  const scrollY = window.scrollY;
  chartEl.replaceChildren();
  legendEl.replaceChildren();
  const chartEmpty = document.getElementById("chart-empty");
  if (points.length === 0) {
    chartEmpty.hidden = false;
    // A block every ten minutes or so, and a curve needs a second
    // announcement, so this is a wait rather than an answer.
    if (!seenAnnouncement) placeholder(chartEmpty, "waiting", "waiting for the first block announcement");
    else placeholder(chartEmpty, "empty", "no block announced to more than one peer yet");
    return;
  }
  chartEmpty.hidden = true;
  const seconds = Math.max(1, (worstP99 / 1000) * HEADROOM);
  const plot = Plot.plot({
    width: Math.min(1100, chartEl.clientWidth || 1100),
    height: 360,
    marginLeft: 50,
    x: { label: "seconds after the first announcement →", domain: [0, seconds] },
    y: { label: "↑ share of announcements", domain: [0, 1], percent: true, grid: true },
    color: { legend: false },
    marks: [
      Plot.line(points, { x: "s", y: "share", stroke: "block", curve: "step-after", tip: true }),
      Plot.ruleY([0.5, 0.9, 0.99], { stroke: "#bbb", strokeDasharray: "3,3" }),
    ],
  });
  chartEl.append(plot);
  try {
    const legend = plot.legend("color");
    if (legend) legendEl.append(legend);
  } catch (e) {
    // A single curve has no colour scale to make a legend from.
  }
  if (window.scrollY !== scrollY) window.scrollTo(window.scrollX, scrollY);
  return seconds;
}

function renderTable(rows) {
  const body = document.createDocumentFragment();
  for (const b of rows) {
    const offsets = sortedOffsets(b);
    const latency = [...b.probe_latency_ms].sort((x, y) => x - y);
    const row = document.createElement("tr");
    if (b.height === null) row.classList.add("otherchain");
    textCell(row, b.height === null ? "" : b.height, "num");
    textCell(row, shortHash(b.hash), null, b.hash);
    textCell(row, b.network);
    textCell(row, time(b.first_seen_ms), null, new Date(b.first_seen_ms).toISOString());
    textCell(row, b.first_type);
    textCell(row, b.first_peer, null, b.first_user_agent);
    textCell(row, b.announcements, "num");
    textCell(row, b.compact_block + "/" + b.headers + "/" + b.inv, "num");
    textCell(row, b.new_to_us, "num");
    textCell(row, b.txs === null ? "" : b.txs, "num");
    textCell(row, offsets.length > 1 ? duration(percentile(offsets, 0.5)) : "", "num");
    textCell(row, offsets.length > 1 ? duration(percentile(offsets, 0.9)) : "", "num");
    textCell(row, offsets.length > 1 ? duration(percentile(offsets, 0.99)) : "", "num");
    textCell(row, b.probe_requests ? b.probe_answers + "/" + b.probe_requests : "", "num");
    textCell(row, latency.length ? duration(percentile(latency, 0.5)) : "", "num");
    textCell(row, b.max_batch, "num");
    body.append(row);
  }
  tableBody.replaceChildren(body);
  const empty = document.getElementById("blocks-empty");
  empty.hidden = rows.length > 0;
  if (rows.length > 0) return;
  if (!seenAnnouncement) placeholder(empty, "waiting", "waiting for the first block announcement");
  else placeholder(empty, "empty", "no block matches the network and height filters");
}

function render() {
  updateNetworks();
  const rows = selected();
  const seconds = renderChart(rows);
  renderTable(rows);
  const unplaced = [...blocks.values()].filter((b) => b.height === null).length;
  summaryEl.textContent = seenAnnouncement
    ? rows.length + " of " + blocks.size + " blocks shown" +
      (unplaced ? ", " + unplaced + " without a height" : "") +
      (seconds ? " · axis to " + seconds.toFixed(1) + "s, the slowest 99th percentile drawn" : "")
    : "";
  sources.render(sourcesEl);
}
const queue = renderer(render);
// A block reaches every connection within seconds, so events arrive in
// bursts of thousands. Redrawing on a timer rather than per event keeps one
// burst to one redraw instead of one per animation frame.
let dirty = false;

function onMessage(e) {
  const msg = parseMessage(e);
  if (!msg) return;
  if (msg.hello) {
    syncClock(msg.hello.server_time_ms);
    return;
  }
  if (msg.event) {
    apply(msg.event);
    dirty = true;
  }
}

function onReset() {
  blocks.clear();
  pendingProbes.clear();
  sources.clear();
  seenAnnouncement = false;
  queue();
}

networkEl.addEventListener("change", queue);
curvesEl.addEventListener("change", queue);
placedOnlyEl.addEventListener("change", queue);
window.addEventListener("resize", queue);
setInterval(() => {
  if (!dirty) return;
  dirty = false;
  render();
}, REFRESH_MS);
// Once up front, so the page shows what it is waiting for before any event
// arrives; after that only a change redraws it.
render();
connect({ block_announcements: true, compact_block_probes: true }, onMessage, onReset);
