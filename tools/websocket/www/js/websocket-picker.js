/*
 Lets a page connect to one of several websocket tool instances.

 A `websockets.json` file served next to the page maps names to websocket
 URLs, e.g. { "eu": "ws://127.0.0.1:47484", "us": "wss://host/ws/us" }
 (same format as peer-observer's websocket tools). The picker renders one
 radio button per entry; `?ws=<url>` in the page URL selects or adds a
 websocket directly, which is handy during development when there is no
 websockets.json.

 Usage:
   initWebsocketPicker("websockets.json", "websocket-picker", onMessage, onReset)
   updateSubscriptions({ peers: true })   // sent on every (re)connect
*/

var g_websockets = {};
var g_ws = null;
var g_url = null;
var g_messageCallback = null;
var g_resetCallback = null;
var g_statusCallback = null;
var g_subscriptions = {};
var g_reconnectTimer = null;

function updateSubscriptions(subscriptions) {
  g_subscriptions = subscriptions;
  if (g_ws && g_ws.readyState === WebSocket.OPEN) {
    g_ws.send(JSON.stringify(g_subscriptions));
  }
}

function setStatus(text, error) {
  if (typeof g_statusCallback === "function") {
    g_statusCallback(text, !!error);
  }
}

function switchWebsocket(url) {
  clearTimeout(g_reconnectTimer);
  if (g_ws) {
    g_ws.onclose = null;
    g_ws.close();
  }
  if (typeof g_resetCallback === "function") {
    g_resetCallback();
  }
  g_url = url;
  setStatus("connecting to " + url + " …");
  try {
    g_ws = new WebSocket(url);
  } catch (e) {
    setStatus("cannot open " + url + ": " + e.message, true);
    return;
  }
  g_ws.onopen = () => {
    setStatus("connected to " + url);
    g_ws.send(JSON.stringify(g_subscriptions));
  };
  g_ws.onmessage = (e) => {
    if (typeof g_messageCallback === "function") {
      g_messageCallback(e);
    }
  };
  g_ws.onerror = () => setStatus("websocket error for " + url, true);
  g_ws.onclose = () => {
    setStatus("disconnected from " + url + ", reconnecting in 5 s", true);
    g_reconnectTimer = setTimeout(() => switchWebsocket(url), 5000);
  };
}

function drawWebsockets(divId) {
  const picker = document.getElementById(divId);
  picker.replaceChildren();
  const names = Object.keys(g_websockets);
  for (const name of names) {
    const radio = document.createElement("input");
    radio.type = "radio";
    radio.name = "websocket-picker";
    radio.id = "websocket-" + name;
    radio.value = name;
    radio.checked = g_websockets[name] === g_url;
    radio.addEventListener("change", () => switchWebsocket(g_websockets[name]));
    const label = document.createElement("label");
    label.htmlFor = radio.id;
    label.textContent = name;
    const wrapper = document.createElement("span");
    wrapper.append(radio, " ", label);
    picker.append(wrapper);
  }
  // Manual entry, always available.
  const form = document.createElement("form");
  const input = document.createElement("input");
  input.type = "text";
  input.placeholder = "ws://127.0.0.1:47484";
  input.value = names.length === 0 && g_url ? g_url : "";
  const button = document.createElement("button");
  button.type = "submit";
  button.textContent = "connect";
  form.append(input, " ", button);
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const url = input.value.trim();
    if (url.length > 0) {
      for (const r of picker.querySelectorAll("input[type=radio]")) {
        r.checked = false;
      }
      switchWebsocket(url);
    }
  });
  picker.append(form);
  if (names.length === 0) {
    const hint = document.createElement("span");
    hint.className = "dim";
    hint.textContent = "no websockets.json found, enter a websocket URL or use ?ws=";
    picker.append(hint);
  }
}

/*
 params:
  websocketJsonUrl: URL of the websockets.json file
  divId: id of the element the picker is rendered into
  messageCallback: called with every websocket MessageEvent
  resetCallback: called when switching websockets; should reset page state
  statusCallback: optional, called with (text, isError) on connection changes
*/
function initWebsocketPicker(websocketJsonUrl, divId, messageCallback, resetCallback, statusCallback) {
  g_messageCallback = messageCallback;
  g_resetCallback = resetCallback;
  g_statusCallback = statusCallback;
  const params = new URLSearchParams(location.search);
  const fromUrl = params.get("ws");

  fetch(websocketJsonUrl)
    .then((response) => (response.ok ? response.json() : {}))
    .catch(() => ({}))
    .then((data) => {
      g_websockets = data && typeof data === "object" ? data : {};
      const names = Object.keys(g_websockets);
      if (fromUrl) {
        switchWebsocket(fromUrl);
      } else if (names.length === 1) {
        switchWebsocket(g_websockets[names[0]]);
      } else if (names.length === 0) {
        setStatus("no websocket selected");
      }
      drawWebsockets(divId);
    });
}
