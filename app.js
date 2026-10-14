import {
  DEFAULT_SECRET, PARAM_MQTT_HOST, PARAM_SERVER_ADDR, PARAM_SERVER_PORT,
  PARAM_DATALOGGER_TYPE, encodeSet, encodeRead, paramText, parseWifiList, wifiStatus, serverStatus,
  parseAdvertisement, parseTypeSetting, applyTypeConfig,
} from './codec.js';
import * as codec from './codec.js';
import { DataloggerBle } from './ble.js';
import { types } from './types.js';

applyTypeConfig(types, 'types.js');

window.__appLoaded = true; // checked by the fallback script in index.html
const $ = (id) => document.getElementById(id);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const ble = new DataloggerBle();

// The session key goes out when the device's connect handshake arrives,
// or after a 400 ms fallback (_scheduleSendSecretKeyAfterConnect, BP68); secret
// ack and SSID read waits of 5 s with up to 3 attempts (BP07–BP11, BP61–BP64).
const KEY_DELAY_MS = 400;
const ACK_TIMEOUT_MS = 5000;
const ATTEMPTS = 3;

// Server settings: each group is read on connect and written only when ticked.
const SERVER_GROUPS = {
  mqtt: { ids: [PARAM_MQTT_HOST], fields: { [PARAM_MQTT_HOST]: 'p17' } },
  server: { ids: [PARAM_SERVER_ADDR, PARAM_SERVER_PORT], fields: { [PARAM_SERVER_ADDR]: 'p19', [PARAM_SERVER_PORT]: 'p18' } },
};
const HOST_RE = /^[^\s/:]+$/; // bare host name or IPv4: no scheme, port, path or spaces

let deviceMqttHost = null; // setting 17 as read on connect
let lastTypeSetting; // setting 13 as read on connect (undefined until read)
let networks = [];
let currentSsid = '';
let busy = false;

if (!window.isSecureContext || !navigator.bluetooth) {
  const b = $('unsupported');
  b.hidden = false;
  const linux = /Linux/.test(navigator.userAgent) && !/Android/.test(navigator.userAgent);
  b.textContent = !window.isSecureContext
    ? 'Web Bluetooth needs a secure context: open this page via https:// or http://localhost.'
    : linux
      ? 'Web Bluetooth is off by default in Chrome/Chromium on Linux. Enable chrome://flags/#enable-experimental-web-platform-features, relaunch the browser and reload this page.'
      : 'This browser has no Web Bluetooth. Use Chrome or Edge on desktop/Android (not iOS Safari or Firefox).';
  $('btn-connect').disabled = true;
}

function log(kind, text) {
  const line = document.createElement('div');
  line.className = kind;
  line.textContent = `${new Date().toLocaleTimeString()}  ${kind.toUpperCase().padEnd(4)} ${text}`;
  $('log').append(line);
  $('log').scrollTop = $('log').scrollHeight;
}
ble.addEventListener('log', (e) => log(e.detail.kind, e.detail.text));
ble.addEventListener('disconnected', () => {
  log('info', 'Disconnected');
  setConnected(false);
});

function setConnected(on) {
  $('btn-connect').hidden = on;
  $('btn-disconnect').hidden = !on;
  $('s-wifi').setAttribute('aria-disabled', String(!on));
  $('s-status').setAttribute('aria-disabled', String(!on));
  $('conn-state').textContent = on ? `Bluetooth connection successful: ${ble.device?.name ?? ''}` : '';
  $('conn-state').className = on ? 'ok' : 'pending';
  if (!on) clearDeviceInfo();
}

function clearDeviceInfo() {
  $('device-info').hidden = true;
  $('di-name').textContent = '—';
  $('di-group').textContent = '—';
  $('di-type').textContent = '—';
  $('di-write').textContent = '—';
  lastTypeSetting = undefined;
}

function setState(el, text, cls) {
  $(el).textContent = text;
  $(el).className = cls;
}

const read = async (ids, label, timeout) => {
  const r = await ble.request(await encodeRead(ids), { label, timeout });
  if (r.kind !== 'read') throw new Error(`Unexpected reply to ${label}`);
  return new Map(r.params.map((p) => [p.id, p.raw]));
};

/** Read one setting, tolerating firmware that rejects it. Returns text or null. */
async function readSetting(id, label = `read setting ${id}`) {
  try {
    const r = await read([id], label);
    return r.has(id) ? paramText(r.get(id)) : null;
  } catch (e) {
    log('err', e.message);
    return null;
  }
}

async function withRetries(what, fn) {
  for (let attempt = 1; ; attempt++) {
    try {
      return await fn();
    } catch (e) {
      if (attempt >= ATTEMPTS || !ble.connected) throw e;
      log('err', `${e.message}; resending ${what} (${attempt + 1}/${ATTEMPTS})`);
    }
  }
}

async function guarded(fn) {
  if (busy) return;
  busy = true;
  try {
    await fn();
  } catch (e) {
    // NotFoundError is also used for "Bluetooth adapter not available", so only
    // stay quiet when the user simply closed the chooser.
    const cancelled = e.name === 'NotFoundError' && /cancel/i.test(e.message);
    log('err', e.message ?? String(e));
    $('conn-state').textContent = cancelled ? 'No device selected.' : e.message;
    $('conn-state').className = cancelled ? 'pending' : 'bad';
    if (!ble.connected) clearDeviceInfo();
  } finally {
    busy = false;
  }
}

// Step 1: connect, send session key (54), read SSID (56), device type (13) and server settings.
$('btn-connect').onclick = () => guarded(async () => {
  $('conn-state').textContent = 'Choose the AECC device in the browser dialog…';
  await ble.connect({ allDevices: true });
  $('conn-state').textContent = 'Connect Bluetooth…';
  showDeviceInfo();

  if (!(await ble.waitForHandshake(KEY_DELAY_MS))) log('info', `No connect handshake within ${KEY_DELAY_MS} ms; sending the session key anyway`);
  const keyFrame = await encodeSet([{ id: 54, value: DEFAULT_SECRET }]);
  const ack = await withRetries('session key', () =>
    ble.request(keyFrame, { label: 'set key (54)', timeout: ACK_TIMEOUT_MS, retryDelay: 100, acceptHandshake: true }));
  // Real devices answer with a normal 0x18 reply; older firmware may echo the handshake.
  if (ack.kind === 'keyAck' || (ack.kind === 'set' && ack.ok)) log('info', 'Session key accepted');
  else log('err', `Session key not confirmed: ${JSON.stringify(ack)}; continuing like the app`);
  setConnected(true);

  try {
    const r = await withRetries('SSID read', () => read([56], 'read SSID (56)', ACK_TIMEOUT_MS));
    currentSsid = r.has(56) ? paramText(r.get(56)) : '';
  } catch (e) {
    log('err', e.message);
  }
  $('current-ssid').textContent = currentSsid ? `Currently configured: ${currentSsid}` : '';
  if (currentSsid) $('ssid').value = currentSsid;

  const typeSetting = await readSetting(PARAM_DATALOGGER_TYPE, 'read device type (13)');
  log('info', `Setting 13 (device type) = ${typeSetting == null ? '(unreadable)' : JSON.stringify(typeSetting)}`);
  lastTypeSetting = typeSetting;
  showDeviceInfo(typeSetting);

  for (const [key, g] of Object.entries(SERVER_GROUPS)) {
    setGroupEditable(key, false);
    const values = {};
    for (const id of g.ids) {
      values[id] = await readSetting(id);
      $(g.fields[id]).value = values[id] ?? '';
      log('info', `Setting ${id} = ${values[id] == null ? '(unreadable)' : JSON.stringify(values[id])}`);
    }
    const shown = g.ids.map((id) => {
      const v = values[id];
      return `${id}: ${v == null ? 'unreadable' : v || '(empty)'}`;
    });
    $(`hint-${key}`).textContent = `Current value on device: ${shown.join(', ')}`;
    if (key === 'mqtt') deviceMqttHost = values[PARAM_MQTT_HOST];
  }

  await scanNetworks();
});

$('btn-disconnect').onclick = () => ble.disconnect();

/** Group from the advertisement; setting 13 is the fallback when the browser hides it. */
function showDeviceInfo(typeSetting) {
  const adv = ble.advertisement;
  const fromAdv = adv && parseAdvertisement(adv.manufacturer, adv.name || ble.device.name || '');
  const fromSetting = typeSetting != null ? parseTypeSetting(typeSetting) : null;
  const info = fromAdv || fromSetting;
  const source = fromAdv ? 'advertisement' : fromSetting ? 'setting 13' : null;

  $('device-info').hidden = false;
  $('di-name').textContent = fromAdv?.bleName || ble.device.name || '(no name)';
  $('di-write').textContent = ble.writeChar ? ble.writeUuid : '—';
  if (info) {
    const label = info.group === -1
      ? `Unknown (code ${info.code} is not in the type table)`
      : info.label;
    $('di-group').textContent = `${label}  (from ${source})`;
    const hasExtra = info.type !== String(info.code) || info.machineMode != null || info.netMode != null;
    const extra = hasExtra
      ? `  (raw "${info.type}"${info.machineMode != null ? `, mode ${info.machineMode}` : ''}${info.netMode != null ? `, net mode ${info.netMode}` : ''})`
      : '';
    $('di-type').textContent = `${info.code}${extra}`;
    if (fromAdv && fromSetting && fromAdv.code !== fromSetting.code) {
      log('info', `Advertised type ${fromAdv.code} differs from setting 13 (${fromSetting.code}); showing the advertised one like the app`);
    }
  } else if (typeSetting === undefined) {
    $('di-group').textContent = adv ? `Unrecognised advertisement "${adv.manufacturer}"; reading setting 13…` : 'Reading setting 13…';
    $('di-type').textContent = '—';
  } else {
    $('di-group').textContent = 'Unknown: no usable advertisement and setting 13 was unreadable'
      + (adv ? '' : ' (Chrome: chrome://flags/#enable-experimental-web-platform-features exposes advertisements)');
    $('di-type').textContent = typeSetting ? `setting 13 = "${typeSetting}"` : '—';
  }
}

function setGroupEditable(key, on) {
  $(`upd-${key}`).checked = on;
  for (const field of Object.values(SERVER_GROUPS[key].fields)) $(field).readOnly = !on;
}
// Browsers restore checkbox state on reload, so always start unticked.
for (const key of Object.keys(SERVER_GROUPS)) {
  setGroupEditable(key, false);
  $(`upd-${key}`).onchange = (e) => {
    setGroupEditable(key, e.target.checked);
    warnMqttChange();
  };
}
$('p17').oninput = warnMqttChange;
// A different MQTT host moves the device to another backend.
function warnMqttChange() {
  const to = $('p17').value.trim();
  const from = deviceMqttHost;
  $('warn-mqtt').hidden = !$('upd-mqtt').checked || !from || to === from;
  $('warn-mqtt').textContent = `The device reports to ${from}. `
    + `Changing it to ${to || '(empty)'} moves the device to that `
    + 'server; its current account will stop receiving data.';
}

/** Validated server params for the ticked groups, or throws with a user-facing message. */
function serverParams() {
  const params = [];
  if ($('upd-mqtt').checked) {
    const host = $('p17').value.trim();
    if (!HOST_RE.test(host)) throw new Error('MQTT host must be a bare host name or IP (no scheme, port, path or spaces)');
    params.push({ id: PARAM_MQTT_HOST, value: host });
  }
  if ($('upd-server').checked) {
    const addr = $('p19').value.trim();
    const port = $('p18').value.trim();
    if (!HOST_RE.test(addr)) throw new Error('Server address must be a bare host name or IP (no scheme, port, path or spaces)');
    if (!/^\d+$/.test(port) || +port < 1 || +port > 65535) throw new Error('Port must be a number from 1 to 65535');
    params.push({ id: PARAM_SERVER_ADDR, value: addr }, { id: PARAM_SERVER_PORT, value: port });
  }
  return params;
}

// Step 2: Wi-Fi list (param 75). The app retries after 10 s if nothing arrives.
async function scanNetworks() {
  $('networks').innerHTML = '<li>Querying The Wi‑Fi List…</li>';
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      const r = await read([75], 'read Wi-Fi list (75)', 10000);
      if (r.has(75)) {
        networks = parseWifiList(r.get(75));
        renderNetworks();
        return;
      }
    } catch (e) {
      log('err', `${e.message} (attempt ${attempt})`);
    }
  }
  $('networks').innerHTML = '<li>No networks returned — type the SSID manually.</li>';
}

function renderNetworks() {
  const show5g = $('show-5g').checked;
  const seen = new Set();
  const list = networks
    .filter((n) => show5g || !n.ssid.toLowerCase().includes('5g'))
    .sort((a, b) => b.rssi - a.rssi)
    .filter((n) => n.ssid && !seen.has(n.ssid) && seen.add(n.ssid));
  const i = list.findIndex((n) => n.ssid === currentSsid);
  if (i > 0) list.unshift(...list.splice(i, 1));

  const ul = $('networks');
  ul.replaceChildren();
  for (const n of list) {
    const li = document.createElement('li');
    li.setAttribute('aria-selected', String(n.ssid === $('ssid').value));
    const name = document.createElement('span');
    name.textContent = n.ssid;
    const rssi = document.createElement('span');
    rssi.className = 'rssi';
    rssi.textContent = `${n.rssi} dBm`;
    li.append(name, rssi);
    li.onclick = () => {
      $('ssid').value = n.ssid;
      renderNetworks();
      $('pwd').focus();
    };
    ul.append(li);
  }
  if (!list.length) ul.innerHTML = '<li>No 2.4 GHz networks found.</li>';
}

$('show-5g').onchange = renderNetworks;
$('btn-rescan').onclick = () => guarded(scanNetworks);
$('btn-showpwd').onclick = () => {
  const p = $('pwd');
  p.type = p.type === 'password' ? 'text' : 'password';
  $('btn-showpwd').textContent = p.type === 'password' ? 'Show' : 'Hide';
};

// Steps 4–6: write SSID/password (56/57), poll Wi-Fi status (55), then server status (60).
$('btn-send').onclick = () => guarded(async () => {
  const ssid = $('ssid').value;
  const pwd = $('pwd').value;
  if (!ssid) return log('err', 'Wi‑Fi Name Cannot Be Empty, Please Select Or Enter 2.4Wifi');
  if (!pwd) return log('err', "Wi‑Fi Can't Be Empty. Please Enter the Password");

  let extra;
  try {
    extra = serverParams();
  } catch (e) {
    return log('err', e.message);
  }
  const params = [{ id: 56, value: ssid }, { id: 57, value: pwd }, ...extra];
  for (const p of extra) log('info', `Also writing setting ${p.id} = ${p.value}`);

  setState('st-wifi', 'Sending credentials…', 'pending');
  setState('st-server', '—', '');
  $('st-hint').textContent = '';
  const set = await ble.request(await encodeSet(params), { label: `set ${params.map((p) => p.id).join('/')}` });
  if (set.kind === 'set' && !set.ok) log('err', 'Device reported "command set failed"; polling anyway like the app');

  await pollStatus({ wifiChecks: 20, serverChecks: 30, firstDelay: 2000 });
});

/**
 * Poll Wi-Fi status (55), then server status (60) once Wi-Fi is up. After sending
 * credentials this follows the app (20 × 55, 30 × 60, 2 s apart); "Check status
 * again" uses a short version that changes nothing on the device.
 */
async function pollStatus({ wifiChecks, serverChecks, firstDelay = 0 }) {
  setState('st-server', '—', '');
  $('st-hint').textContent = '';
  let wifiOk = false;
  for (let i = 0; i < wifiChecks && !wifiOk; i++) {
    if (i || firstDelay) await sleep(i ? 2000 : firstDelay);
    const r = await read([55], 'read Wi-Fi status (55)').catch((e) => (log('err', e.message), null));
    if (!r?.has(55)) continue;
    const s = wifiStatus(paramText(r.get(55)));
    setState('st-wifi', s.text, s.state === 'connected' ? 'ok' : s.state === 'failed' ? 'bad' : 'pending');
    if (s.state === 'failed') return ($('st-hint').textContent = s.hint ?? '');
    wifiOk = s.state === 'connected';
  }
  if (!wifiOk) {
    setState('st-wifi', 'Router connection failed', 'bad');
    $('st-hint').textContent = '1. Please confirm that the router network is normal.';
    return;
  }

  setState('st-server', 'Retrieving Server Interaction Status', 'pending');
  for (let i = 0; i < serverChecks; i++) {
    if (i) await sleep(2000);
    const r = await read([60], 'read server status (60)').catch((e) => (log('err', e.message), null));
    if (r?.has(60)) {
      const s = serverStatus(paramText(r.get(60)));
      setState('st-server', s.text, s.ok ? 'ok' : 'pending');
      if (s.ok) return log('info', 'Device is exchanging data with the server');
    }
  }
  setState('st-server', 'No data interaction', 'bad');
  $('st-hint').textContent = "1. Please confirm that the operator's network status is normal. "
    + '2. Reconfigure the network after restarting the router. '
    + 'The first cloud connection can take a few minutes; use "Check status again" later.';
}

// Read-only: re-reads 55 and 60 without resending credentials.
$('btn-recheck').onclick = () => guarded(async () => {
  log('info', 'Checking status again (read-only)');
  setState('st-wifi', 'Querying routing connection status', 'pending');
  await pollStatus({ wifiChecks: 1, serverChecks: 5 });
});
