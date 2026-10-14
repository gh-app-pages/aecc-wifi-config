// Frame codec for the "shuoxd aiot" datalogger BLE protocol.

export const SERVICE_UUID = 0x00ff;
export const CHAR_UUID = 0xff01; // notify, and default write
export const ALT_WRITE_UUID = 0xff03; // fallback write characteristic

const AES_KEY = 'sxd_aiot_key_001';
const AES_IV = 'sxd_aiot_2022_01';
export const DEFAULT_SECRET = 'shuoxd_aiot_local_wireless_key01'; // param 54

export const FN_SET = 0x18;
export const FN_READ = 0x19;

const SERIAL_PLACEHOLDER = new Uint8Array(10).fill(0x30); // "0000000000"
const KEY_ACK = '000102030405060708090a0b0c';

const enc = new TextEncoder();
const dec = new TextDecoder();

export const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
export const fromHex = (h) => new Uint8Array(h.match(/../g).map((x) => parseInt(x, 16)));

const u16 = (n) => [(n >> 8) & 0xff, n & 0xff];

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function crc16modbus(bytes) {
  let crc = 0xffff;
  for (const b of bytes) {
    crc ^= b;
    for (let i = 0; i < 8; i++) crc = crc & 1 ? (crc >>> 1) ^ 0xa001 : crc >>> 1;
  }
  return crc;
}

// The app always appends 1..16 zero bytes (a full block when already aligned).
function zeroPad(bytes) {
  const out = new Uint8Array(bytes.length + (16 - (bytes.length % 16)));
  out.set(bytes);
  return out;
}

let keyPromise;
const aesKey = () =>
  (keyPromise ??= crypto.subtle.importKey('raw', enc.encode(AES_KEY), 'AES-CBC', false, ['encrypt', 'decrypt']));
const IV = enc.encode(AES_IV);

// Web Crypto only does PKCS#7 AES-CBC. For block-aligned input the last
// output block is pure padding, so dropping it yields NoPadding ciphertext.
async function aesEncryptNoPad(plain) {
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: IV }, await aesKey(), plain));
  return ct.slice(0, plain.length);
}

// To decrypt NoPadding data, forge one extra ciphertext block that decrypts
// to a valid PKCS#7 padding block (16 x 0x10) and let Web Crypto strip it.
async function aesDecryptNoPad(ct) {
  const key = await aesKey();
  const last = ct.slice(ct.length - 16);
  const pad = new Uint8Array(16).fill(16);
  const extra = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: last }, key, pad)).slice(0, 16);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv: IV }, key, concat(ct, extra)));
}

async function buildFrame(fn, body) {
  const padded = zeroPad(body);
  const ct = await aesEncryptNoPad(padded);
  const head = new Uint8Array([...u16(8 + padded.length), 0x00, 0x06, ...u16(2 + body.length), 0x01, fn]);
  const f = concat(head, ct);
  return concat(f, new Uint8Array(u16(crc16modbus(f))));
}

/** Function 0x18: write parameters. params = [{ id, value }] */
export function encodeSet(params) {
  const items = params.map(({ id, value }) => {
    const data = enc.encode(String(value));
    return concat(new Uint8Array([...u16(id), ...u16(data.length)]), data);
  });
  const total = items.reduce((n, i) => n + i.length, 0);
  return buildFrame(FN_SET, concat(SERIAL_PLACEHOLDER, new Uint8Array([...u16(params.length), ...u16(total)]), ...items));
}

/** Function 0x19: read parameters by id. */
export function encodeRead(ids) {
  return buildFrame(FN_READ, concat(SERIAL_PLACEHOLDER, new Uint8Array([...u16(ids.length), ...ids.flatMap(u16)])));
}

/** The device sends 00 01 … 0e unprompted right after notifications are enabled. */
export const isHandshake = (frame) => frame.length >= 13 && toHex(frame.slice(0, 13)) === KEY_ACK;

/** Total length of the frame at the start of buf, or null if not yet known. */
export function frameLength(buf) {
  if (buf.length >= 13 && toHex(buf.slice(0, 13)) === KEY_ACK) return Math.min(buf.length, 15);
  if (buf.length < 2) return null;
  return ((buf[0] << 8) | buf[1]) + 2;
}

/**
 * Decode a device frame.
 * Returns { kind: 'keyAck' } | { kind: 'set', ok } | { kind: 'read', ok, params: [{ id, raw }] }
 */
export async function decodeFrame(frame) {
  if (toHex(frame.slice(0, 13)) === KEY_ACK) return { kind: 'keyAck' };
  const body = frame.slice(0, -2);
  const crc = (frame[frame.length - 2] << 8) | frame[frame.length - 1];
  if (crc !== crc16modbus(body)) throw new Error('CRC mismatch');
  const fn = frame[7];
  const dataLen = (frame[4] << 8) | frame[5];
  const z = dataLen - 2; // meaningful plaintext bytes
  const ctLen = 16 * Math.ceil(dataLen / 16);
  const plain = await aesDecryptNoPad(frame.slice(8, 8 + ctLen));
  if (fn === FN_SET) return { kind: 'set', ok: plain[z - 1] === 0 };
  if (fn === FN_READ) {
    const count = (plain[10] << 8) | plain[11];
    const params = [];
    let o = 13;
    for (let i = 0; i < count && o + 4 <= z; i++) {
      const id = (plain[o] << 8) | plain[o + 1];
      const len = (plain[o + 2] << 8) | plain[o + 3];
      params.push({ id, raw: plain.slice(o + 4, o + 4 + len) });
      o += 4 + len;
    }
    return { kind: 'read', ok: params.length > 0, status: plain[12], params };
  }
  return { kind: 'unknown', fn, plain };
}

export const paramText = (raw) => dec.decode(raw);

/** Param 75: [count][len][ssid...][rssi int8] ... */
export function parseWifiList(raw) {
  const list = [];
  let o = 1;
  for (let i = 0; i < raw[0] && o < raw.length; i++) {
    const len = raw[o];
    const ssid = dec.decode(raw.slice(o + 1, o + 1 + len));
    const rssi = (raw[o + 1 + len] << 24) >> 24;
    list.push({ ssid, rssi });
    o += 2 + len;
  }
  return list;
}

// Datalogger settings
export const PARAM_DATALOGGER_TYPE = 13;
export const PARAM_SERVER_PORT = 18;
export const PARAM_SERVER_ADDR = 19;
// MQTT broker host: multi-node provisioning writes mqtt_base here
// after normalizeMqttBaseToHost (no scheme, port or path).
export const PARAM_MQTT_HOST = 17;

// Device group labels
const GROUP_LABELS = {
  0: 'Datalogger', 1: 'Controller', 2: 'Inverter', 3: 'Battery', 5: 'Socket', 6: 'Charging piles',
  7: 'Meter', 8: 'Relay', 9: 'Power controller', 10: 'Heat pump',
};

// returnDeviceType() built-in defaults (adds 131 to older tables).
const BUILTIN_GROUPS = [
  { type: 0, arr: [1, 2, 3, 4, 5, 6, 7, 8, 9, 13, 14, 106, 32, 66, 96, 54, 55, 65, 56, 81, 57, 82, 83, 101, 63, 64, 68, 69, 102, 75, 76, 92, 84, 79, 87, 85, 86, 88, 90, 131, 112, 93, 100, 95, 97, 98, 99, 103, 104, 105, 109, 110, 111, 114] },
  { type: 1, arr: [53, 77, 60, 61, 70, 80, 62, 91] },
  { type: 2, arr: [12, 15, 52, 59, 71, 72, 73, 115, 116, 117, 118, 119, 120, 121] },
  { type: 3, arr: [89] },
  { type: 5, arr: [58, 74] },
  { type: 6, arr: [10, 94] },
  { type: 7, arr: [11, 16, 17, 107, 108, 113, 78] },
];
const BUILTIN_TYPE_RE = /^(g:|G:)?[1-9]\d*(_[0-9a-fA-F]+){0,5}$/;

let GROUPS = BUILTIN_GROUPS;
let TYPE_RE = BUILTIN_TYPE_RE;
export let typeTableSource = 'built-in table';

/**
 * Apply a dataLogType.
 * Returns false and keeps the current table if invalid.
 */
export function applyTypeConfig(cfg, source) {
  const arr = cfg?.typeArr;
  if (!Array.isArray(arr) || !arr.length || !arr.every((g) => Number.isInteger(g?.type) && Array.isArray(g.arr))) return false;
  let re = TYPE_RE;
  if (typeof cfg.typeRegExp === 'string') {
    try { re = new RegExp(cfg.typeRegExp); } catch { return false; }
  }
  GROUPS = arr.map((g) => ({ type: g.type, arr: g.arr.map(Number) }));
  TYPE_RE = re;
  typeTableSource = source;
  return true;
}

/** Back to the built-in table (used by tests). */
export function resetTypeConfig() {
  GROUPS = BUILTIN_GROUPS;
  TYPE_RE = BUILTIN_TYPE_RE;
  typeTableSource = 'built-in table';
}

/** returnDeviceType(): group number, or -1 when the code is not in the table. */
export function deviceGroup(code) {
  return GROUPS.find((g) => g.arr.includes(code))?.type ?? -1;
}

export const groupLabel = (group) => GROUP_LABELS[group] ?? (group === -1 ? 'Unknown' : `Group ${group}`);

/**
 * Manufacturer data is ASCII "<type>#<namePrefix>", e.g. "89_1_0#ABC". Web Bluetooth
 * splits off the first two bytes as a little-endian company ID, so every possible
 * leading pair of type characters has to be requested up front.
 */
export const MANUFACTURER_IDS = (() => {
  const first = [...'0123456789gG'], second = [...'0123456789:_'];
  return first.flatMap((a) => second.map((b) => a.charCodeAt(0) | (b.charCodeAt(0) << 8)));
})();

export function manufacturerString(companyId, data) {
  const bytes = new Uint8Array(2 + data.byteLength);
  bytes.set([companyId & 0xff, companyId >> 8]);
  bytes.set(new Uint8Array(data.buffer, data.byteOffset, data.byteLength), 2);
  return dec.decode(bytes);
}

/**
 * Returns null when the type string is not one the app would list.
 */
export function parseAdvertisement(manufacturer, localName = '') {
  const hash = manufacturer.indexOf('#');
  const type = hash === -1 ? manufacturer : manufacturer.slice(0, hash);
  const bleName = (hash === -1 ? '' : manufacturer.slice(hash + 1)) + localName;
  if (!TYPE_RE.test(type)) return null;
  // getBroadcastData(): first field decimal, the rest hex.
  const fields = type.replace(/^[gG]:/, '').split('_').filter(Boolean)
    .map((f, i) => parseInt(f, i === 0 ? 10 : 16));
  const [code, machineMode, netMode] = fields;
  const group = code === 52 && bleName[6] === 'C' ? 7 : deviceGroup(code);
  return { type, bleName, code, machineMode, netMode, group, label: groupLabel(group) };
}

/**
 * Setting 13 (datalogger type). The value format is unverified on hardware; accept
 * either a full type string ("89_1_0") or a bare number.
 */
export function parseTypeSetting(value) {
  const v = String(value ?? '').trim();
  const info = parseAdvertisement(v);
  if (info) return info;
  const m = v.match(/^\d+/);
  if (!m) return null;
  const code = parseInt(m[0], 10);
  const group = deviceGroup(code);
  return { type: v, bleName: '', code, group, label: groupLabel(group) };
}

/** Param 55 (Wi-Fi link status). */
export function wifiStatus(code) {
  const n = Number(code);
  // Texts are standard en-US tip.log.* strings.
  const retry = 'Please confirm the router account password and then reconfigure the network.';
  if (n === 0) return { state: 'connected', text: 'Router connection successful' };
  if (n === 199) return { state: 'pending', text: 'Querying routing connection status (getting IP address)' };
  if (n === 255) return { state: 'pending', text: 'Querying routing connection status (connecting to router)' };
  if (n === 201) return { state: 'failed', text: 'Router account error', hint: retry };
  if (n === 204 || n === 205) return { state: 'failed', text: 'Router password error', hint: retry };
  return { state: 'pending', text: `Querying routing connection status (code ${code})` };
}

/** Param 60 (cloud server status). */
export function serverStatus(code) {
  const n = Number(code);
  if (n === 16 || n === 3 || n === 4) {
    return { ok: true, text: `Data is being exchanged between the device and the server. (code ${n})` };
  }
  return { ok: false, text: `Retrieving Server Interaction Status (code ${code})` };
}

// Exposed for the device simulator in test/;
export const _internal = { buildFrame, aesDecryptNoPad };
