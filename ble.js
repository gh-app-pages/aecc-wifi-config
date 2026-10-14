// Web Bluetooth transport for service 0x00FF, one request in flight at a time.
// Notifications always come on 0xFF01.
// Some firmware writes to 0xFF01 while other firmware writes to 0xFF03,
// so 0xFF03 is the fallback when 0xFF01 does not accept writes.
import {
  SERVICE_UUID, CHAR_UUID, ALT_WRITE_UUID, MANUFACTURER_IDS, frameLength, decodeFrame, toHex, manufacturerString, isHandshake,
} from './codec.js';

const canWrite = (c) => !!(c?.properties.write || c?.properties.writeWithoutResponse);
// What Chrome throws when the characteristic refuses writes ("GATT operation not permitted").
const isWriteRefused = (e) => e?.name === 'NotSupportedError' || e?.name === 'NotAllowedError';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class DataloggerBle extends EventTarget {
  device = null;
  char = null; // notify characteristic (0xFF01)
  writeChar = null; // 0xFF01, or 0xFF03 as fallback
  #altChar = null; // 0xFF03 if the device has it
  advertisement = null; // { manufacturer, name } or null when the browser can't provide it
  handshakeSeen = false; // set when the device sends its 00 01 … 0e connect handshake
  #rx = new Uint8Array(0);
  #pending = null;
  #queue = Promise.resolve();

  // Native app: BleManager.setReConnectCount(3, WebAppActivity.SPLASH_SECOND = 5000 ms).
  static CONNECT_RETRIES = 3;
  static CONNECT_RETRY_DELAY = 5000;

  /**
   * Real devices advertise service 0x00FF, so the chooser lists only those by default;
   * allDevices lists everything (for firmware that does not advertise it).
   */
  async connect({ namePrefix, allDevices = true } = {}) {
    const common = { optionalServices: [SERVICE_UUID], optionalManufacturerData: MANUFACTURER_IDS };
    const filter = { ...(allDevices ? {} : { services: [SERVICE_UUID] }), ...(namePrefix ? { namePrefix } : {}) };
    const options = Object.keys(filter).length ? { filters: [filter], ...common } : { acceptAllDevices: true, ...common };
    this.device = await navigator.bluetooth.requestDevice(options);
    this.handshakeSeen = false;
    this.advertisement = await this.#readAdvertisement();
    this.device.addEventListener('gattserverdisconnected', () => {
      this.#fail(new Error('Device disconnected'));
      this.dispatchEvent(new Event('disconnected'));
    });
    this.#log('info', `Connecting to ${this.device.name ?? this.device.id}…`);
    const server = await this.#gattConnect();
    const service = await server.getPrimaryService(SERVICE_UUID).catch(() => {
      throw new Error('Service 0x00FF not found — this does not look like a supported AECC device');
    });
    this.char = await service.getCharacteristic(CHAR_UUID);
    this.#altChar = await service.getCharacteristic(ALT_WRITE_UUID).catch(() => null);
    this.writeChar = canWrite(this.char) || !canWrite(this.#altChar) ? this.char : this.#altChar;
    this.char.addEventListener('characteristicvaluechanged', (e) => this.#onNotify(e.target.value));
    await this.char.startNotifications();
    this.#log('info', `Connected, notifications on 0xFF01, writing to ${this.writeUuid}`
      + (this.#altChar ? ' (device also has 0xFF03)' : ''));
    return this.device;
  }

  // Linux/BlueZ often reports "Connection attempt failed." for a device that is
  // advertising fine (seen on a real datalogger after it joined Wi-Fi); retry like the app.
  async #gattConnect() {
    const { CONNECT_RETRIES: retries, CONNECT_RETRY_DELAY: delay } = DataloggerBle;
    for (let attempt = 1; ; attempt++) {
      try {
        return await this.device.gatt.connect();
      } catch (e) {
        if (attempt > retries) throw new Error(`${e.message} (gave up after ${attempt} attempts)`);
        this.#log('err', `${e.message}; retrying in ${delay / 1000} s (${attempt}/${retries})`);
        await sleep(delay);
      }
    }
  }

  // The device type is only in the advertisement, so listen briefly before connecting.
  // watchAdvertisements() is missing in some Chrome builds (behind a flag).
  async #readAdvertisement(timeout = 4000) {
    if (typeof this.device.watchAdvertisements !== 'function') {
      this.#log('info', 'Browser does not support watchAdvertisements(); device group unavailable');
      return null;
    }
    const abort = new AbortController();
    let seen = 0;
    let first = null;
    try {
      const got = new Promise((resolve) => {
        this.device.addEventListener('advertisementreceived', (e) => {
          seen++;
          first ??= e;
          const [entry] = e.manufacturerData;
          if (entry) resolve({ manufacturer: manufacturerString(entry[0], entry[1]), name: e.name ?? e.device.name ?? '' });
        }, { signal: abort.signal });
        setTimeout(() => resolve(null), timeout);
      });
      await this.device.watchAdvertisements({ signal: abort.signal });
      const adv = await got;
      if (adv) this.#log('info', `Advertisement: "${adv.manufacturer}" name "${adv.name}"`);
      else if (!seen) this.#log('info', `No advertisements received within ${timeout / 1000} s`);
      else {
        const keys = (m) => [...(m?.keys() ?? [])].map((k) => (typeof k === 'number' ? `0x${k.toString(16).padStart(4, '0')}` : k));
        this.#log('info', `${seen} advertisement(s), none with manufacturer data. First: name "${first.name ?? ''}", `
          + `RSSI ${first.rssi ?? '?'}, services [${(first.uuids ?? []).join(', ')}], `
          + `service data [${keys(first.serviceData).join(', ')}]`);
      }
      return adv;
    } catch (e) {
      this.#log('info', `Could not read advertisements: ${e.message}`);
      return null;
    } finally {
      abort.abort();
    }
  }

  get writeUuid() {
    return this.writeChar && this.writeChar === this.#altChar ? '0xFF03' : '0xFF01';
  }

  disconnect() {
    if (this.device?.gatt.connected) this.device.gatt.disconnect();
  }

  get connected() {
    return !!this.device?.gatt.connected;
  }

  /** Send one frame and resolve with the decoded reply. Requests are serialized. */
  request(frame, { label = '', timeout = 8000, retryDelay = 50, acceptHandshake = false } = {}) {
    const run = () => this.#send(frame, label, timeout, retryDelay, acceptHandshake);
    const p = this.#queue.then(run, run);
    this.#queue = p.catch(() => {});
    return p;
  }

  /** Resolves when the connect handshake has arrived, or after ms (400 ms fallback). */
  waitForHandshake(ms) {
    if (this.handshakeSeen) return Promise.resolve(true);
    return new Promise((resolve) => {
      const done = (v) => { clearTimeout(timer); this.removeEventListener('handshake', onShake); resolve(v); };
      const onShake = () => done(true);
      const timer = setTimeout(() => done(false), ms);
      this.addEventListener('handshake', onShake);
    });
  }

  async #send(frame, label, timeout, retryDelay, acceptHandshake) {
    this.#rx = new Uint8Array(0);
    const reply = new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending = null;
        reject(new Error(`Timed out waiting for reply${label ? ` to ${label}` : ''}`));
      }, timeout);
      this.#pending = {
        acceptHandshake,
        resolve: (v) => { clearTimeout(timer); resolve(v); },
        reject: (e) => { clearTimeout(timer); reject(e); },
      };
    });
    this.#log('tx', `${label}  ${toHex(frame)}`);
    try {
      await this.#write(frame, label, retryDelay);
    } catch (e) {
      this.#fail(e);
    }
    return reply;
  }

  // A failed GATT write is retried up to 3 attempts in total
  // (_bleOnSendFailRetry: 100 ms for the session key, 50 ms otherwise).
  async #write(frame, label, retryDelay, attempts = 3) {
    for (let attempt = 1; ; attempt++) {
      const c = this.writeChar;
      try {
        if (c.properties.write) await c.writeValueWithResponse(frame);
        else await c.writeValueWithoutResponse(frame);
        return;
      } catch (e) {
        if (isWriteRefused(e) && c === this.char && this.#altChar && this.#altChar !== c) {
          this.writeChar = this.#altChar;
          this.#log('info', `0xFF01 refused the write (${e.message}); switching to 0xFF03`);
          attempt--; // the switch itself does not use up an attempt
          continue;
        }
        if (attempt >= attempts) throw e;
        this.#log('err', `Write ${label} failed (${e.message}); retry ${attempt}/${attempts - 1} in ${retryDelay} ms`);
        await sleep(retryDelay);
      }
    }
  }

  async #onNotify(view) {
    const chunk = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
    const buf = new Uint8Array(this.#rx.length + chunk.length);
    buf.set(this.#rx);
    buf.set(chunk, this.#rx.length);
    this.#rx = buf;
    const len = frameLength(buf);
    if (len == null || buf.length < len) return; // wait for more fragments
    const frame = buf.slice(0, len);
    this.#rx = new Uint8Array(0);
    this.#log('rx', toHex(frame));
    // The handshake is not a reply, except that older firmware may answer the
    // session key with it (treated as "key set OK").
    if (isHandshake(frame) && !this.#pending?.acceptHandshake) {
      this.handshakeSeen = true;
      this.#log('info', 'Device handshake (connect ack) received');
      this.dispatchEvent(new Event('handshake'));
      return;
    }
    const pending = this.#pending;
    this.#pending = null;
    try {
      const decoded = await decodeFrame(frame);
      pending ? pending.resolve(decoded) : this.#log('info', 'Unsolicited frame ignored');
    } catch (e) {
      pending?.reject(e);
    }
  }

  #fail(err) {
    this.#pending?.reject(err);
    this.#pending = null;
  }

  #log(kind, text) {
    this.dispatchEvent(new CustomEvent('log', { detail: { kind, text } }));
  }
}
