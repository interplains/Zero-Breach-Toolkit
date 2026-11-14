// Zero Breach phone check - the sealed worker that runs the engine.
//
// The page downloads the runtime from this site, checks every file against
// files.json, and hands the bytes over. From then on this worker never needs
// the network: its own fetch() only answers from those bytes, and the
// server sends this file with a security policy that forbids every network
// connection (connect-src falls back to default-src 'none'). Before any of the
// person's files are opened the worker proves the seal by trying to reach this
// site and reporting whether the browser blocked it.
//
// The person's files are mounted read-only (WORKERFS): they are read where they
// are, in pieces, only when the engine asks for them, and never copied
// anywhere. Plaintext the engine decrypts lives in this worker's memory and is
// gone when the page closes or the check is restarted.

"use strict";

const realFetch = self.fetch.bind(self);
let runtime = null;      // Map: path ("runtime/x", "engine.zip") -> ArrayBuffer
let pyodide = null;
let driver = null;

const TYPES = { ".wasm": "application/wasm", ".mjs": "text/javascript", ".json": "application/json",
                ".zip": "application/zip", ".whl": "application/zip" };

function post(type, data) { self.postMessage(Object.assign({ type }, data || {})); }

function memoryFetch(input) {
  const raw = (typeof Request !== "undefined" && input instanceof Request) ? input.url : String(input);
  const url = new URL(raw, self.location.href);
  for (const [path, bytes] of runtime) {
    if (url.pathname.endsWith("/" + path)) {
      const ext = path.slice(path.lastIndexOf("."));
      return Promise.resolve(new Response(bytes.slice(0), {
        status: 200, headers: { "Content-Type": TYPES[ext] || "application/octet-stream" } }));
    }
  }
  return Promise.reject(new TypeError("the phone check does not use the network (" + url.pathname + ")"));
}

async function proveSeal() {
  // A real request to this same site. Under the worker's policy the browser
  // must refuse it before anything leaves the computer.
  try {
    await realFetch(new URL("seal-probe.txt?t=" + Date.now(), self.location.href), { cache: "no-store" });
    return false;
  } catch (e) {
    return true;
  }
}

function sealGlobals() {
  // Belt and braces next to the policy: remove every network API from scope.
  const refuse = () => { throw new TypeError("the phone check does not use the network"); };
  self.fetch = memoryFetch;
  for (const name of ["XMLHttpRequest", "WebSocket", "EventSource", "WebTransport"]) {
    try { Object.defineProperty(self, name, { value: undefined, configurable: false, writable: false }); } catch (e) {}
  }
  try { self.importScripts = refuse; } catch (e) {}
  try { if (self.navigator && self.navigator.sendBeacon) self.navigator.sendBeacon = () => false; } catch (e) {}
}

async function init(files) {
  runtime = new Map(Object.entries(files));
  self.fetch = memoryFetch;
  post("status", { text: "Starting the checking engine" });
  const { loadPyodide } = await import(new URL("runtime/pyodide.mjs", self.location.href).href);
  pyodide = await loadPyodide({
    indexURL: new URL("runtime/", self.location.href).href,
    stdout: () => {}, stderr: () => {},
    env: { HOME: "/home/pyodide", TMPDIR: "/tmp" },
  });
  post("status", { text: "Loading the backup decryption library" });
  await pyodide.loadPackage(["cryptography"], { messageCallback: () => {}, errorCallback: () => {} });
  post("status", { text: "Loading the indicator lists" });
  pyodide.unpackArchive(runtime.get("engine.zip"), "zip", { extractDir: "/zbt" });
  runtime.delete("engine.zip");
  pyodide.runPython("import sys\nif '/zbt' not in sys.path: sys.path.insert(0, '/zbt')");
  driver = pyodide.pyimport("zbt_web");
  const info = JSON.parse(driver.engine_info());
  const sealed = await proveSeal();
  sealGlobals();
  post("ready", { info, sealed });
}

function mount(entries) {
  const FS = pyodide.FS;
  try { FS.unmount("/evidence"); } catch (e) {}
  try { FS.rmdir("/evidence"); } catch (e) {}
  FS.mkdir("/evidence");
  const blobs = [];
  const seen = new Set();
  for (const { name, data } of entries) {
    const clean = String(name).split("/").filter((p) => p && p !== "." && p !== "..").join("/");
    if (!clean || seen.has(clean)) continue;
    seen.add(clean);
    blobs.push({ name: clean, data });
  }
  FS.mount(FS.filesystems.WORKERFS, { blobs }, "/evidence");
  return JSON.parse(driver.find_inputs());
}

function toHex(buffer) {
  return Array.from(new Uint8Array(buffer), (b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(text) {
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(text.substr(i * 2, 2), 16);
  return out;
}

// The encrypted backup's password derivation (PBKDF2, 10 million rounds on
// current iPhones) run with the browser's own Web Crypto, which is native code.
// The engine receives the results and would derive them itself otherwise.
async function deriveKeys(folder, password) {
  if (!password || !self.crypto || !crypto.subtle) return [];
  let steps;
  try { steps = JSON.parse(driver.keybag_steps(folder)); } catch (e) { return []; }
  const done = [];
  let secret = new TextEncoder().encode(password);
  try {
    for (const [digest, saltHex, rounds, length] of steps) {
      const hash = { sha256: "SHA-256", sha1: "SHA-1" }[digest];
      if (!hash) return done;
      const base = await crypto.subtle.importKey("raw", secret, "PBKDF2", false, ["deriveBits"]);
      const bits = await crypto.subtle.deriveBits(
        { name: "PBKDF2", hash, salt: fromHex(saltHex), iterations: rounds }, base, length * 8);
      done.push([digest, saltHex, rounds, length, toHex(bits)]);
      secret = new Uint8Array(bits);
    }
  } catch (e) {
    return done;   // the engine derives whatever is missing
  }
  return done;
}

async function run(folder, password, lang, encrypted) {
  const started = Date.now();
  const emit = (raw) => {
    let item = {};
    try { item = JSON.parse(raw); } catch (e) { item = { text: String(raw) }; }
    post("progress", { text: item.text, percent: item.percent, line: item.line,
                       seconds: Math.round((Date.now() - started) / 1000) });
  };
  let derived = [];
  if (encrypted && password) {
    post("progress", { text: "Unlocking the backup with your password" });
    derived = await deriveKeys(folder, password);
  }
  const result = driver.run_check(folder, password, lang, emit, JSON.stringify(derived));
  password = "";
  derived = null;
  return JSON.parse(result);
}

self.onmessage = async (event) => {
  const msg = event.data || {};
  try {
    if (msg.type === "init") {
      await init(msg.files);
    } else if (msg.type === "mount") {
      post("inputs", { inputs: mount(msg.entries) });
    } else if (msg.type === "run") {
      const result = await run(msg.folder, msg.password || "", msg.lang || "en", !!msg.encrypted);
      msg.password = "";
      post("result", { result });
    }
  } catch (e) {
    post("error", { text: String((e && e.message) || e).slice(0, 2000) });
  }
};
