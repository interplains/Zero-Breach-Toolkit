// Zero Breach phone check - page controller.
//
// Downloads the runtime from this site once, checks every file's SHA-256
// against files.json, then hands the bytes to the sealed worker (worker.js),
// which runs the engine. This page itself only ever talks to this site, and
// only to load the checker; the person's files go to the worker, never to the
// network.
(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };
  var state = { device: "iphone", worker: null, runtime: null, ready: false, inputs: [],
                entries: null, result: null, info: null, running: false, timer: null };

  // Headline colours used by the desktop window (gui.py), mapped to page styles.
  var COLOUR_KIND = { "#c4161c": "found", "#1e7e34": "none", "#3c4858": "none_with_gaps", "#9a6700": "warn" };

  function show(id, on) { $(id).hidden = !on; }
  function setText(id, text) { $(id).textContent = text; }

  function fail(text) {
    state.running = false;
    show("progress", false);
    setText("error-text", text);
    show("error", true);
  }

  // ---- platform notes ------------------------------------------------------
  (function platform() {
    var ua = navigator.userAgent || "";
    var mobile = (navigator.userAgentData && navigator.userAgentData.mobile) ||
                 /Android|iPhone|iPad|iPod|Mobile/i.test(ua) ||
                 (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1);
    show("mobile-note", !!mobile);
    show("desktop-note", !mobile);
  })();

  // ---- loading and verifying the runtime -----------------------------------
  function hex(buffer) {
    var bytes = new Uint8Array(buffer), out = "";
    for (var i = 0; i < bytes.length; i++) out += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
    return out;
  }

  function fetchWithProgress(url, onBytes) {
    return fetch(url, { cache: "default", credentials: "omit" }).then(function (res) {
      if (!res.ok) throw new Error(url + ": HTTP " + res.status);
      if (!res.body || !res.body.getReader) return res.arrayBuffer().then(function (b) { onBytes(b.byteLength); return b; });
      var reader = res.body.getReader(), chunks = [], size = 0;
      function pump() {
        return reader.read().then(function (step) {
          if (step.done) {
            var out = new Uint8Array(size), at = 0;
            chunks.forEach(function (c) { out.set(c, at); at += c.length; });
            return out.buffer;
          }
          chunks.push(step.value); size += step.value.length; onBytes(step.value.length);
          return pump();
        });
      }
      return pump();
    });
  }

  function loadRuntime() {
    if (!window.crypto || !crypto.subtle || !window.Worker || !window.WebAssembly) {
      return Promise.reject(new Error("This browser cannot run the check (it needs WebAssembly, Web Workers and " +
        "Web Crypto over https). Use a current Chrome, Edge, Firefox or Safari, or the Zero Breach program."));
    }
    return fetch("files.json", { cache: "no-cache", credentials: "omit" }).then(function (res) {
      if (!res.ok) throw new Error("files.json: HTTP " + res.status);
      return res.json();
    }).then(function (manifest) {
      state.manifest = manifest;
      var total = manifest.files.reduce(function (n, f) { return n + f.bytes; }, 0), done = 0;
      var tick = function (n) {
        done += n;
        var pct = Math.min(100, Math.round(100 * done / total));
        $("loader-bar").style.width = pct + "%";
        setText("loader-pct", pct + "%");
      };
      var files = {};
      // Sequential keeps memory flat and the progress honest.
      return manifest.files.reduce(function (chain, f) {
        return chain.then(function () {
          return fetchWithProgress(f.path + "?v=" + f.sha256.slice(0, 12), tick).then(function (buffer) {
            if (buffer.byteLength !== f.bytes) throw new Error(f.path + " has the wrong size; reload the page");
            return crypto.subtle.digest("SHA-256", buffer).then(function (digest) {
              if (hex(digest) !== f.sha256) throw new Error(f.path + " does not match its published fingerprint; " +
                "the check will not run. Reload the page, or use the Zero Breach program.");
              files[f.path] = buffer;
            });
          });
        });
      }, Promise.resolve()).then(function () { return files; });
    });
  }

  function startWorker() {
    var worker = new Worker("worker.js?v=1", { type: "module" });
    state.worker = worker;
    state.ready = false;
    worker.onmessage = onWorker;
    worker.onerror = function (e) { fail("The checker stopped: " + (e.message || "worker error")); };
    // Copies, so a restart (Stop) can start a fresh worker without downloading again.
    var copy = {};
    Object.keys(state.runtime).forEach(function (k) { copy[k] = state.runtime[k].slice(0); });
    worker.postMessage({ type: "init", files: copy }, Object.keys(copy).map(function (k) { return copy[k]; }));
  }

  function onWorker(event) {
    var msg = event.data || {};
    if (msg.type === "status") {
      setText("loader-text", msg.text + "…");
    } else if (msg.type === "ready") {
      state.ready = true;
      state.info = msg.info;
      show("loader", false);
      sealStatus(msg.sealed);
      fillLanguages(msg.info.languages);
      setText("foot", "Zero Breach " + msg.info.version + " · " + msg.info.indicators.toLocaleString() +
        " built-in indicators" + (msg.info.kev ? " · exploited-vulnerability list " + msg.info.kev : "") +
        " · runs locally in WebAssembly (Pyodide " + state.manifest.pyodide + ")");
      if (state.entries) mount(state.entries);
      refreshStart();
    } else if (msg.type === "inputs") {
      onInputs(msg.inputs);
    } else if (msg.type === "progress") {
      if (msg.text) setText("progress-text", msg.text);
      if (typeof msg.percent === "number") $("progress-bar").style.width = msg.percent + "%";
      if (msg.line) setText("progress-line", msg.line);
    } else if (msg.type === "result") {
      onResult(msg.result);
    } else if (msg.type === "error") {
      fail(msg.text);
    }
  }

  function sealStatus(sealed) {
    var el = $("seal");
    el.setAttribute("data-state", sealed ? "sealed" : "open");
    setText("seal-text", sealed
      ? "Sealed: the checker tried to contact our server as a test, and your browser blocked it."
      : "Warning: your browser did not block the checker's test connection on this copy of the page. " +
        "The checker has no code that sends your files, but the extra lock is missing here.");
  }

  function fillLanguages(list) {
    var select = $("lang"), want = (navigator.language || "en").toLowerCase().split("-")[0];
    select.innerHTML = "";
    (list || [["en", "English"]]).forEach(function (pair) {
      var opt = document.createElement("option");
      opt.value = pair[0]; opt.textContent = pair[1];
      if (pair[0] === want) opt.selected = true;
      select.appendChild(opt);
    });
  }

  // ---- step 1: device ------------------------------------------------------
  ["pick-iphone", "pick-android"].forEach(function (id) {
    $(id).addEventListener("click", function () {
      state.device = $(id).getAttribute("data-device");
      $("pick-iphone").setAttribute("aria-selected", state.device === "iphone");
      $("pick-android").setAttribute("aria-selected", state.device === "android");
      show("guide-iphone", state.device === "iphone");
      show("guide-android", state.device === "android");
    });
  });

  // ---- step 3: the folder --------------------------------------------------
  function stripTop(paths) {
    // A picked folder "X" arrives as "X/Manifest.db": the engine sees X as the root.
    var first = null;
    for (var i = 0; i < paths.length; i++) {
      var top = paths[i].name.split("/")[0];
      if (first === null) first = top; else if (first !== top) return { top: "", entries: paths };
    }
    return { top: first || "", entries: paths.map(function (p) {
      return { name: p.name.slice((first || "").length + 1), data: p.data };
    }).filter(function (p) { return p.name; }) };
  }

  function picked(list, label) {
    if (!list.length) { setText("picked", "That folder is empty."); show("picked", true); return; }
    var split = stripTop(list);
    var bytes = 0;
    split.entries.forEach(function (e) { bytes += e.data.size || 0; });
    setText("picked", (label || split.top || "Folder") + ": " + split.entries.length.toLocaleString() +
      " files, " + (bytes / 1e9).toFixed(2) + " GB (read here, not uploaded)");
    show("picked", true);
    show("error", false);
    show("result", false);
    state.entries = split.entries;
    state.inputs = [];
    refreshStart();
    if (state.ready) mount(split.entries);
  }

  function mount(entries) {
    setText("start-note", "Opening the folder…");
    show("step-run", true);
    state.worker.postMessage({ type: "mount", entries: entries });
  }

  $("folder-input").addEventListener("change", function () {
    var files = this.files, list = [];
    for (var i = 0; i < files.length; i++) {
      list.push({ name: files[i].webkitRelativePath || files[i].name, data: files[i] });
    }
    picked(list);
    this.value = "";
  });

  var drop = $("drop");
  drop.addEventListener("dragover", function (e) { e.preventDefault(); drop.classList.add("over"); });
  drop.addEventListener("dragleave", function () { drop.classList.remove("over"); });
  drop.addEventListener("drop", function (e) {
    e.preventDefault();
    drop.classList.remove("over");
    var items = e.dataTransfer && e.dataTransfer.items;
    if (!items || !items.length || !items[0].webkitGetAsEntry) return;
    var roots = [];
    for (var i = 0; i < items.length; i++) { var en = items[i].webkitGetAsEntry(); if (en) roots.push(en); }
    var list = [], pending = 0;
    setText("picked", "Reading the folder…"); show("picked", true);
    function finish() { if (pending === 0) picked(list); }
    function walk(entry, prefix) {
      pending++;
      if (entry.isFile) {
        entry.file(function (f) { list.push({ name: prefix + f.name, data: f }); pending--; finish(); },
                   function () { pending--; finish(); });
      } else if (entry.isDirectory) {
        var reader = entry.createReader();
        var more = function () {
          reader.readEntries(function (batch) {
            if (!batch.length) { pending--; finish(); return; }
            batch.forEach(function (child) { walk(child, prefix + entry.name + "/"); });
            if (list.length % 5000 < batch.length) setText("picked", "Reading the folder… " + list.length.toLocaleString() + " files");
            more();
          }, function () { pending--; finish(); });
        };
        more();
      } else { pending--; finish(); }
    }
    roots.forEach(function (r) { walk(r, ""); });
  });

  // ---- step 4: what to check, password, start -------------------------------
  function onInputs(inputs) {
    state.inputs = inputs || [];
    var select = $("which-select");
    select.innerHTML = "";
    state.inputs.forEach(function (item, i) {
      var opt = document.createElement("option");
      opt.value = String(i);
      opt.textContent = item.label || (item.kind === "iphone" ? "iPhone backup" : "Android collection");
      select.appendChild(opt);
    });
    show("which", state.inputs.length > 1);
    var iphone = state.inputs.some(function (i) { return i.kind === "iphone"; });
    if (!state.inputs.length) {
      setText("start-note", "Nothing was found in that folder. Choose the backup folder itself.");
    } else if (!iphone && state.device === "iphone") {
      setText("start-note", "This does not look like an iPhone backup (no Manifest.db). If it is an Android " +
        "collection, that is fine: start the check.");
    } else {
      setText("start-note", "");
    }
    updatePassword();
    refreshStart();
  }

  function current() { return state.inputs[Number($("which-select").value || 0)] || state.inputs[0]; }

  function updatePassword() {
    var item = current();
    show("password-row", !!(item && item.encrypted));
  }
  $("which-select").addEventListener("change", updatePassword);

  function refreshStart() {
    $("start").disabled = !(state.ready && state.inputs.length && !state.running);
  }

  $("start").addEventListener("click", function () {
    var item = current();
    if (!item) return;
    var password = item.encrypted ? $("password").value : "";
    if (item.encrypted && !password) {
      setText("start-note", "This backup is encrypted: enter its backup password.");
      $("password").focus();
      return;
    }
    state.running = true;
    refreshStart();
    show("result", false); show("error", false); show("progress", true);
    setText("progress-text", item.encrypted ? "Unlocking the backup (this takes up to a minute)" : "Starting");
    setText("progress-line", "");
    $("progress-bar").style.width = "0%";
    var started = Date.now();
    clearInterval(state.timer);
    state.timer = setInterval(function () {
      var s = Math.round((Date.now() - started) / 1000);
      setText("progress-time", Math.floor(s / 60) + ":" + ("0" + (s % 60)).slice(-2));
    }, 1000);
    state.worker.postMessage({ type: "run", folder: item.path, password: password, lang: $("lang").value,
                               encrypted: !!item.encrypted });
    $("password").value = "";
    password = "";
  });

  $("stop").addEventListener("click", function () {
    // The engine runs without pauses, so stopping means ending the worker.
    // Its memory (and anything decrypted in it) goes with it.
    clearInterval(state.timer);
    state.worker.terminate();
    state.running = false;
    show("progress", false);
    setText("start-note", "Stopped. Nothing was kept. Restarting the checker…");
    show("loader", true);
    startWorker();
  });

  // ---- result --------------------------------------------------------------
  function onResult(result) {
    clearInterval(state.timer);
    state.running = false;
    state.result = result;
    refreshStart();
    show("progress", false);
    var verdict = $("verdict");
    verdict.setAttribute("data-kind", COLOUR_KIND[(result.colour || "").toLowerCase()] || result.kind);
    setText("verdict-title", result.title);
    setText("verdict-text", result.text);
    var list = $("next-steps");
    list.innerHTML = "";
    (result.next_steps || []).forEach(function (step) {
      var li = document.createElement("li");
      li.textContent = step;
      list.appendChild(li);
    });
    var labels = result.labels || {};
    Array.prototype.forEach.call(document.querySelectorAll("#result [data-label]"), function (el) {
      var key = el.getAttribute("data-label");
      el.textContent = labels[key] || key;
    });
    var leadList = $("leads");
    leadList.innerHTML = "";
    (result.leads || []).forEach(function (lead) {
      var li = document.createElement("li");
      var what = document.createElement("strong");
      what.textContent = lead.what;
      li.appendChild(what);
      if (lead.usual_reason) {
        var why = document.createElement("span");
        why.className = "small";
        why.textContent = " " + lead.usual_reason;
        li.appendChild(why);
      }
      leadList.appendChild(li);
    });
    show("leads-box", (result.leads || []).length > 0);
    setText("summary", result.summary);
    setText("report", result.report);
    $("result").setAttribute("dir", result.rtl ? "rtl" : "ltr");
    show("result", true);
    $("result").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function stamp() {
    var d = new Date(), p = function (n) { return ("0" + n).slice(-2); };
    return d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + "-" + p(d.getHours()) + p(d.getMinutes());
  }

  function save(name, text, type) {
    var url = URL.createObjectURL(new Blob([text], { type: type }));
    var a = document.createElement("a");
    a.href = url; a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
  }

  $("save-report").addEventListener("click", function () {
    if (state.result) save("zero-breach-phone-report-" + stamp() + ".txt", state.result.report, "text/plain;charset=utf-8");
  });
  $("save-json").addEventListener("click", function () {
    if (state.result) save("zero-breach-phone-report-" + stamp() + ".json",
      JSON.stringify(state.result.document, null, 2), "application/json");
  });
  $("save-share").addEventListener("click", function () {
    if (state.result) save("zero-breach-phone-sharing-summary-" + stamp() + ".json",
      JSON.stringify(state.result.share, null, 2), "application/json");
  });
  $("again").addEventListener("click", function () {
    show("result", false);
    state.entries = null; state.inputs = [];
    show("picked", false); show("step-run", false);
    refreshStart();
    $("step-pick").scrollIntoView({ behavior: "smooth" });
  });

  // ---- go -----------------------------------------------------------------
  loadRuntime().then(function (files) {
    state.runtime = files;
    setText("loader-text", "Starting the checking engine…");
    startWorker();
  }).catch(function (e) {
    show("loader", false);
    fail(String((e && e.message) || e));
  });
})();
