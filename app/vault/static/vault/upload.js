// Drag & drop upload with per-file progress bars.
// Each file is sent as a RAW request body (not multipart) so the server can encrypt it
// on the fly. Client-side checks are a convenience only; the server re-validates everything.
(function () {
  var dz = document.getElementById("dropzone");
  if (!dz) return;
  var input = document.getElementById("file-input");
  var pick = document.getElementById("pick-files");
  var list = document.getElementById("upload-list");
  var MAX = Number(dz.dataset.max);
  var ALLOWED = dz.dataset.allowed.split(",");
  var queue = [], running = false, failures = 0, successes = 0;

  pick.addEventListener("click", function () { input.click(); });
  input.addEventListener("change", function () { add(input.files); input.value = ""; });
  ["dragenter", "dragover"].forEach(function (ev) {
    dz.addEventListener(ev, function (e) { e.preventDefault(); dz.dataset.active = "true"; });
  });
  ["dragleave", "drop"].forEach(function (ev) {
    dz.addEventListener(ev, function (e) { e.preventDefault(); dz.dataset.active = "false"; });
  });
  dz.addEventListener("drop", function (e) { add(e.dataTransfer.files); });

  function fmt(n) {
    var u = ["B", "KB", "MB", "GB"], i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return n.toFixed(i ? 1 : 0) + " " + u[i];
  }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;   // textContent: file names can't inject HTML
    return e;
  }

  function row(file) {
    var wrap = el("div", "border-b border-rule py-3");
    var top = el("div", "flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1");
    var name = el("span", "min-w-0 break-words font-medium", file.name);
    var status = el("span", "shrink-0 text-sm text-ink-2", "Waiting · " + fmt(file.size));
    top.appendChild(name); top.appendChild(status);
    var track = el("div", "mt-2 h-1 overflow-hidden rounded-full bg-rule");
    var bar = el("div", "h-full w-0 rounded-full bg-ok transition-[width] duration-150");
    track.appendChild(bar);
    wrap.appendChild(top); wrap.appendChild(track);
    list.appendChild(wrap);
    return {
      progress: function (p) { bar.style.width = p + "%"; status.textContent = "Uploading " + p + "% · " + fmt(file.size); },
      encrypting: function () { bar.style.width = "100%"; status.textContent = "Encrypting and storing…"; },
      done: function () { status.textContent = "Encrypted and stored"; status.className = "shrink-0 text-sm font-medium text-ok"; },
      fail: function (msg) { track.className = "hidden"; status.textContent = "Not uploaded: " + msg; status.className = "shrink-0 text-sm font-medium text-bad"; }
    };
  }

  function add(files) {
    Array.prototype.forEach.call(files, function (f) { queue.push({ file: f, ui: row(f) }); });
    if (!running) next();
  }

  function next() {
    var item = queue.shift();
    if (!item) {
      running = false;
      if (!failures && successes) { setTimeout(function () { location.reload(); }, 600); }
      else if (successes) {
        var b = el("button", "btn-quiet mt-3", "Refresh file list");
        b.addEventListener("click", function () { location.reload(); });
        list.appendChild(b);
      }
      return;
    }
    running = true;
    send(item.file, item.ui, function (ok) { ok ? successes++ : failures++; next(); });
  }

  function send(file, ui, cb) {
    var ext = (file.name.split(".").pop() || "").toLowerCase();
    if (ALLOWED.indexOf(ext) === -1) { ui.fail("." + ext + " files are not allowed"); return cb(false); }
    if (file.size > MAX) { ui.fail("larger than the " + fmt(MAX) + " limit"); return cb(false); }
    if (file.size === 0) { ui.fail("the file is empty"); return cb(false); }

    var xhr = new XMLHttpRequest();
    xhr.open("POST", dz.dataset.url);
    xhr.setRequestHeader("X-CSRFToken", dz.dataset.csrf);
    xhr.setRequestHeader("X-File-Name", encodeURIComponent(file.name));
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    xhr.upload.onprogress = function (e) {
      if (e.lengthComputable) {
        var p = Math.floor((e.loaded / e.total) * 100);
        p >= 100 ? ui.encrypting() : ui.progress(p);
      }
    };
    xhr.onload = function () {
      if (xhr.status === 201) { ui.done(); return cb(true); }
      var msg = "error " + xhr.status;
      try { msg = JSON.parse(xhr.responseText).error || msg; } catch (e) {}
      ui.fail(msg); cb(false);
    };
    xhr.onerror = function () { ui.fail("connection lost. Check your network and try again"); cb(false); };
    xhr.send(file);
  }
})();
