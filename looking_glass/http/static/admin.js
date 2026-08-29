function rawTextField(node, kind) {
  if (!node) return node;
  node.setAttribute("spellcheck", "false");
  if (kind === "password") return node;
  node.setAttribute("autocorrect", "off");
  node.setAttribute("autocapitalize", "off");
  var ac = String(node.getAttribute("autocomplete") || "").toLowerCase();
  if (ac !== "username" && ac !== "current-password" && ac !== "new-password" && ac !== "one-time-code") {
    node.setAttribute("autocomplete", "off");
  }
  return node;
}

(function () {
    const logsBtn = document.getElementById("status-logs");
    if (!logsBtn) return;

    let pop = null;
    let inner = null;
    let z = 120;
    let tab = "overview";
    let loginFilter = "all";
    let challengeFilter = "all";
    const sortState = {};
    const WIN_ID = "logs";

    function t(id, fallback) {
      const text = window.t ? window.t(id) : "";
      if (text && text !== id) return text;
      return fallback || id;
    }

    function raise(node) {
      if (window.lookingGlassWindows) {
        window.lookingGlassWindows.raise(node);
        return;
      }
      z += 1;
      node.style.zIndex = String(z);
    }

    function closePop() {
      if (window.lookingGlassWindows) window.lookingGlassWindows.detach(WIN_ID);
      if (pop) pop.remove();
      pop = null;
      inner = null;
    }

    function makeDraggable(node) {
      if (window.lookingGlassWindows) return;
      const bar = node.querySelector(".inspect-pop-bar");
      if (!bar) return;
      let startX = 0, startY = 0, origX = 0, origY = 0;
      bar.addEventListener("pointerdown", (event) => {
        if (event.target.closest("button, a, input, select, textarea, label, .inspect-pop-actions")) return;
        if (event.button != null && event.button !== 0) return;
        event.preventDefault();
        raise(node);
        bar.setPointerCapture(event.pointerId);
        startX = event.clientX;
        startY = event.clientY;
        const rect = node.getBoundingClientRect();
        origX = rect.left + window.scrollX;
        origY = rect.top + window.scrollY;
      });
      bar.addEventListener("pointermove", (event) => {
        if (!bar.hasPointerCapture(event.pointerId)) return;
        node.style.left = Math.max(8, origX + event.clientX - startX) + "px";
        node.style.top = Math.max(8, origY + event.clientY - startY) + "px";
      });
    }

    function lockPopSize(node, opts) {
      const rect = node.getBoundingClientRect();
      if ((!opts || opts.width !== false) && rect.width) node.style.width = rect.width + "px";
      if ((!opts || opts.height !== false) && rect.height) node.style.height = rect.height + "px";
    }

    async function sizeLogPopToAccess() {
      if (!pop) return;
      if (window.lookingGlassWindows && window.lookingGlassWindows.fit) window.lookingGlassWindows.fit(pop);
    }

    function el(tag, cls, text) {
      const node = document.createElement(tag);
      if (cls) node.className = cls;
      if (text != null) node.textContent = text;
      return node;
    }

    function chartSvg(series, title) {
      const w = 440, h = 118;
      const pad = { l: 36, r: 14, t: 18, b: 32 };
      const rows = (Array.isArray(series) ? series : []).slice().sort((a, b) => Number(a.t) - Number(b.t));
      const wrap = el("div", "log-chart");
      if (!rows.length) {
        wrap.append(el("p", "log-chart-title", title));
        wrap.append(el("p", "muted", t("gui.logs.empty", "no data")));
        return wrap;
      }
      const hits = rows.map((r) => Number(r.hits) || 0);
      const errors = rows.map((r) => Number(r.errors) || 0);
      const max = Math.max(1, ...hits, ...errors);
      const peakHits = Math.max(0, ...hits);
      const lastHits = hits.length ? hits[hits.length - 1] : 0;
      const innerW = w - pad.l - pad.r;
      const innerH = h - pad.t - pad.b;
      const t0 = Number(rows[0].t) || 0;
      const t1 = Number(rows[rows.length - 1].t) || t0;
      const span = t1 > t0 ? t1 - t0 : 1;
      const tickKind = span <= 36 * 3600 ? "clock" : "datehour";
      wrap.append(el("p", "log-chart-title", title + " · " + formatTs(t0, tickKind) + " → " + formatTs(t1, tickKind)));
      function xy(t, val) {
        const x = pad.l + (t1 > t0 ? ((Number(t) - t0) / span) * innerW : innerW / 2);
        const y = pad.t + (1 - val / max) * innerH;
        return [x.toFixed(1), y.toFixed(1)];
      }
      function area(values, color) {
        const base0 = xy(rows[0].t, 0);
        let d = "M " + base0[0] + " " + base0[1];
        values.forEach((v, i) => {
          const p = xy(rows[i].t, v);
          d += " L " + p[0] + " " + p[1];
        });
        const last = xy(rows[rows.length - 1].t, 0);
        d += " L " + last[0] + " " + last[1] + " Z";
        return '<path d="' + d + '" fill="' + color + '" fill-opacity="0.38" stroke="' + color + '" stroke-width="1.2"/>';
      }
      const grid = [];
      for (let g = 0; g <= 4; g++) {
        const y = pad.t + (g / 4) * innerH;
        grid.push('<line x1="' + pad.l + '" x2="' + (w - pad.r) + '" y1="' + y + '" y2="' + y + '" stroke="currentColor" stroke-opacity="0.12"/>');
      }
      const wantTicks = rows.length === 1
        ? [0]
        : [0, Math.floor((rows.length - 1) / 2), rows.length - 1];
      const seenTick = {};
      const tickIdx = [];
      wantTicks.forEach((i) => {
        const stamp = Number(rows[i].t);
        if (seenTick[stamp]) return;
        seenTick[stamp] = 1;
        tickIdx.push(i);
      });
      const ticks = tickIdx.map((i, n) => {
        const anchor = n === 0 ? "start" : n === tickIdx.length - 1 ? "end" : "middle";
        const p = xy(rows[i].t, 0);
        return (
          '<text class="log-chart-tick" x="' + p[0] + '" y="' + (h - 6) +
          '" text-anchor="' + anchor + '" fill="currentColor" font-size="9" opacity="0.7">' +
          formatTs(rows[i].t, tickKind) + "</text>"
        );
      });
      const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      svg.setAttribute("viewBox", "0 0 " + w + " " + h);
      svg.setAttribute("class", "log-chart-svg");
      svg.innerHTML =
        grid.join("") +
        area(hits, "var(--ok, #8ee29a)") +
        area(errors, "var(--bad, #ff8d8d)") +
        '<text x="' + pad.l + '" y="12" fill="currentColor" font-size="10" opacity="0.7">' + max + "</text>" +
        ticks.join("");
      wrap.append(svg);
      const legend = el("p", "log-chart-legend");
      legend.innerHTML =
        '<span class="log-swatch ok"></span> ' + t("gui.logs.hits", "hits") +
        ' <span class="log-swatch bad"></span> ' + t("gui.logs.errors", "errors") +
        " · " + t("gui.logs.peak", "peak") + " " + peakHits +
        " · " + t("gui.logs.last", "last") + " " + lastHits;
      wrap.append(legend);
      return wrap;
    }

    function sparkline(series) {
      const w = 120, h = 24;
      const rows = (Array.isArray(series) ? series : []).slice().sort((a, b) => Number(a.t) - Number(b.t));
      const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      svg.setAttribute("viewBox", "0 0 " + w + " " + h);
      if (!rows.length) return svg;
      const hits = rows.map((r) => Number(r.hits) || 0);
      const max = Math.max(1, ...hits);
      const t0 = Number(rows[0].t) || 0;
      const t1 = Number(rows[rows.length - 1].t) || t0;
      const span = t1 > t0 ? t1 - t0 : 1;
      const tickKind = span <= 36 * 3600 ? "clock" : "datehour";
      svg.setAttribute("title", formatTs(t0, tickKind) + " → " + formatTs(t1, tickKind));
      let d = "";
      rows.forEach((row, i) => {
        const x = t1 > t0 ? ((Number(row.t) - t0) / span) * w : w / 2;
        const y = h - (hits[i] / max) * (h - 2) - 1;
        d += (i ? " L " : "M ") + x.toFixed(1) + " " + y.toFixed(1);
      });
      svg.innerHTML = '<path d="' + d + '" fill="none" stroke="var(--ok, #8ee29a)" stroke-width="1.2"/>';
      return svg;
    }

    function formatTs(val, kind) {
      if (val == null || val === "") return "—";
      const n = Number(val);
      const d = Number.isFinite(n) && n > 1000000000 && n < 10000000000000
        ? new Date(n > 1e12 ? n : n * 1000)
        : new Date(val);
      if (isNaN(d.getTime())) return String(val);
      const iso = d.toISOString().replace("T", " ").slice(0, 19);
      if (kind === "clock") return iso.slice(11, 16);
      if (kind === "datehour") return iso.slice(0, 16);
      return iso;
    }

    function encodePath(value) {
      return encodeURIComponent(String(value)).replace(/%3A/gi, ":");
    }

    const SKIP_KINDS = {
      other: 1, login: 1, logout: 1, docs: 1, cache: 1, history: 1,
      serve: 1, logs: 1, index: 1, status: 1,
    };
    const HOST_KINDS = {
      dns: 1, dnstrace: 1, dnssec: 1, apex: 1, rdap: 1, whois: 1, reputation: 1,
      tls: 1, http: 1, mail: 1, ptr: 1, ping: 1, traceroute: 1, mtr: 1,
      tcptraceroute: 1, tcp: 1, pmtu: 1,
    };
    const FILE_EXT = /\.(ico|png|jpe?g|gif|webp|svg|css|js|mjs|map|txt|html?|xml|json|woff2?|ttf|eot)$/i;

    function looksLikeIp(text) {
      const raw = String(text || "").trim();
      if (!raw) return false;
      if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(raw)) return true;
      return raw.indexOf(":") >= 0 && /^[0-9a-fA-F:.]+$/.test(raw);
    }

    function looksLikeHost(text) {
      const raw = String(text || "").trim().replace(/\.$/, "");
      if (!raw || /\s/.test(raw) || looksLikeIp(raw) || FILE_EXT.test(raw)) return false;
      return /^(?=.{1,253}$)(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z]{2,63}$/.test(raw);
    }

    function classifyInspect(text, row, key) {
      const raw = String(text || "").trim();
      if (!raw) return null;
      const kind = String(row && row.kind || "");
      if (/^AS\d+$/i.test(raw) || (kind === "asn" && /^\d+$/.test(raw))) {
        return { type: "asn", value: String(raw).replace(/^AS/i, ""), href: "/AS" + String(raw).replace(/^AS/i, "") };
      }
      if (looksLikeIp(raw)) {
        return { type: "ip", value: raw, href: "/" + encodePath(raw) };
      }
      if (FILE_EXT.test(raw) || (SKIP_KINDS[kind] && key !== "peer")) return null;
      if (looksLikeHost(raw) && (HOST_KINDS[kind] || key === "query" || key === "value")) {
        const host = raw.replace(/\.$/, "");
        return { type: "domain", value: host, href: "/" + encodePath(host) };
      }
      return null;
    }

    function inspectAnchor(target, label) {
      if (target.type === "ip") {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "wall-value";
        btn.textContent = label;
        btn.addEventListener("click", (event) => {
          event.preventDefault();
          event.stopPropagation();
          if (typeof window.openWallMenu === "function") {
            window.openWallMenu("ip", target.value, btn);
          } else if (typeof window.openInspect === "function") {
            window.openInspect("ip", target.value, btn);
          }
        });
        return btn;
      }
      const a = document.createElement("a");
      a.textContent = label;
      a.href = target.href;
      if (target.type === "asn") a.setAttribute("data-asn", target.value);
      else a.setAttribute("data-domain", target.value);
      return a;
    }

    function intelCell(intel, row) {
      const wrap = el("span", "log-intel");
      const peer = String(row && row.peer || "").trim();
      if (looksLikeIp(peer)) {
        wrap.append(inspectAnchor(
          { type: "ip", value: peer, href: "/" + encodePath(peer) },
          peer
        ));
      }
      if (intel && typeof intel === "object") {
        if (intel.flag_url) {
          const img = document.createElement("img");
          img.className = "looking-glass-flag";
          img.src = intel.flag_url;
          img.alt = intel.country || "";
          wrap.append(img);
        } else if (intel.flag) {
          wrap.append(el("span", "", intel.flag));
        }
        if (intel.asn != null && intel.asn !== false) {
          wrap.append(inspectAnchor(
            { type: "asn", value: String(intel.asn), href: "/AS" + intel.asn },
            "AS" + intel.asn + (intel.org_name ? " " + intel.org_name : "")
          ));
        } else if (intel.country) {
          const a = document.createElement("a");
          a.href = "/" + encodePath(intel.country);
          a.textContent = intel.country_name || intel.country;
          wrap.append(a);
        }
      }
      if (!wrap.childNodes.length) wrap.textContent = "—";
      return wrap;
    }

    function valueCell(row, key, val) {
      if (key === "intel") return intelCell(row.intel, row);
      if (key === "ts") return document.createTextNode(formatTs(val));
      if (key === "ok") return document.createTextNode(row.ok ? "ok" : "fail");
      if (key === "path") return document.createTextNode(String(val));
      if (val == null || val === "") return document.createTextNode("—");
      if (key === "query" || key === "peer" || key === "value") {
        const target = classifyInspect(val, row, key);
        if (target) return inspectAnchor(target, String(val));
      }
      return document.createTextNode(String(val));
    }

    function uniqueCount(rows, key) {
      const set = new Set();
      (rows || []).forEach((row) => {
        const val = row[key];
        if (val == null || val === "") return;
        set.add(String(val));
      });
      return set.size;
    }

    function countBy(rows, fn) {
      const map = {};
      (rows || []).forEach((row) => {
        const key = fn(row);
        if (!key) return;
        map[key] = (map[key] || 0) + 1;
      });
      return map;
    }

    function avgMs(rows) {
      let sum = 0;
      let n = 0;
      (rows || []).forEach((row) => {
        const val = Number(row.ms);
        if (!Number.isFinite(val)) return;
        sum += val;
        n += 1;
      });
      return n ? sum / n : null;
    }

    function statusBucket(status) {
      const n = Number(status);
      if (!Number.isFinite(n)) return "";
      if (n >= 200 && n < 300) return "2xx";
      if (n >= 300 && n < 400) return "3xx";
      if (n >= 400 && n < 500) return "4xx";
      if (n >= 500) return "5xx";
      return "";
    }

    function sumSeries(map) {
      let hits = 0;
      let errors = 0;
      Object.keys(map || {}).forEach((page) => {
        (map[page] || []).forEach((row) => {
          hits += Number(row.hits) || 0;
          errors += Number(row.errors) || 0;
        });
      });
      return { hits: hits, errors: errors };
    }

    function logChip(strong, label, cls) {
      const node = el("span", "log-stat" + (cls ? " " + cls : ""));
      node.append(el("strong", "", String(strong)));
      if (label) node.append(document.createTextNode(" " + label));
      return node;
    }

    function logSummary(kind, rows, extra) {
      const wrap = el("div", "log-summary");
      const list = rows || [];
      if (kind === "overview" && extra) {
        wrap.append(logChip(extra.hits || 0, t("gui.logs.day", "day") + " " + t("gui.logs.hits", "hits")));
        wrap.append(logChip(extra.errors || 0, t("gui.logs.day", "day") + " " + t("gui.logs.errors", "errors"), extra.errors ? "bad" : ""));
        wrap.append(logChip(extra.weekHits || 0, t("gui.logs.week", "week") + " " + t("gui.logs.hits", "hits")));
        wrap.append(logChip(extra.weekErrors || 0, t("gui.logs.week", "week") + " " + t("gui.logs.errors", "errors"), extra.weekErrors ? "bad" : ""));
        wrap.append(logChip(extra.pages || 0, t("gui.logs.pages", "pages")));
        return wrap;
      }
      wrap.append(logChip(list.length, t("gui.logs.rows", "rows")));
      if (!list.length) return wrap;
      if (kind === "access" || kind === "error" || kind === "login" || kind === "challenge") {
        wrap.append(logChip(uniqueCount(list, "peer"), t("gui.logs.visitors", "visitors")));
      }
      if (kind === "access") {
        const buckets = countBy(list, (row) => statusBucket(row.status));
        ["2xx", "3xx", "4xx", "5xx"].forEach((code) => {
          if (!buckets[code]) return;
          wrap.append(logChip(buckets[code], code, code === "2xx" ? "ok" : (code === "4xx" || code === "5xx" ? "bad" : "")));
        });
        wrap.append(logChip(uniqueCount(list, "kind"), t("gui.logs.kinds", "kinds")));
        const avg = avgMs(list);
        if (avg != null) wrap.append(logChip(avg.toFixed(1), t("gui.logs.avg_ms", "avg ms")));
      }
      if (kind === "error") {
        wrap.append(logChip(uniqueCount(list, "path"), t("gui.logs.paths", "paths")));
        wrap.append(logChip(uniqueCount(list, "kind"), t("gui.logs.kinds", "kinds")));
      }
      if (kind === "login") {
        const ok = list.filter((row) => row.ok).length;
        const fail = list.length - ok;
        wrap.append(logChip(ok, t("gui.logs.ok", "successful"), "ok"));
        wrap.append(logChip(fail, t("gui.logs.fail", "unsuccessful"), fail ? "bad" : ""));
        wrap.append(logChip(uniqueCount(list, "user"), t("gui.logs.users", "users")));
      }
      if (kind === "lookup") {
        wrap.append(logChip(uniqueCount(list, "query"), t("gui.logs.queries", "queries")));
        wrap.append(logChip(uniqueCount(list, "kind"), t("gui.logs.kinds", "kinds")));
        const buckets = countBy(list, (row) => statusBucket(row.status));
        ["2xx", "4xx", "5xx"].forEach((code) => {
          if (!buckets[code]) return;
          wrap.append(logChip(buckets[code], code, code === "2xx" ? "ok" : "bad"));
        });
        const avg = avgMs(list);
        if (avg != null) wrap.append(logChip(avg.toFixed(1), t("gui.logs.avg_ms", "avg ms")));
      }
      if (kind === "serve-err") {
        wrap.append(logChip(uniqueCount(list, "logger"), t("gui.logs.loggers", "loggers")));
        const levels = countBy(list, (row) => String(row.level || "").toLowerCase());
        Object.keys(levels).sort().forEach((level) => {
          wrap.append(logChip(levels[level], level, level === "error" || level === "critical" ? "bad" : ""));
        });
      }
      if (kind === "wall") {
        wrap.append(logChip(uniqueCount(list, "event"), t("gui.logs.events", "events")));
        wrap.append(logChip(uniqueCount(list, "kind"), t("gui.logs.kinds", "kinds")));
        wrap.append(logChip(uniqueCount(list, "value"), t("gui.logs.values", "values")));
      }
      if (kind === "challenge") {
        const pass = list.filter((row) => row.event === "solved").length;
        const fail = list.filter((row) => row.event === "failed").length;
        wrap.append(logChip(pass, t("gui.wall.solved", "solved"), "ok"));
        wrap.append(logChip(fail, t("gui.wall.failed", "failed"), fail ? "bad" : ""));
      }
      if (kind === "build") {
        wrap.append(logChip(uniqueCount(list, "dataset"), t("gui.logs.datasets", "datasets")));
        wrap.append(logChip(uniqueCount(list, "event"), t("gui.logs.events", "events")));
      }
      return wrap;
    }

    function defaultSort(tabName) {
      const cur = sortState[tabName];
      if (cur && cur.key) return cur;
      return { key: "ts", dir: "desc" };
    }

    function sortValue(row, key) {
      if (key === "intel") {
        const intel = row.intel && typeof row.intel === "object" ? row.intel : {};
        const parts = [];
        if (intel.asn != null && intel.asn !== false) parts.push("AS" + intel.asn);
        if (intel.org_name) parts.push(intel.org_name);
        if (intel.country_name) parts.push(intel.country_name);
        else if (intel.country) parts.push(intel.country);
        return parts.join(" ").toLowerCase();
      }
      if (key === "ok") return row.ok ? 1 : 0;
      const val = row[key];
      if (val == null || val === "") return null;
      if (key === "ts" || key === "ms" || key === "status") {
        const n = Number(val);
        return Number.isFinite(n) ? n : String(val).toLowerCase();
      }
      if (typeof val === "number") return val;
      return String(val).toLowerCase();
    }

    function sortLogRows(rows, key, dir) {
      const sign = dir === "asc" ? 1 : -1;
      return (rows || []).slice().sort((a, b) => {
        const va = sortValue(a, key);
        const vb = sortValue(b, key);
        const aEmpty = va == null || va === "";
        const bEmpty = vb == null || vb === "";
        if (aEmpty && bEmpty) return ((Number(a.ts) || 0) - (Number(b.ts) || 0)) * sign;
        if (aEmpty) return 1;
        if (bEmpty) return -1;
        let cmp = 0;
        if (typeof va === "number" && typeof vb === "number") cmp = va - vb;
        else cmp = String(va).localeCompare(String(vb), undefined, { numeric: true, sensitivity: "base" });
        if (cmp === 0 && key !== "ts") cmp = (Number(a.ts) || 0) - (Number(b.ts) || 0);
        return cmp * sign;
      });
    }

    function tableFromRows(rows, columns, tabName) {
      if (!rows || !rows.length) return el("p", "muted", t("gui.logs.empty", "no data"));
      const sortTab = tabName || tab;
      const sort = defaultSort(sortTab);
      const sorted = sortLogRows(rows, sort.key, sort.dir);
      const table = el("table", "log-table");
      const head = document.createElement("thead");
      const hr = document.createElement("tr");
      columns.forEach((col) => {
        const th = document.createElement("th");
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "log-th-sort";
        btn.textContent = col.label;
        btn.title = t("gui.logs.sort", "sort");
        if (sort.key === col.key) {
          th.className = "sort-" + sort.dir;
          btn.setAttribute("aria-sort", sort.dir === "asc" ? "ascending" : "descending");
          btn.append(el("span", "sort-ind", sort.dir === "asc" ? "▲" : "▼"));
        } else {
          btn.setAttribute("aria-sort", "none");
        }
        btn.addEventListener("click", () => {
          const cur = defaultSort(sortTab);
          const dir = cur.key === col.key && cur.dir === "desc" ? "asc" : "desc";
          sortState[sortTab] = { key: col.key, dir: dir };
          const next = tableFromRows(rows, columns, sortTab);
          table.replaceWith(next);
        });
        th.append(btn);
        hr.append(th);
      });
      head.append(hr);
      const body = document.createElement("tbody");
      sorted.forEach((row) => {
        const tr = document.createElement("tr");
        columns.forEach((col) => {
          const td = el("td", col.key === "ok" ? (row.ok ? "ok" : "bad") : "");
          td.append(valueCell(row, col.key, row[col.key]));
          tr.append(td);
        });
        body.append(tr);
      });
      table.append(head, body);
      return table;
    }

    const TABS = [
      ["overview", "gui.logs.overview", "overview"],
      ["access", "gui.logs.access", "access"],
      ["error", "gui.logs.error", "error"],
      ["login", "gui.logs.login", "login"],
      ["lookup", "gui.logs.lookup", "lookup"],
      ["serve-err", "gui.logs.serve_err", "serve err"],
      ["wall", "gui.logs.wall", "wall"],
      ["challenge", "gui.logs.challenge", "challenge"],
      ["build", "gui.logs.build", "build"],
      ["acme", "gui.logs.acme", "acme"],
      ["https-out", "gui.logs.https_out", "https out"],
      ["https-err", "gui.logs.https_err", "https err"],
    ];

    const COLUMNS = {
      access: [
        { key: "ts", label: "time" },
        { key: "peer", label: "visitor" },
        { key: "method", label: "method" },
        { key: "status", label: "status" },
        { key: "path", label: "path" },
        { key: "kind", label: "kind" },
        { key: "query", label: "query" },
        { key: "user", label: "user" },
        { key: "ms", label: "ms" },
        { key: "intel", label: "intel" },
      ],
      error: [
        { key: "ts", label: "time" },
        { key: "peer", label: "visitor" },
        { key: "status", label: "status" },
        { key: "path", label: "path" },
        { key: "kind", label: "kind" },
        { key: "query", label: "query" },
        { key: "error", label: "error" },
        { key: "intel", label: "intel" },
      ],
      login: [
        { key: "ts", label: "time" },
        { key: "peer", label: "visitor" },
        { key: "ok", label: "result" },
        { key: "user", label: "user" },
        { key: "reason", label: "reason" },
        { key: "intel", label: "intel" },
      ],
      lookup: [
        { key: "ts", label: "time" },
        { key: "status", label: "status" },
        { key: "ms", label: "ms" },
        { key: "kind", label: "kind" },
        { key: "query", label: "query" },
        { key: "intel", label: "intel" },
      ],
      "serve-err": [
        { key: "ts", label: "time" },
        { key: "level", label: "level" },
        { key: "logger", label: "logger" },
        { key: "message", label: "message" },
      ],
      wall: [
        { key: "ts", label: "time" },
        { key: "event", label: "event" },
        { key: "kind", label: "kind" },
        { key: "value", label: "value" },
        { key: "note", label: t("gui.wall.note", "note") },
        { key: "intel", label: "intel" },
      ],
      challenge: [
        { key: "ts", label: "time" },
        { key: "peer", label: "visitor" },
        { key: "event", label: "event" },
        { key: "reason", label: "reason" },
        { key: "intel", label: "intel" },
      ],
      build: [
        { key: "ts", label: "time" },
        { key: "event", label: "event" },
        { key: "dataset", label: "dataset" },
        { key: "message", label: "message" },
      ],
      acme: [
        { key: "message", label: "message" },
      ],
      "https-out": [
        { key: "message", label: "message" },
      ],
      "https-err": [
        { key: "message", label: "message" },
      ],
    };

    async function fetchJson(url) {
      const res = await fetch(url, {
        cache: "no-store",
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.ok === false) throw new Error(data.error || "logs");
      return data;
    }

    function paint(node) {
      if (!inner) return;
      inner.replaceChildren(node);
      if (pop) pop.classList.remove("loading");
      if (pop && window.lookingGlassWindows && window.lookingGlassWindows.fit) window.lookingGlassWindows.fit(pop);
    }

    async function loadTab() {
      if (!inner) return;
      inner.textContent = t("gui.cache.loading", "Loading…");
      if (pop) pop.classList.add("loading");
      try {
        if (tab === "overview") {
          const data = await fetchJson("/logs/stats");
          const box = el("div", "log-overview");
          const day = data.day || {};
          const week = data.week || {};
          const pages = Object.keys(data.totals || day).sort();
          const daySum = sumSeries(day);
          const weekSum = sumSeries(week);
          function merge(map) {
            const byT = {};
            Object.keys(map || {}).forEach((page) => {
              (map[page] || []).forEach((row) => {
                const t = Number(row.t);
                if (!Number.isFinite(t)) return;
                const dest = byT[t] || (byT[t] = { t: t, hits: 0, errors: 0 });
                dest.hits += Number(row.hits) || 0;
                dest.errors += Number(row.errors) || 0;
              });
            });
            return Object.keys(byT).sort((a, b) => Number(a) - Number(b)).map((k) => byT[k]);
          }
          box.append(logSummary("overview", [], {
            hits: daySum.hits,
            errors: daySum.errors,
            weekHits: weekSum.hits,
            weekErrors: weekSum.errors,
            pages: pages.length,
          }));
          const charts = el("div", "log-charts");
          charts.append(chartSvg(merge(day), t("gui.logs.day", "day") + " · last 24h"));
          charts.append(chartSvg(merge(week), t("gui.logs.week", "week") + " · last 7d"));
          box.append(charts);
          if (pages.length) {
            const sparks = el("div", "log-sparks");
            pages.forEach((page) => {
              const line = el("div", "log-spark");
              const hits = (day[page] || []).reduce((sum, row) => sum + (Number(row.hits) || 0), 0);
              line.append(el("span", "log-spark-title", page));
              line.append(sparkline(day[page] || []));
              line.append(el("span", "muted", String(hits)));
              sparks.append(line);
            });
            box.append(sparks);
          }
          paint(box);
          return;
        }
        let url = "/logs?kind=" + encodeURIComponent(tab) + "&limit=200";
        if (tab === "login" && loginFilter === "ok") url += "&ok=true";
        if (tab === "login" && loginFilter === "fail") url += "&ok=false";
        if (tab === "challenge" && challengeFilter === "solved") url += "&ok=true";
        if (tab === "challenge" && challengeFilter === "failed") url += "&ok=false";
        const data = await fetchJson(url);
        const wrap = el("div", "log-pane");
        if (tab === "login") {
          const filters = el("div", "log-filters");
          [
            ["all", t("gui.logs.all", "all")],
            ["ok", t("gui.logs.ok", "successful")],
            ["fail", t("gui.logs.fail", "unsuccessful")],
          ].forEach(([id, label]) => {
            const btn = el("button", "log-filter" + (loginFilter === id ? " on" : ""), label);
            btn.type = "button";
            btn.dataset.filter = id;
            btn.addEventListener("click", () => {
              loginFilter = id;
              loadTab();
            });
            filters.append(btn);
          });
          wrap.append(filters);
        }
        if (tab === "challenge") {
          const filters = el("div", "log-filters");
          [
            ["all", t("gui.logs.all", "all")],
            ["solved", t("gui.wall.solved", "solved")],
            ["failed", t("gui.wall.failed", "failed")],
          ].forEach(([id, label]) => {
            const btn = el("button", "log-filter" + (challengeFilter === id ? " on" : ""), label);
            btn.type = "button";
            btn.dataset.filter = id;
            btn.addEventListener("click", () => {
              challengeFilter = id;
              loadTab();
            });
            filters.append(btn);
          });
          wrap.append(filters);
        }
        wrap.append(logSummary(tab, data.rows || []));
        wrap.append(tableFromRows(data.rows || [], COLUMNS[tab] || COLUMNS.access, tab));
        paint(wrap);
      } catch (err) {
        paint(el("p", "muted", String(err.message || err)));
      }
    }

    function openLogs(anchor) {
      if (pop && window.lookingGlassWindows && window.lookingGlassWindows.front(WIN_ID)) {
        loadTab();
        return;
      }
      if (pop && !window.lookingGlassWindows && document.body.contains(pop)) {
        raise(pop);
        loadTab();
        return;
      }
      if (pop) {
        try { pop.remove(); } catch (err) {}
        pop = null;
        inner = null;
      }
      pop = el("div", "asn-pop inspect-pop log-pop loading");
      pop.setAttribute("role", "dialog");
      const bar = el("div", "inspect-pop-bar");
      bar.append(el("strong", "inspect-pop-title", t("status.logs", "logs")));
      const close = el("button", "inspect-pop-close", "×");
      close.type = "button";
      close.setAttribute("aria-label", t("gui.close", "Close"));
      close.addEventListener("click", (event) => {
        event.preventDefault();
        closePop();
      });
      bar.append(close);
      const body = el("div", "inspect-pop-body");
      const nav = el("div", "log-tabs");
      TABS.forEach(([id, key, fallback]) => {
        const btn = el("button", "log-tab" + (tab === id ? " on" : ""), t(key, fallback));
        btn.type = "button";
        btn.dataset.tab = id;
        btn.addEventListener("click", () => {
          tab = id;
          nav.querySelectorAll(".log-tab").forEach((n) => n.classList.remove("on"));
          btn.classList.add("on");
          loadTab();
        });
        nav.append(btn);
      });
      inner = el("div", "log-inner");
      inner.textContent = t("gui.cache.loading", "Loading…");
      body.append(nav, inner);
      pop.append(bar, body);
      document.body.append(pop);
      const rect = anchor && anchor.getBoundingClientRect ? anchor.getBoundingClientRect() : { left: 24, bottom: 48 };
      pop.style.left = Math.max(8, rect.left + window.scrollX) + "px";
      pop.style.top = Math.max(8, window.scrollY + 48) + "px";
      if (window.lookingGlassWindows && window.lookingGlassWindows.place) window.lookingGlassWindows.place(pop, anchor);
      makeDraggable(pop);
      lockPopSize(pop, { width: false });
      if (window.lookingGlassWindows) {
        window.lookingGlassWindows.adopt(pop, {
          id: WIN_ID,
          kind: "logs",
          title: t("status.logs", "logs"),
          onClose: closePop,
          onRefresh: loadTab,
        });
      } else {
        raise(pop);
      }
      loadTab();
      sizeLogPopToAccess();
    }

    logsBtn.addEventListener("click", () => openLogs(logsBtn));
    if (window.lookingGlassWindows) {
      window.lookingGlassWindows.register("logs", function () {
        openLogs();
      });
    }
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && pop && !pop.classList.contains("is-minimized")) closePop();
    });
  })();


(function () {
    const cacheBtn = document.getElementById("cache-btn");
    if (!cacheBtn) return;

    let pop = null;
    let summary = null;
    let filtersEl = null;
    let listEl = null;
    let z = 125;
    const WIN_ID = "cache";
    let files = [];
    let cacheQuery = "";
    let cacheFilter = "all";
    let cacheSort = { key: "cached_at", dir: "desc" };

    function t(id, fallback) {
      const text = window.t ? window.t(id) : "";
      if (text && text !== id) return text;
      return fallback || id;
    }

    function el(tag, cls, text) {
      const node = document.createElement(tag);
      if (cls) node.className = cls;
      if (text != null) node.textContent = text;
      return node;
    }

    function raise(node) {
      if (window.lookingGlassWindows) {
        window.lookingGlassWindows.raise(node);
        return;
      }
      z += 1;
      node.style.zIndex = String(z);
    }

    function closeCache() {
      if (window.lookingGlassWindows) window.lookingGlassWindows.detach(WIN_ID);
      if (pop) pop.remove();
      pop = null;
      summary = null;
      filtersEl = null;
      listEl = null;
    }

    function makeDraggable(node) {
      if (window.lookingGlassWindows) return;
      const bar = node.querySelector(".inspect-pop-bar");
      if (!bar) return;
      let startX = 0, startY = 0, origX = 0, origY = 0;
      bar.addEventListener("pointerdown", (event) => {
        if (event.target.closest("button, a, input, select, textarea, label, .inspect-pop-actions")) return;
        if (event.button != null && event.button !== 0) return;
        event.preventDefault();
        raise(node);
        bar.setPointerCapture(event.pointerId);
        startX = event.clientX;
        startY = event.clientY;
        const rect = node.getBoundingClientRect();
        origX = rect.left + window.scrollX;
        origY = rect.top + window.scrollY;
      });
      bar.addEventListener("pointermove", (event) => {
        if (!bar.hasPointerCapture(event.pointerId)) return;
        node.style.left = Math.max(8, origX + event.clientX - startX) + "px";
        node.style.top = Math.max(8, origY + event.clientY - startY) + "px";
      });
    }

    function lockPopSize(node) {
      const rect = node.getBoundingClientRect();
      if (rect.width) node.style.width = rect.width + "px";
      if (rect.height) node.style.height = rect.height + "px";
    }

    function fmtBytes(n) {
      n = Number(n) || 0;
      if (n < 1024) return n + " B";
      if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
      return (n / 1048576).toFixed(2) + " MB";
    }

    function fmtStamp(ts) {
      const n = Number(ts);
      if (!Number.isFinite(n)) return "";
      const d = new Date(n * 1000);
      const pad = (x) => String(x).padStart(2, "0");
      const zone = (() => {
        try {
          const parts = new Intl.DateTimeFormat(undefined, { timeZoneName: "short" }).formatToParts(d);
          const hit = parts.find((p) => p.type === "timeZoneName");
          return hit && hit.value ? " " + hit.value : "";
        } catch (err) {
          return "";
        }
      })();
      return (
        d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) +
        " " + pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds()) +
        zone
      );
    }

    function looksLikeIp(text) {
      const raw = String(text || "").trim();
      if (!raw) return false;
      if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(raw)) return true;
      return raw.indexOf(":") >= 0 && /^[0-9a-fA-F:.]+$/.test(raw);
    }

    function inspectable(text) {
      const raw = String(text || "").trim();
      if (!raw) return null;
      if (/^AS\d+$/i.test(raw)) {
        const asn = raw.replace(/^AS/i, "");
        return { type: "asn", value: asn, label: "AS" + asn };
      }
      if (looksLikeIp(raw)) return { type: "ip", value: raw, label: raw };
      if (/^[A-Z]{2}$/.test(raw)) return { type: "country", value: raw, label: raw };
      if (/^(?=.{1,253}$)(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z]{2,63}$/.test(raw.replace(/\.$/, ""))) {
        return { type: "domain", value: raw.replace(/\.$/, ""), label: raw };
      }
      return null;
    }

    function inspectSpan(text) {
      const hit = inspectable(text);
      if (!hit) return document.createTextNode(text || "—");
      if (hit.type === "ip") {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "wall-value";
        btn.textContent = hit.label;
        btn.addEventListener("click", (event) => {
          event.preventDefault();
          event.stopPropagation();
          if (typeof window.openWallMenu === "function") {
            window.openWallMenu("ip", hit.value, btn);
          } else if (typeof window.openInspect === "function") {
            window.openInspect("ip", hit.value, btn);
          }
        });
        return btn;
      }
      const a = document.createElement("a");
      a.href = hit.type === "asn" ? "/AS" + hit.value : "/" + encodeURIComponent(hit.value);
      a.textContent = hit.label;
      if (hit.type === "asn") a.setAttribute("data-asn", hit.value);
      else a.setAttribute("data-domain", hit.value);
      return a;
    }

    function matchesCache(row) {
      if (cacheFilter !== "all") {
        if (cacheFilter.indexOf("ns:") === 0) {
          if (String(row.namespace || "") !== cacheFilter.slice(3)) return false;
        } else if (cacheFilter.indexOf("kind:") === 0) {
          if (String(row.kind || "") !== cacheFilter.slice(5)) return false;
        }
      }
      const q = cacheQuery.trim().toLowerCase();
      if (!q) return true;
      const blob = [
        row.query, row.file, row.namespace, row.kind, fmtBytes(row.bytes),
        row.age_hours != null ? row.age_hours + "h" : "",
        fmtStamp(row.cached_at),
      ].map((part) => String(part || "").toLowerCase()).join(" ");
      return blob.indexOf(q) >= 0;
    }

    function sortCacheValue(row, key) {
      if (key === "bytes") {
        const n = Number(row.bytes);
        return Number.isFinite(n) ? n : null;
      }
      if (key === "age_hours" || key === "cached_at") {
        const n = Number(row.cached_at != null ? row.cached_at : row.age_hours);
        return Number.isFinite(n) ? n : null;
      }
      const val = row[key];
      if (val == null || val === "") return null;
      return String(val).toLowerCase();
    }

    function sortCacheRows(rows, key, dir) {
      const sign = dir === "asc" ? 1 : -1;
      return (rows || []).slice().sort((a, b) => {
        const va = sortCacheValue(a, key);
        const vb = sortCacheValue(b, key);
        const aEmpty = va == null || va === "";
        const bEmpty = vb == null || vb === "";
        if (aEmpty && bEmpty) return ((Number(a.cached_at) || 0) - (Number(b.cached_at) || 0)) * sign;
        if (aEmpty) return 1;
        if (bEmpty) return -1;
        let cmp = 0;
        if (typeof va === "number" && typeof vb === "number") cmp = va - vb;
        else cmp = String(va).localeCompare(String(vb), undefined, { numeric: true, sensitivity: "base" });
        if (cmp === 0 && key !== "cached_at") cmp = (Number(a.cached_at) || 0) - (Number(b.cached_at) || 0);
        return cmp * sign;
      });
    }

    function paintCacheFilters() {
      if (!filtersEl) return;
      filtersEl.replaceChildren();
      const namespaces = [];
      const kinds = [];
      files.forEach((row) => {
        const ns = String(row.namespace || "").trim();
        const kind = String(row.kind || "").trim();
        if (ns && namespaces.indexOf(ns) < 0) namespaces.push(ns);
        if (kind && kinds.indexOf(kind) < 0) kinds.push(kind);
      });
      namespaces.sort();
      kinds.sort();
      const chips = [["all", t("gui.cache.all", "all")]];
      namespaces.forEach((ns) => chips.push(["ns:" + ns, ns]));
      kinds.forEach((kind) => chips.push(["kind:" + kind, kind]));
      if (!chips.some((item) => item[0] === cacheFilter)) cacheFilter = "all";
      chips.forEach(([id, label]) => {
        const btn = el("button", "log-filter" + (cacheFilter === id ? " on" : ""), label);
        btn.type = "button";
        btn.dataset.filter = id;
        btn.addEventListener("click", () => {
          cacheFilter = id;
          paintCacheFilters();
          paintCache();
        });
        filtersEl.append(btn);
      });
    }

    function paintCache() {
      if (!listEl) return;
      listEl.replaceChildren();
      if (!files.length) {
        listEl.append(el("p", "empty", t("gui.cache.empty", "Cache is empty.")));
        return;
      }
      const visible = sortCacheRows(files.filter(matchesCache), cacheSort.key, cacheSort.dir);
      if (!visible.length) {
        listEl.append(el("p", "empty", t("gui.cache.none", "No matches.")));
        return;
      }
      const table = el("table", "log-table");
      const thead = document.createElement("thead");
      const hr = document.createElement("tr");
      [
        { key: "query", label: t("gui.cache.query", "query") },
        { key: "namespace", label: t("gui.cache.namespace", "namespace") },
        { key: "kind", label: t("gui.cache.kind", "kind") },
        { key: "bytes", label: t("gui.cache.size", "size") },
        { key: "cached_at", label: t("gui.cache.when", "when") },
        { key: "age_hours", label: t("gui.cache.age", "age") },
      ].forEach((col) => {
        const th = document.createElement("th");
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "log-th-sort";
        btn.textContent = col.label;
        btn.title = t("gui.logs.sort", "sort");
        if (cacheSort.key === col.key) {
          th.className = "sort-" + cacheSort.dir;
          btn.setAttribute("aria-sort", cacheSort.dir === "asc" ? "ascending" : "descending");
          btn.append(el("span", "sort-ind", cacheSort.dir === "asc" ? "▲" : "▼"));
        } else {
          btn.setAttribute("aria-sort", "none");
        }
        btn.addEventListener("click", () => {
          const dir = cacheSort.key === col.key && cacheSort.dir === "desc" ? "asc" : "desc";
          cacheSort = { key: col.key, dir: dir };
          paintCache();
        });
        th.append(btn);
        hr.append(th);
      });
      hr.append(el("th", "", ""));
      thead.append(hr);
      const tbody = document.createElement("tbody");
      visible.forEach((row) => {
        const tr = document.createElement("tr");
        const qTd = el("td", "cache-query");
        qTd.append(inspectSpan(row.query || row.file || "—"));
        tr.append(qTd);
        tr.append(el("td", "cache-ns", row.namespace || "—"));
        tr.append(el("td", "cache-kind", row.kind || "—"));
        tr.append(el("td", "cache-size", fmtBytes(row.bytes)));
        const when = el("td", "cache-when", row.cached_at ? fmtStamp(row.cached_at) : "—");
        when.title = row.cached_at ? fmtStamp(row.cached_at) : "";
        tr.append(when);
        tr.append(el("td", "cache-age", row.age_hours != null ? row.age_hours + "h" : "—"));
        const td = document.createElement("td");
        const btn = el("button", "ghost", t("gui.cache.clear", "Clear"));
        btn.type = "button";
        btn.setAttribute("data-cache-file", row.file);
        btn.setAttribute("data-cache-ns", row.namespace || "");
        td.append(btn);
        tr.append(td);
        tbody.append(tr);
      });
      table.append(thead, tbody);
      listEl.append(table);
      if (pop && window.lookingGlassWindows && window.lookingGlassWindows.fit) window.lookingGlassWindows.fit(pop);
    }

    async function loadCache() {
      if (!summary || !listEl) return;
      summary.textContent = t("gui.cache.loading", "Loading…");
      try {
        const res = await fetch("/cache", {
          cache: "no-store",
          credentials: "same-origin",
          headers: { Accept: "application/json" },
        });
        const data = await res.json();
        summary.textContent =
          (data.count || 0) + " files · " + fmtBytes(data.bytes) + " · " +
          (data.ttl_days || 7) + "-day TTL · " + (data.directory || "");
        files = data.files || [];
        paintCacheFilters();
        paintCache();
      } catch (err) {
        summary.textContent = String(err);
      }
    }

    function openCache(anchor) {
      if (pop && window.lookingGlassWindows && window.lookingGlassWindows.front(WIN_ID)) {
        loadCache();
        return;
      }
      if (pop && !window.lookingGlassWindows && document.body.contains(pop)) {
        raise(pop);
        loadCache();
        return;
      }
      if (pop) {
        try { pop.remove(); } catch (err) {}
        pop = null;
        summary = null;
        filtersEl = null;
        listEl = null;
      }
      pop = el("div", "asn-pop inspect-pop cache-pop");
      pop.setAttribute("role", "dialog");
      pop.setAttribute("aria-labelledby", "cache-title");
      const bar = el("div", "inspect-pop-bar");
      bar.append(el("strong", "inspect-pop-title", t("gui.cache.title", "Cache")));
      bar.lastChild.id = "cache-title";
      const actions = document.createElement("span");
      actions.className = "inspect-pop-actions";
      const clearAll = el("button", "ghost", t("gui.cache.clear_all", "Clear all"));
      clearAll.type = "button";
      clearAll.id = "cache-clear-all";
      clearAll.addEventListener("click", async (event) => {
        event.preventDefault();
        event.stopPropagation();
        try {
          const res = await fetch("/cache", {
            method: "DELETE",
            credentials: "same-origin",
            headers: { Accept: "application/json" },
          });
          const data = await res.json().catch(() => ({}));
          if (!res.ok || data.ok === false) {
            throw new Error(data.error || ("HTTP " + res.status));
          }
          if (typeof window.clearAsnPopCache === "function") window.clearAsnPopCache();
          loadCache();
        } catch (err) {
          if (summary) summary.textContent = String(err.message || err);
        }
      });
      const close = el("button", "inspect-pop-close", "×");
      close.type = "button";
      close.setAttribute("aria-label", t("gui.close", "Close"));
      close.addEventListener("click", (event) => {
        event.preventDefault();
        closeCache();
      });
      actions.append(clearAll, close);
      bar.append(actions);
      const pane = el("div", "inspect-pop-body");
      summary = el("p", "hint");
      summary.id = "cache-summary";
      const search = document.createElement("input");
      search.type = "search";
      search.className = "hist-search";
      search.placeholder = t("gui.cache.search", "Search query, namespace, or kind");
      search.setAttribute("aria-label", t("gui.cache.search", "Search query, namespace, or kind"));
      rawTextField(search);
      search.value = cacheQuery;
      search.addEventListener("input", () => {
        cacheQuery = search.value;
        paintCache();
      });
      filtersEl = el("div", "log-filters");
      listEl = document.createElement("div");
      listEl.id = "cache-body";
      pane.append(summary, search, filtersEl, listEl);
      pop.append(bar, pane);
      document.body.append(pop);
      const rect = anchor && anchor.getBoundingClientRect ? anchor.getBoundingClientRect() : { left: 24, bottom: 48 };
      pop.style.left = Math.max(8, rect.left + window.scrollX) + "px";
      pop.style.top = Math.max(8, window.scrollY + 48) + "px";
      if (window.lookingGlassWindows && window.lookingGlassWindows.place) window.lookingGlassWindows.place(pop, anchor);
      makeDraggable(pop);
      lockPopSize(pop);
      if (window.lookingGlassWindows) {
        window.lookingGlassWindows.adopt(pop, {
          id: WIN_ID,
          kind: "cache",
          title: t("gui.cache.title", "Cache"),
          onClose: closeCache,
          onRefresh: loadCache,
        });
      } else {
        raise(pop);
      }
      loadCache();
      pane.addEventListener("click", async (event) => {
        const btn = event.target.closest("[data-cache-file]");
        if (!btn) return;
        const ns = btn.getAttribute("data-cache-ns") || "rdap";
        const file = btn.getAttribute("data-cache-file");
        await fetch("/cache/" + encodeURIComponent(ns) + "/" + encodeURIComponent(file), {
          method: "DELETE",
          credentials: "same-origin",
          headers: { Accept: "application/json" },
        });
        if (typeof window.clearAsnPopCache === "function") window.clearAsnPopCache();
        loadCache();
      });
    }

    cacheBtn.addEventListener("click", () => openCache(cacheBtn));
    if (window.lookingGlassWindows) {
      window.lookingGlassWindows.register("cache", function () {
        openCache();
      });
    }
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && pop && !pop.classList.contains("is-minimized")) closeCache();
    });
  })();


(function () {
    const histBtn = document.getElementById("status-history");
    if (!histBtn) return;
    const WIN_ID = "history";
    let pop = null;
    let list = null;
    let filtersEl = null;
    let files = [];
    let histFilter = "all";
    let histQuery = "";
    let histSort = { key: "ts", dir: "desc" };

    function t(id, fallback) {
      const text = window.t ? window.t(id) : "";
      if (text && text !== id) return text;
      return fallback || id;
    }

    function el(tag, cls, text) {
      const node = document.createElement(tag);
      if (cls) node.className = cls;
      if (text != null) node.textContent = text;
      return node;
    }

    function fmtStamp(ts) {
      const n = Number(ts);
      if (!Number.isFinite(n)) return "";
      const d = new Date(n * 1000);
      const pad = (x) => String(x).padStart(2, "0");
      const zone = (() => {
        try {
          const parts = new Intl.DateTimeFormat(undefined, { timeZoneName: "short" }).formatToParts(d);
          const hit = parts.find((p) => p.type === "timeZoneName");
          return hit && hit.value ? " " + hit.value : "";
        } catch (err) {
          return "";
        }
      })();
      return (
        d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) +
        " " + pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds()) +
        zone
      );
    }

    function looksLikeIp(text) {
      const raw = String(text || "").trim();
      if (!raw) return false;
      if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(raw)) return true;
      return raw.indexOf(":") >= 0 && /^[0-9a-fA-F:.]+$/.test(raw);
    }

    function inspectable(text) {
      const raw = String(text || "").trim();
      if (!raw) return null;
      if (/^AS\d+$/i.test(raw)) {
        const asn = raw.replace(/^AS/i, "");
        return { type: "asn", value: asn, label: "AS" + asn };
      }
      if (looksLikeIp(raw)) return { type: "ip", value: raw, label: raw };
      if (/^[A-Z]{2}$/.test(raw)) return { type: "country", value: raw, label: raw };
      if (/^(?=.{1,253}$)(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z]{2,63}$/.test(raw.replace(/\.$/, ""))) {
        return { type: "domain", value: raw.replace(/\.$/, ""), label: raw };
      }
      return null;
    }

    function inspectSpan(text) {
      const hit = inspectable(text);
      if (!hit) return document.createTextNode(text || "—");
      if (hit.type === "ip") {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "wall-value";
        btn.textContent = hit.label;
        btn.addEventListener("click", (event) => {
          event.preventDefault();
          event.stopPropagation();
          if (typeof window.openWallMenu === "function") {
            window.openWallMenu("ip", hit.value, btn);
          } else if (typeof window.openInspect === "function") {
            window.openInspect("ip", hit.value, btn);
          }
        });
        return btn;
      }
      const a = document.createElement("a");
      a.href = hit.type === "asn" ? "/AS" + hit.value : "/" + encodeURIComponent(hit.value);
      a.textContent = hit.label;
      if (hit.type === "asn") a.setAttribute("data-asn", hit.value);
      else a.setAttribute("data-domain", hit.value);
      return a;
    }

    function intelLine(intel, visitor) {
      const wrap = el("span", "hist-intel");
      if (visitor) wrap.append(inspectSpan(visitor));
      if (intel && typeof intel === "object") {
        if (intel.flag_url) {
          const img = document.createElement("img");
          img.className = "looking-glass-flag";
          img.src = intel.flag_url;
          img.alt = intel.country_name || intel.country || "";
          wrap.append(img);
        } else if (intel.flag) {
          wrap.append(el("span", "", intel.flag));
        }
        if (intel.asn != null && intel.asn !== false) {
          wrap.append(inspectSpan("AS" + intel.asn));
          if (intel.org_name) wrap.append(document.createTextNode(" " + intel.org_name));
        }
        if (intel.prefix) wrap.append(el("span", "hist-prefix", intel.prefix));
        if (intel.country || intel.country_name) {
          const label = intel.country_name
            ? intel.country_name + (intel.country ? " (" + intel.country + ")" : "")
            : intel.country;
          const node = inspectSpan(intel.country || label);
          node.textContent = label;
          wrap.append(node);
        }
      }
      if (!wrap.childNodes.length) wrap.textContent = "—";
      return wrap;
    }

    function replay(payload, path) {
      if (!payload) return;
      if (typeof window.openLookupPayload === "function") {
        window.openLookupPayload(payload, path || payload.path);
        return;
      }
      if (typeof window.showResult === "function") {
        window.showResult(payload, path || payload.path);
        return;
      }
      const host = document.getElementById("report-body");
      if (host && window.paintInspect) {
        host.replaceChildren(window.paintInspect(payload));
      }
    }

    function permalink(id) {
      return location.origin.replace(/\/$/, "") + "/history/" + encodeURIComponent(id);
    }

    function copyHistUrl(event, node, url) {
      event.preventDefault();
      event.stopPropagation();
      const text = url || (node && (node.href || node.getAttribute("href"))) || "";
      if (!text) return;
      const mark = function () {
        if (!node) return;
        node.classList.add("copied");
        window.setTimeout(function () { node.classList.remove("copied"); }, 1200);
      };
      const fallback = function () {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.setAttribute("readonly", "");
        ta.style.position = "fixed";
        ta.style.left = "-9999px";
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand("copy"); mark(); } catch (err) {}
        ta.remove();
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(mark).catch(fallback);
      } else {
        fallback();
      }
    }

    async function openEntry(id, btn) {
      try {
        const res = await fetch("/history/" + encodeURIComponent(id), {
          credentials: "same-origin",
          headers: { Accept: "application/json" },
        });
        const data = await res.json();
        if (!res.ok || !data.payload) return;
        if (list) list.querySelectorAll("tr.is-active").forEach((el) => el.classList.remove("is-active"));
        if (btn) btn.classList.add("is-active");
        replay(data.payload, data.path);
      } catch (err) {}
    }

    function pathId() {
      const match = (location.pathname || "").match(/^\/history\/([^/]+)\/?$/);
      return match ? decodeURIComponent(match[1]) : "";
    }

    function matchesRow(row) {
      if (histFilter !== "all" && (row.kind || "") !== histFilter) return false;
      const q = histQuery.trim().toLowerCase();
      if (!q) return true;
      const blob = [row.query, row.kind, row.user, row.path, row.visitor, row.id, fmtStamp(row.ts)]
        .map((part) => String(part || "").toLowerCase())
        .join(" ");
      return blob.indexOf(q) >= 0;
    }

    function paintFilters() {
      if (!filtersEl) return;
      filtersEl.replaceChildren();
      const kinds = [];
      files.forEach((row) => {
        const kind = String(row.kind || "").trim();
        if (kind && kinds.indexOf(kind) < 0) kinds.push(kind);
      });
      kinds.sort();
      [["all", t("gui.history.all", "all")]].concat(kinds.map((kind) => [kind, kind])).forEach(([id, label]) => {
        const btn = el("button", "log-filter" + (histFilter === id ? " on" : ""), label);
        btn.type = "button";
        btn.dataset.filter = id;
        btn.addEventListener("click", () => {
          histFilter = id;
          paintFilters();
          paintList();
        });
        filtersEl.append(btn);
      });
    }

    function sortHistValue(row, key) {
      if (key === "user") return String(row.user || "").toLowerCase();
      if (key === "visitor") return String(row.visitor || "").toLowerCase();
      if (key === "path") return String(row.path || "").toLowerCase();
      if (key === "intel") {
        const intel = row.intel && typeof row.intel === "object" ? row.intel : {};
        const parts = [];
        if (intel.asn != null && intel.asn !== false) parts.push("AS" + intel.asn);
        if (intel.org_name) parts.push(intel.org_name);
        if (intel.prefix) parts.push(intel.prefix);
        if (intel.country_name) parts.push(intel.country_name);
        else if (intel.country) parts.push(intel.country);
        return parts.join(" ").toLowerCase() || null;
      }
      const val = row[key];
      if (val == null || val === "") return null;
      if (key === "ts") {
        const n = Number(val);
        return Number.isFinite(n) ? n : String(val).toLowerCase();
      }
      return String(val).toLowerCase();
    }

    function sortHistRows(rows, key, dir) {
      const sign = dir === "asc" ? 1 : -1;
      return (rows || []).slice().sort((a, b) => {
        const va = sortHistValue(a, key);
        const vb = sortHistValue(b, key);
        const aEmpty = va == null || va === "";
        const bEmpty = vb == null || vb === "";
        if (aEmpty && bEmpty) return ((Number(a.ts) || 0) - (Number(b.ts) || 0)) * sign;
        if (aEmpty) return 1;
        if (bEmpty) return -1;
        let cmp = 0;
        if (typeof va === "number" && typeof vb === "number") cmp = va - vb;
        else cmp = String(va).localeCompare(String(vb), undefined, { numeric: true, sensitivity: "base" });
        if (cmp === 0 && key !== "ts") cmp = (Number(a.ts) || 0) - (Number(b.ts) || 0);
        return cmp * sign;
      });
    }

    function paintList() {
      if (!list) return;
      list.replaceChildren();
      if (!files.length) {
        list.append(el("p", "hist-empty", t("gui.history.empty", "No actions yet.")));
        return;
      }
      const visible = sortHistRows(files.filter(matchesRow), histSort.key, histSort.dir);
      if (!visible.length) {
        list.append(el("p", "hist-empty", t("gui.history.none", "No matches.")));
        return;
      }
      const table = el("table", "log-table");
      const head = document.createElement("thead");
      const hr = document.createElement("tr");
      [
        { key: "query", label: t("gui.history.query", "query") },
        { key: "kind", label: t("gui.history.kind", "kind") },
        { key: "user", label: t("gui.history.who", "who") },
        { key: "visitor", label: t("gui.history.visitor", "visitor") },
        { key: "intel", label: t("gui.history.intel", "intel") },
        { key: "path", label: t("gui.history.path", "path") },
        { key: "ts", label: t("gui.history.when", "when") },
      ].forEach((col) => {
        const th = document.createElement("th");
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "log-th-sort";
        btn.textContent = col.label;
        btn.title = t("gui.logs.sort", "sort");
        if (histSort.key === col.key) {
          th.className = "sort-" + histSort.dir;
          btn.setAttribute("aria-sort", histSort.dir === "asc" ? "ascending" : "descending");
          btn.append(el("span", "sort-ind", histSort.dir === "asc" ? "▲" : "▼"));
        } else {
          btn.setAttribute("aria-sort", "none");
        }
        btn.addEventListener("click", () => {
          const dir = histSort.key === col.key && histSort.dir === "desc" ? "asc" : "desc";
          histSort = { key: col.key, dir: dir };
          paintList();
        });
        th.append(btn);
        hr.append(th);
      });
      hr.append(el("th", "", ""));
      head.append(hr);
      table.append(head);
      const body = document.createElement("tbody");
      const current = pathId();
      let replayRow = null;
      for (const row of visible) {
        const tr = document.createElement("tr");
        const qTd = el("td", "hist-query");
        qTd.append(inspectSpan(row.query || "—"));
        tr.append(qTd);
        tr.append(el("td", "hist-kind", row.kind || row.path || ""));
        tr.append(el("td", "hist-who", row.user || t("gui.history.guest", "guest")));
        const visTd = el("td", "hist-visitor");
        visTd.append(row.visitor ? inspectSpan(row.visitor) : document.createTextNode("—"));
        tr.append(visTd);
        const intelTd = el("td", "hist-intel-cell");
        intelTd.append(intelLine(row.intel, ""));
        tr.append(intelTd);
        tr.append(el("td", "hist-path", row.path || "—"));
        const when = el("td", "hist-when", row.ts ? fmtStamp(row.ts) : "—");
        when.title = row.ts ? fmtStamp(row.ts) : "";
        tr.append(when);
        const actTd = document.createElement("td");
        const actions = el("span", "hist-actions");
        const link = document.createElement("a");
        link.className = "hist-link";
        link.href = permalink(row.id);
        link.textContent = t("gui.history.link", "link");
        link.title = permalink(row.id);
        link.addEventListener("click", (event) => copyHistUrl(event, link));
        actions.append(link);
        actTd.append(actions);
        tr.append(actTd);
        tr.addEventListener("click", (event) => {
          if (event.target.closest(".hist-link, .wall-value, [data-asn], [data-domain]")) return;
          openEntry(row.id, tr);
        });
        body.append(tr);
        if (current && row.id === current) {
          tr.classList.add("is-active");
          replayRow = tr;
        }
      }
      table.append(body);
      list.append(table);
      if (pop && window.lookingGlassWindows && window.lookingGlassWindows.fit) window.lookingGlassWindows.fit(pop);
      if (current && replayRow) openEntry(current, replayRow);
    }

    async function loadHistory() {
      try {
        const res = await fetch("/history", {
          cache: "no-store",
          credentials: "same-origin",
          headers: { Accept: "application/json" },
        });
        const data = await res.json();
        files = data.files || [];
        if (histFilter !== "all" && !files.some((row) => (row.kind || "") === histFilter)) {
          histFilter = "all";
        }
        paintFilters();
        paintList();
      } catch (err) {}
    }

    function closeHistory() {
      const node = pop;
      pop = null;
      list = null;
      filtersEl = null;
      if (window.lookingGlassWindows) window.lookingGlassWindows.detach(WIN_ID);
      if (node) node.remove();
    }

    function openHistory(anchor) {
      if (pop && window.lookingGlassWindows && window.lookingGlassWindows.front(WIN_ID)) {
        loadHistory();
        return;
      }
      if (pop && document.body.contains(pop)) {
        loadHistory();
        return;
      }
      if (pop) {
        try { pop.remove(); } catch (err) {}
        pop = null;
        list = null;
        filtersEl = null;
      }
      pop = el("div", "asn-pop inspect-pop history-pop");
      pop.setAttribute("role", "dialog");
      const bar = el("div", "inspect-pop-bar");
      bar.append(el("strong", "inspect-pop-title", t("gui.history", "History")));
      const close = el("button", "inspect-pop-close", "×");
      close.type = "button";
      close.setAttribute("aria-label", t("gui.close", "Close"));
      close.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        closeHistory();
      });
      bar.append(close);
      const body = el("div", "inspect-pop-body");
      const search = document.createElement("input");
      search.type = "search";
      search.className = "hist-search";
      search.placeholder = t("gui.history.search", "Search query, user, or date");
      search.setAttribute("aria-label", t("gui.history.search", "Search query, user, or date"));
      rawTextField(search);
      search.value = histQuery;
      search.addEventListener("input", () => {
        histQuery = search.value;
        paintList();
      });
      filtersEl = el("div", "log-filters");
      list = el("div");
      list.id = "history-list";
      body.append(search, filtersEl, list);
      pop.append(bar, body);
      document.body.append(pop);
      const rect = anchor && anchor.getBoundingClientRect ? anchor.getBoundingClientRect() : { left: 24, bottom: 48 };
      pop.style.left = Math.max(8, rect.left + window.scrollX) + "px";
      pop.style.top = Math.max(8, window.scrollY + 48) + "px";
      if (window.lookingGlassWindows && window.lookingGlassWindows.place) window.lookingGlassWindows.place(pop, anchor);
      if (window.lookingGlassWindows) {
        window.lookingGlassWindows.adopt(pop, {
          id: WIN_ID,
          kind: "history",
          title: t("gui.history", "History"),
          onClose: closeHistory,
          onRefresh: loadHistory,
        });
      }
      loadHistory();
    }

    histBtn.addEventListener("click", () => openHistory(histBtn));
    if (window.lookingGlassWindows) {
      window.lookingGlassWindows.register("history", function () {
        openHistory();
      });
    }
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && pop && !pop.classList.contains("is-minimized")) closeHistory();
    });
    window.refreshHistory = function () {
      if (list) loadHistory();
    };
  })();


(function () {
    const wallBtn = document.getElementById("status-wall");
    if (!wallBtn) return;

    const TABS = [
      ["ipv4", "gui.wall.ipv4", "IPv4"],
      ["ipv6", "gui.wall.ipv6", "IPv6"],
      ["asn", "gui.wall.asn", "ASN"],
      ["country", "gui.wall.country", "country"],
      ["traffic", "gui.wall.traffic", "traffic"],
      ["challenge", "gui.wall.challenge", "challenge"],
    ];
    const FILTERS = [
      ["all", "gui.wall.all", "all"],
      ["allow", "gui.wall.allow", "allow"],
      ["block", "gui.wall.block", "block"],
      ["challenge", "gui.wall.challenge", "challenge"],
    ];
    const WIN_ID = "wall";

    let pop = null;
    let inner = null;
    let filtersEl = null;
    let overlay = null;
    let pendingConfirm = null;
    let menuAnchor = null;
    let tab = "ipv4";
    let filter = "all";
    let poll = null;
    let afterId = "";
    let afterPuzzle = "";
    let listsLoaded = false;
    let wallQuery = "";
    let searchEl = null;
    const wallSort = {
      ipv4: { key: "ip", dir: "asc" },
      ipv6: { key: "ip", dir: "asc" },
      asn: { key: "value", dir: "asc" },
      country: { key: "country", dir: "asc" },
      traffic: { key: "ts", dir: "desc" },
      challenge: { key: "ts", dir: "desc" },
    };
    const expandedPeers = new Set();
    const rows = [];
    const puzzles = [];
    const STALE_SEC = 120;
    let listCache = { ip: {}, asn: {}, country: {}, ip_prefix: {} };

    function t(id, fallback, vars) {
      const text = window.t ? window.t(id, vars) : "";
      if (text && text !== id) return text;
      let out = fallback || id;
      if (vars) {
        Object.keys(vars).forEach((key) => {
          out = String(out).split("{" + key + "}").join(String(vars[key]));
        });
      }
      return out;
    }

    function el(tag, cls, text) {
      const node = document.createElement(tag);
      if (cls) node.className = cls;
      if (text != null) node.textContent = text;
      return node;
    }

    function clearOverlay() {
      if (overlay) overlay.remove();
      overlay = null;
    }

    function closeOverlay() {
      clearOverlay();
      if (pendingConfirm) {
        const done = pendingConfirm;
        pendingConfirm = null;
        done(false);
      }
    }

    function closePop() {
      if (poll) {
        window.clearInterval(poll);
        poll = null;
      }
      closeOverlay();
      if (window.lookingGlassWindows) window.lookingGlassWindows.detach(WIN_ID);
      if (pop) pop.remove();
      listsLoaded = false;
      pop = null;
      inner = null;
      filtersEl = null;
      searchEl = null;
    }

    async function fetchJson(url, opts) {
      const res = await fetch(url, Object.assign({
        cache: "no-store",
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      }, opts || {}));
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.ok === false) throw new Error(data.error || "wall");
      return data;
    }

    function family(value) {
      const text = String(value || "");
      const addr = text.indexOf("/") >= 0 ? text.slice(0, text.lastIndexOf("/")) : text;
      return addr.includes(":") ? "v6" : "v4";
    }

    function hostCidr(ip) {
      const text = String(ip || "").trim();
      if (!text) return "";
      return text + (text.includes(":") ? "/128" : "/32");
    }

    function splitParts(value) {
      const text = String(value || "").trim();
      if (!text) return { ip: "", cidr: "" };
      if (text.indexOf("/") >= 0) {
        return { ip: text.slice(0, text.lastIndexOf("/")), cidr: text };
      }
      return { ip: text, cidr: hostCidr(text) };
    }

    function ipv4ToInt(ip) {
      const parts = String(ip || "").split(".");
      if (parts.length !== 4) return null;
      let n = 0;
      for (const part of parts) {
        if (!/^\d+$/.test(part)) return null;
        const v = Number(part);
        if (v > 255) return null;
        n = (n << 8) + v;
      }
      return n >>> 0;
    }

    function expandV6(ip) {
      const raw = String(ip || "").split("%")[0];
      if (!raw || raw.indexOf(":") < 0) return null;
      const parts = raw.split("::");
      if (parts.length > 2) return null;
      const head = parts[0] ? parts[0].split(":").filter(Boolean) : [];
      const tail = parts.length > 1 && parts[1] ? parts[1].split(":").filter(Boolean) : [];
      const fill = 8 - (head.length + tail.length);
      if (fill < 0) return null;
      const groups = head.concat(Array(fill).fill("0")).concat(tail);
      if (groups.length !== 8) return null;
      let n = 0n;
      for (const group of groups) {
        if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
        n = (n << 16n) + BigInt(parseInt(group, 16));
      }
      return n;
    }

    function ipInCidr(ip, cidr) {
      const text = String(cidr || "");
      const slash = text.lastIndexOf("/");
      if (slash < 0) return String(ip) === text;
      const net = text.slice(0, slash);
      const plen = Number(text.slice(slash + 1));
      const addr = String(ip || "");
      if (addr.indexOf(":") >= 0 || net.indexOf(":") >= 0) {
        const a = expandV6(addr);
        const b = expandV6(net);
        if (a == null || b == null || !Number.isInteger(plen) || plen < 0 || plen > 128) return false;
        const shift = 128n - BigInt(plen);
        return (a >> shift) === (b >> shift);
      }
      const a = ipv4ToInt(addr);
      const b = ipv4ToInt(net);
      if (a == null || b == null || !Number.isInteger(plen) || plen < 0 || plen > 32) return false;
      const mask = plen === 0 ? 0 : (0xFFFFFFFF << (32 - plen)) >>> 0;
      return (a & mask) === (b & mask);
    }

    function coveringCidr(ip, prefix) {
      const text = String(ip || "").trim();
      const net = prefix ? String(prefix) : "";
      if (!text) return net;
      const max = text.includes(":") ? 128 : 32;
      const buckets = listCache.ip || {};
      const all = [].concat(buckets.allow || [], buckets.block || [], buckets.challenge || []);
      let best = "";
      let bestLen = -1;
      all.forEach((entry) => {
        const cidr = String(entry).indexOf("/") >= 0 ? String(entry) : hostCidr(entry);
        const plen = Number(cidr.slice(cidr.lastIndexOf("/") + 1));
        if (!Number.isInteger(plen) || plen >= max) return;
        if (!ipInCidr(text, cidr)) return;
        if (plen > bestLen) {
          best = cidr;
          bestLen = plen;
        }
      });
      return best || net;
    }

    function listedCidr(value) {
      const text = String(value || "").trim();
      if (!text) return "";
      if (text.indexOf("/") >= 0) {
        const plen = Number(text.slice(text.lastIndexOf("/") + 1));
        const max = text.includes(":") ? 128 : 32;
        if (Number.isInteger(plen) && plen < max) return text;
      }
      const parts = splitParts(text);
      const prefixes = listCache.ip_prefix || {};
      return coveringCidr(parts.ip, prefixes[parts.ip] || prefixes[text]) || "";
    }

    function actionsFor(kind) {
      if (kind === "country") return ["block"];
      if (kind === "asn") return ["block", "challenge"];
      return ["allow", "block", "challenge"];
    }

    function listedValue(kind, value) {
      const want = String(value);
      const data = listCache[kind === "ip" ? "ip" : kind] || {};
      const keys = kind === "ip"
        ? ["allow", "block", "challenge"]
        : kind === "asn"
          ? ["block", "challenge"]
          : ["block"];
      const items = keys.reduce((acc, key) => acc.concat(data[key] || []), []).map((item) => String(item));
      if (items.indexOf(want) >= 0) return true;
      if (kind !== "ip" || want.indexOf("/") < 0) return false;
      const plen = want.slice(want.lastIndexOf("/") + 1);
      const max = want.includes(":") ? "128" : "32";
      return plen === max && items.indexOf(want.slice(0, want.lastIndexOf("/"))) >= 0;
    }

    function confirmCopy(action, value) {
      const keys = {
        allow: ["gui.wall.confirm_allow", "Allow {value}?"],
        block: ["gui.wall.confirm_block", "Block {value}?"],
        challenge: ["gui.wall.confirm_challenge", "Challenge {value}?"],
        remove: ["gui.wall.confirm_remove", "Remove {value}?"],
      };
      const pair = keys[action] || keys.block;
      return t(pair[0], pair[1], { value: value });
    }

    function kindLabel(kind, asCidr) {
      if (kind === "asn") return t("gui.wall.asn", "ASN");
      if (kind === "country") return t("gui.wall.country", "country");
      return asCidr ? t("gui.wall.cidr", "CIDR") : t("gui.wall.ip", "ip");
    }

    function lookupTarget(kind, value) {
      if (kind === "asn") return { kind: "asn", key: String(value).replace(/^AS/i, "") };
      if (kind === "country") return null;
      const parts = splitParts(value);
      const ip = parts.ip || String(value || "").trim();
      return ip ? { kind: "ip", key: ip } : null;
    }

    function placeMenu(anchor) {
      if (!overlay) return;
      const rect = anchor && anchor.getBoundingClientRect
        ? anchor.getBoundingClientRect()
        : { left: 24, bottom: 72, right: 160 };
      const width = overlay.offsetWidth || 280;
      const left = Math.min(Math.max(8, rect.left), window.innerWidth - width - 8);
      let top = rect.bottom + 6;
      const height = overlay.offsetHeight || 160;
      if (top + height > window.innerHeight - 8) top = Math.max(8, rect.top - height - 6);
      overlay.style.left = left + "px";
      overlay.style.top = top + "px";
    }

    function showMenu(anchor, build) {
      clearOverlay();
      menuAnchor = anchor || null;
      overlay = el("div", "wall-menu");
      overlay.setAttribute("role", "dialog");
      build(overlay);
      document.body.append(overlay);
      placeMenu(anchor);
    }

    function confirmAction(action, kind, value) {
      return new Promise((resolve) => {
        pendingConfirm = resolve;
        showMenu(menuAnchor, (card) => {
          card.append(el("p", "wall-menu-kind", kindLabel(kind, String(value).indexOf("/") >= 0)));
          card.append(el("p", "wall-menu-value", confirmCopy(action, value)));
          const row = el("div", "wall-menu-confirm");
          const cancel = el("button", "ghost", t("gui.cancel", "Cancel"));
          cancel.type = "button";
          cancel.addEventListener("click", () => closeOverlay());
          const go = el("button", "inspect-tool " + action, t("gui.wall." + action, action));
          go.type = "button";
          go.addEventListener("click", () => {
            pendingConfirm = null;
            clearOverlay();
            resolve(true);
          });
          row.append(cancel, go);
          card.append(row);
        });
      });
    }

    async function postAction(action, kind, value, note) {
      const ok = await confirmAction(action, kind, value);
      if (!ok) return;
      const body = { kind: kind, value: value };
      const text = String(note || "").trim();
      if (text) body.note = text;
      await fetchJson("/wall/" + action, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(body),
      });
      await refreshLists();
      if (tab === "traffic") paintTraffic();
      else if (tab === "challenge") paintChallenge();
    }

    function pickActions(kind, value, anchor) {
      const listed = listedValue(kind, value);
      const look = lookupTarget(kind, value);
      showMenu(anchor, (card) => {
        card.append(el("p", "wall-menu-kind", kindLabel(kind, String(value).indexOf("/") >= 0)));
        card.append(el("p", "wall-menu-value", String(value)));
        card.append(el("p", "wall-menu-group", t("gui.wall.firewall", "firewall")));
        const fire = el("div", "wall-menu-list");
        actionsFor(kind).forEach((action) => {
          const btn = el("button", "inspect-tool " + action, t("gui.wall." + action, action));
          btn.type = "button";
          btn.addEventListener("click", async () => {
            try { await postAction(action, kind, value); } catch (err) {}
          });
          fire.append(btn);
        });
        if (listed) {
          const rm = el("button", "inspect-tool remove", t("gui.wall.remove", "remove"));
          rm.type = "button";
          rm.addEventListener("click", async () => {
            try { await postAction("remove", kind, value); } catch (err) {}
          });
          fire.append(rm);
        }
        card.append(fire);
        if (!look) return;
        if (look.kind === "asn" && typeof window.openInspect === "function") {
          card.append(el("p", "wall-menu-group", t("gui.wall.lookup", "lookup")));
          const tools = el("div", "wall-menu-list");
          const btn = el("button", "inspect-tool", t("gui.wall.asn", "ASN"));
          btn.type = "button";
          btn.addEventListener("click", (event) => {
            event.preventDefault();
            event.stopPropagation();
            closeOverlay();
            window.openInspect("asn", look.key, anchor);
          });
          tools.append(btn);
          card.append(tools);
          return;
        }
        const catalog = typeof window.toolsFor === "function" ? window.toolsFor("ip") : [];
        if (!catalog.length || typeof window.openTool !== "function") return;
        let group = null;
        let toolsEl = null;
        catalog.forEach((tool) => {
          if (tool.group !== group) {
            group = tool.group;
            card.append(el("p", "wall-menu-group", group));
            toolsEl = el("div", "wall-menu-list");
            card.append(toolsEl);
          }
          const btn = el("button", "inspect-tool", tool.label);
          btn.type = "button";
          btn.addEventListener("click", (event) => {
            event.preventDefault();
            event.stopPropagation();
            closeOverlay();
            window.openTool(tool.kind, look.key, anchor);
          });
          toolsEl.append(btn);
        });
      });
    }
    window.openWallMenu = pickActions;

    function valueBtn(kind, value, cls) {
      const btn = el("button", "wall-value" + (cls ? " " + cls : ""), value || "—");
      btn.type = "button";
      if (!value) {
        btn.disabled = true;
        return btn;
      }
      btn.title = t("gui.wall.hint", "Select to allow, block, or challenge.");
      btn.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        pickActions(kind, value, btn);
      });
      return btn;
    }

    function tagged(bucket, values, meta) {
      meta = meta || {};
      return (values || []).map((value) => {
        const info = meta[String(value)] || {};
        return {
          bucket: bucket,
          value: value,
          ts: info.ts,
          note: info.note,
          source: info.source,
          event: info.event,
        };
      });
    }

    function addForm(kind) {
      const form = el("form", "wall-add");
      const action = document.createElement("select");
      actionsFor(kind).forEach((id) => {
        const opt = document.createElement("option");
        opt.value = id;
        opt.textContent = t("gui.wall." + id, id);
        action.append(opt);
      });
      const input = document.createElement("input");
      input.type = "text";
      input.required = true;
      rawTextField(input);
      input.placeholder = kind === "ip"
        ? t("gui.wall.ip_or_cidr", "IP or CIDR")
        : kind === "asn"
          ? t("gui.wall.asn", "ASN")
          : t("gui.wall.country", "country");
      const noteInput = document.createElement("input");
      noteInput.type = "text";
      noteInput.placeholder = t("gui.wall.note", "note");
      rawTextField(noteInput);
      const go = el("button", "wall-act on", t("gui.wall.add", "add"));
      go.type = "submit";
      form.append(action, input, noteInput, go);
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const value = input.value.trim();
        if (!value) return;
        try {
          await postAction(action.value, kind, value, noteInput.value.trim());
          input.value = "";
          noteInput.value = "";
        } catch (err) {}
      });
      return form;
    }

    function sortWallValue(row, key) {
      if (key === "ip") {
        if (row.peer) return String(row.peer).toLowerCase();
        if (row.value) return splitParts(row.value).ip.toLowerCase() || null;
        return null;
      }
      if (key === "cidr") {
        if (row.peer || row.prefix) return (networkCidr(row) || "").toLowerCase() || null;
        if (row.value) return (listedCidr(row.value) || "").toLowerCase() || null;
        return null;
      }
      if (key === "bucket") return String(row.bucket || "").toLowerCase() || null;
      if (key === "country") {
        const text = ((row.name || "") + " " + (row.code || "")).trim().toLowerCase();
        return text || null;
      }
      if (key === "value") return String(row.value || "").toLowerCase() || null;
      if (key === "added" || key === "ts") {
        const raw = row.ts;
        const n = Number(raw);
        if (Number.isFinite(n) && n > 0) return n;
        const ms = Date.parse(raw);
        return Number.isFinite(ms) ? ms : (String(raw || "").toLowerCase() || null);
      }
      if (key === "note") return String(row.note || "").toLowerCase() || null;
      if (key === "ms") {
        const n = Number(row.ms);
        return Number.isFinite(n) ? n : null;
      }
      if (key === "status") {
        const n = Number(row.status);
        return Number.isFinite(n) ? n : (String(row.status || "").toLowerCase() || null);
      }
      const val = row[key];
      if (val == null || val === "") return null;
      if (typeof val === "number") return val;
      return String(val).toLowerCase();
    }

    function sortWallRows(rows, key, dir) {
      const sign = dir === "asc" ? 1 : -1;
      return (rows || []).slice().sort((a, b) => {
        const va = sortWallValue(a, key);
        const vb = sortWallValue(b, key);
        const aEmpty = va == null || va === "";
        const bEmpty = vb == null || vb === "";
        if (aEmpty && bEmpty) {
          const ta = (Number(a.ts) || 0) - (Number(b.ts) || 0);
          if (ta) return ta * sign;
          return String(a.value || a.peer || a.code || "").localeCompare(String(b.value || b.peer || b.code || ""), undefined, { numeric: true });
        }
        if (aEmpty) return 1;
        if (bEmpty) return -1;
        let cmp = 0;
        if (typeof va === "number" && typeof vb === "number") cmp = va - vb;
        else cmp = String(va).localeCompare(String(vb), undefined, { numeric: true, sensitivity: "base" });
        if (cmp === 0 && key !== "ts") cmp = (Number(a.ts) || 0) - (Number(b.ts) || 0);
        if (cmp === 0) {
          cmp = String(a.value || a.peer || a.code || "").localeCompare(String(b.value || b.peer || b.code || ""), undefined, { numeric: true });
        }
        return cmp * sign;
      });
    }

    function sortHead(cols, paint) {
      const hr = document.createElement("tr");
      const sort = wallSort[tab] || { key: "", dir: "desc" };
      cols.forEach((col) => {
        if (!col.key) {
          hr.append(el("th", "", col.label || ""));
          return;
        }
        const th = document.createElement("th");
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "log-th-sort";
        btn.textContent = col.label;
        btn.title = t("gui.logs.sort", "sort");
        if (sort.key === col.key) {
          th.className = "sort-" + sort.dir;
          btn.setAttribute("aria-sort", sort.dir === "asc" ? "ascending" : "descending");
          btn.append(el("span", "sort-ind", sort.dir === "asc" ? "▲" : "▼"));
        } else {
          btn.setAttribute("aria-sort", "none");
        }
        btn.addEventListener("click", () => {
          const dir = sort.key === col.key && sort.dir === "desc" ? "asc" : "desc";
          wallSort[tab] = { key: col.key, dir: dir };
          paint();
        });
        th.append(btn);
        hr.append(th);
      });
      return hr;
    }

    function needle() {
      return wallQuery.trim().toLowerCase();
    }

    function blobMatch(parts) {
      const q = needle();
      if (!q) return true;
      return parts.map((part) => String(part || "").toLowerCase()).join(" ").indexOf(q) >= 0;
    }

    function matchesList(row, ipCols) {
      const value = typeof row === "object" ? row.value : row;
      const bucket = typeof row === "object" ? row.bucket : "";
      if (ipCols) {
        const parts = splitParts(value);
        return blobMatch([value, parts.ip, parts.cidr, listedCidr(value), bucket, row.note, row.ts]);
      }
      return blobMatch([value, bucket, row.note, row.ts]);
    }

    function matchesCountry(row) {
      return blobMatch([row.code, row.name, row.bucket, row.note, row.ts]);
    }

    function matchesTraffic(row) {
      return blobMatch([
        row.peer, row.prefix, networkCidr(row), row.method, row.path,
        row.decision, row.status, row.ms, row.id, row.reason, fmtWallTs(row.ts),
      ]);
    }

    function matchesChallenge(row) {
      return blobMatch([
        row.peer, row.prefix, networkCidr(row), row.event, row.reason,
        row.path, row.id, fmtWallTs(row.ts),
      ]);
    }

    function formatTs(val) {
      if (val == null || val === "") return "—";
      const n = Number(val);
      const d = Number.isFinite(n) && n > 1000000000 && n < 10000000000000
        ? new Date(n > 1e12 ? n : n * 1000)
        : new Date(val);
      return isNaN(d.getTime()) ? String(val) : d.toISOString().replace("T", " ").slice(0, 19);
    }

    function listTable(kind, items, ipCols) {
      if (!items.length) return el("p", "muted", t("gui.wall.empty", "no entries"));
      const table = el("table", "log-table wall-table");
      const head = document.createElement("thead");
      const cols = ipCols
        ? [
            { key: "ip", label: t("gui.wall.ip", "ip") },
            { key: "cidr", label: t("gui.wall.cidr", "CIDR") },
            { key: "bucket", label: t("gui.wall.status", "status") },
            { key: "added", label: t("gui.wall.added", "added") },
            { key: "note", label: t("gui.wall.note", "note") },
          ]
        : [
            { key: "value", label: kind === "asn" ? t("gui.wall.asn", "ASN") : t("gui.wall.country", "country") },
            { key: "bucket", label: t("gui.wall.status", "status") },
            { key: "added", label: t("gui.wall.added", "added") },
            { key: "note", label: t("gui.wall.note", "note") },
          ];
      head.append(sortHead(cols, paintLists));
      table.append(head);
      const body = document.createElement("tbody");
      items.forEach((row) => {
        const tr = document.createElement("tr");
        const value = typeof row === "object" ? row.value : row;
        const bucket = typeof row === "object" ? row.bucket : "";
        if (ipCols) {
          const parts = splitParts(value);
          const ipTd = document.createElement("td");
          ipTd.append(valueBtn("ip", parts.ip));
          const cidrTd = document.createElement("td");
          const cidr = listedCidr(value);
          if (cidr) cidrTd.append(valueBtn("ip", cidr, "wall-cidr"));
          else cidrTd.textContent = "—";
          tr.append(ipTd, cidrTd);
        } else {
          const td = document.createElement("td");
          td.append(valueBtn(kind, String(value)));
          tr.append(td);
        }
        tr.append(el("td", "wall-dec " + bucket, bucket));
        tr.append(el("td", "muted", row.ts ? formatTs(row.ts) : "—"));
        tr.append(el("td", "", row.note || "—"));
        body.append(tr);
      });
      table.append(body);
      return table;
    }

    function applyFilter(items) {
      if (filter === "all") return items;
      return items.filter((row) => row.bucket === filter);
    }

    function countryRows() {
      const blocked = {};
      ((listCache.country || {}).block || []).forEach((code) => { blocked[String(code)] = true; });
      const meta = (listCache.country || {}).meta || {};
      let items = (listCache.country_catalog || []).map((row) => {
        const info = meta[row.code] || {};
        return {
          code: row.code,
          name: row.name || row.code,
          flag_url: row.flag_url || "",
          bucket: blocked[row.code] ? "block" : "",
          ts: info.ts,
          note: info.note,
        };
      });
      if (filter === "block") items = items.filter((row) => row.bucket === "block");
      else if (filter !== "all" && filter !== "block") items = [];
      items = items.filter(matchesCountry);
      const sort = wallSort.country || { key: "country", dir: "asc" };
      return sortWallRows(items, sort.key, sort.dir);
    }

    function countryTable(items) {
      if (!items.length) return el("p", "muted", t("gui.wall.empty", "no entries"));
      const table = el("table", "log-table wall-table");
      const head = document.createElement("thead");
      head.append(sortHead([
        { key: "country", label: t("gui.wall.country", "country") },
        { key: "bucket", label: t("gui.wall.status", "status") },
        { key: "added", label: t("gui.wall.added", "added") },
        { key: "note", label: t("gui.wall.note", "note") },
      ], paintLists));
      table.append(head);
      const body = document.createElement("tbody");
      items.forEach((row) => {
        const tr = document.createElement("tr");
        const td = document.createElement("td");
        const wrap = el("span", "wall-cc");
        if (row.flag_url) {
          const img = document.createElement("img");
          img.className = "looking-glass-flag";
          img.src = row.flag_url;
          img.alt = row.name;
          wrap.append(img);
        }
        wrap.append(valueBtn("country", row.code));
        wrap.append(el("span", "muted", row.name));
        td.append(wrap);
        tr.append(td);
        tr.append(el("td", "wall-dec " + row.bucket, row.bucket || "—"));
        tr.append(el("td", "muted", row.ts ? formatTs(row.ts) : "—"));
        tr.append(el("td", "", row.note || "—"));
        body.append(tr);
      });
      table.append(body);
      return table;
    }

    function paintLists() {
      if (!inner || tab === "traffic" || tab === "challenge") return;
      const wrap = el("div", "wall-pane");
      wrap.append(el("p", "muted wall-hint", t("gui.wall.hint", "Select an IP or CIDR to allow, block, or challenge.")));
      const sort = wallSort[tab] || { key: "ip", dir: "asc" };
      if (tab === "ipv4" || tab === "ipv6") {
        wrap.append(addForm("ip"));
        const want = tab === "ipv6" ? "v6" : "v4";
        const ip = listCache.ip || {};
        const items = sortWallRows(
          applyFilter(
            tagged("allow", ip.allow, ip.meta)
              .concat(tagged("block", ip.block, ip.meta))
              .concat(tagged("challenge", ip.challenge, ip.meta))
              .filter((row) => family(row.value) === want)
          ).filter((row) => matchesList(row, true)),
          sort.key,
          sort.dir
        );
        wrap.append(listTable("ip", items, true));
      } else if (tab === "asn") {
        wrap.append(addForm("asn"));
        const asn = listCache.asn || {};
        const items = sortWallRows(
          applyFilter(tagged("block", asn.block, asn.meta).concat(tagged("challenge", asn.challenge, asn.meta))).filter((row) => matchesList(row, false)),
          sort.key,
          sort.dir
        );
        wrap.append(listTable("asn", items, false));
      } else {
        wrap.append(countryTable(countryRows()));
      }
      inner.replaceChildren(wrap);
      if (pop && window.lookingGlassWindows && window.lookingGlassWindows.fit) window.lookingGlassWindows.fit(pop);
    }

    async function refreshLists() {
      try {
        listCache = await fetchJson("/wall");
        listsLoaded = true;
      } catch (err) {
        if (inner && tab !== "traffic" && tab !== "challenge") {
          inner.replaceChildren(el("p", "muted", String(err.message || err)));
        }
        return;
      }
      paintLists();
    }

    function copyId(event, node, text) {
      event.preventDefault();
      event.stopPropagation();
      if (!text) return;
      const mark = function () {
        node.classList.add("copied");
        window.setTimeout(function () { node.classList.remove("copied"); }, 1200);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(mark).catch(mark);
      } else {
        mark();
      }
    }

    function networkCidr(row) {
      return coveringCidr(row && row.peer, row && row.prefix) || "";
    }

    function cidrCell(row) {
      const td = document.createElement("td");
      const cidr = networkCidr(row);
      if (cidr && row && row.peer) td.append(valueBtn("ip", cidr, "wall-cidr"));
      else td.textContent = "—";
      return td;
    }

    function ipCell(peer) {
      const td = document.createElement("td");
      if (peer && peer !== "—") td.append(valueBtn("ip", peer));
      else td.textContent = "—";
      return td;
    }

    function fmtWallTs(ts) {
      const n = Number(ts);
      if (!Number.isFinite(n)) return "";
      const d = new Date(n * 1000);
      const pad = (x) => String(x).padStart(2, "0");
      const zone = (() => {
        try {
          const parts = new Intl.DateTimeFormat(undefined, { timeZoneName: "short" }).formatToParts(d);
          const hit = parts.find((p) => p.type === "timeZoneName");
          return hit && hit.value ? " " + hit.value : "";
        } catch (err) {
          return "";
        }
      })();
      return (
        d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) +
        " " + pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds()) +
        zone
      );
    }

    function pruneRing(list) {
      const cutoff = Date.now() / 1000 - STALE_SEC;
      let i = 0;
      while (i < list.length) {
        if (Number(list[i].ts) < cutoff) list.splice(i, 1);
        else i += 1;
      }
      if (list.length > 500) list.splice(0, list.length - 500);
    }

    function trafficRow(row) {
      const tr = document.createElement("tr");
      tr.className = "wall-peer-detail";
      const idCell = el("td", "wall-tree-branch", "│ └─ " + String(row.id || "").slice(0, 8));
      idCell.title = row.id || "";
      idCell.addEventListener("click", (event) => copyId(event, idCell, row.id));
      tr.append(idCell);
      tr.append(el("td", "", ""));
      tr.append(el("td", "", ""));
      tr.append(el("td", "", row.method || ""));
      tr.append(el("td", "", row.path || ""));
      tr.append(el("td", "wall-dec " + (row.decision || ""), row.decision || ""));
      tr.append(el("td", "", String(row.status || "")));
      tr.append(el("td", "", String(row.ms || "")));
      return tr;
    }

    function paintTraffic() {
      if (!inner || tab !== "traffic") return;
      pruneRing(rows);
      const wrap = el("div", "wall-pane");
      const visible = rows.filter((row) => (filter === "all" || (row.decision || "") === filter) && matchesTraffic(row));
      wrap.append(el("p", "muted", t("gui.wall.live", "live") + " · " + visible.length));
      wrap.append(el("p", "muted wall-hint", t("gui.wall.hint", "Select an IP or CIDR to allow, block, or challenge.")));
      if (!visible.length) {
        wrap.append(el("p", "muted", t("gui.logs.empty", "no data")));
        inner.replaceChildren(wrap);
      if (pop && window.lookingGlassWindows && window.lookingGlassWindows.fit) window.lookingGlassWindows.fit(pop);
        return;
      }
      const groups = [];
      const index = {};
      visible.forEach((row) => {
        const key = row.peer || "—";
        if (index[key] == null) {
          index[key] = groups.length;
          groups.push({ peer: key, rows: [] });
        }
        groups[index[key]].rows.push(row);
      });
      const sort = wallSort.traffic || { key: "ts", dir: "desc" };
      const ranked = sortWallRows(groups.map((group) => {
        const latest = group.rows[group.rows.length - 1] || {};
        return {
          peer: group.peer,
          prefix: latest.prefix,
          method: latest.method,
          path: latest.path,
          decision: latest.decision,
          status: latest.status,
          ms: latest.ms,
          ts: latest.ts,
          rows: group.rows,
        };
      }), sort.key, sort.dir);
      const table = el("table", "log-table wall-table wall-tree");
      const head = document.createElement("thead");
      head.append(sortHead([
        { key: "", label: "" },
        { key: "ip", label: t("gui.wall.ip", "ip") },
        { key: "cidr", label: t("gui.wall.cidr", "CIDR") },
        { key: "method", label: t("gui.wall.method", "method") },
        { key: "path", label: t("gui.wall.path", "path") },
        { key: "decision", label: t("gui.wall.decision", "decision") },
        { key: "status", label: t("gui.wall.status", "status") },
        { key: "ms", label: t("gui.wall.ms", "ms") },
      ], paintTraffic));
      table.append(head);
      const body = document.createElement("tbody");
      ranked.forEach((group) => {
        const latest = group.rows[group.rows.length - 1];
        const open = expandedPeers.has(group.peer);
        const summary = document.createElement("tr");
        summary.className = "wall-peer-row" + (open ? " open" : "");
        const toggle = el("td", "wall-tree-toggle", open ? "▾" : "▸");
        if (group.rows.length > 1) {
          toggle.append(el("span", "wall-tree-count", String(group.rows.length)));
        }
        summary.append(toggle);
        summary.append(ipCell(group.peer));
        summary.append(cidrCell(latest));
        summary.append(el("td", "", latest.method || ""));
        summary.append(el("td", "", latest.path || ""));
        summary.append(el("td", "wall-dec " + (latest.decision || ""), latest.decision || ""));
        summary.append(el("td", "", String(latest.status || "")));
        summary.append(el("td", "", String(latest.ms || "")));
        summary.addEventListener("click", (event) => {
          if (event.target.closest(".wall-value")) return;
          if (open) expandedPeers.delete(group.peer);
          else expandedPeers.add(group.peer);
          paintTraffic();
        });
        body.append(summary);
        if (open) {
          group.rows.slice().reverse().forEach((row) => body.append(trafficRow(row)));
        }
      });
      table.append(body);
      wrap.append(table);
      inner.replaceChildren(wrap);
      if (pop && window.lookingGlassWindows && window.lookingGlassWindows.fit) window.lookingGlassWindows.fit(pop);
    }

    function paintChallenge() {
      if (!inner || tab !== "challenge") return;
      pruneRing(puzzles);
      const wrap = el("div", "wall-pane");
      const visible = sortWallRows(
        puzzles.filter((row) => (filter === "all" || (row.event || "") === filter) && matchesChallenge(row)),
        (wallSort.challenge || { key: "ts", dir: "desc" }).key,
        (wallSort.challenge || { key: "ts", dir: "desc" }).dir
      );
      const chips = el("div", "log-summary");
      const issued = puzzles.filter((row) => row.event === "issued").length;
      const solved = puzzles.filter((row) => row.event === "solved").length;
      const failed = puzzles.filter((row) => row.event === "failed").length;
      function chip(n, key, fallback, cls) {
        const node = el("span", "log-stat" + (cls ? " " + cls : ""));
        node.append(el("strong", "", String(n)));
        node.append(document.createTextNode(" " + t(key, fallback)));
        return node;
      }
      chips.append(chip(issued, "gui.wall.issued", "issued"));
      chips.append(chip(solved, "gui.wall.solved", "solved", "ok"));
      chips.append(chip(failed, "gui.wall.failed", "failed", failed ? "bad" : ""));
      wrap.append(chips);
      wrap.append(el("p", "muted wall-hint", t("gui.wall.hint", "Select an IP or CIDR to allow, block, or challenge.")));
      if (!visible.length) {
        wrap.append(el("p", "muted", t("gui.logs.empty", "no data")));
        inner.replaceChildren(wrap);
      if (pop && window.lookingGlassWindows && window.lookingGlassWindows.fit) window.lookingGlassWindows.fit(pop);
        return;
      }
      const table = el("table", "log-table wall-table");
      const head = document.createElement("thead");
      head.append(sortHead([
        { key: "ts", label: t("gui.wall.time", "time") },
        { key: "ip", label: t("gui.wall.ip", "ip") },
        { key: "cidr", label: t("gui.wall.cidr", "CIDR") },
        { key: "event", label: t("gui.wall.event", "event") },
        { key: "reason", label: t("gui.wall.reason", "reason") },
      ], paintChallenge));
      table.append(head);
      const body = document.createElement("tbody");
      visible.forEach((row) => {
        const tr = document.createElement("tr");
        const when = el("td", "muted", fmtWallTs(row.ts) || "—");
        when.title = fmtWallTs(row.ts);
        tr.append(when);
        tr.append(ipCell(row.peer));
        tr.append(cidrCell(row));
        tr.append(el("td", "wall-dec " + (row.event || ""), row.event || ""));
        tr.append(el("td", "", row.reason || "—"));
        body.append(tr);
      });
      table.append(body);
      wrap.append(table);
      inner.replaceChildren(wrap);
      if (pop && window.lookingGlassWindows && window.lookingGlassWindows.fit) window.lookingGlassWindows.fit(pop);
    }

    async function pollTraffic() {
      try {
        let url = "/wall/traffic?limit=200";
        if (afterId) url += "&after=" + encodeURIComponent(afterId);
        const data = await fetchJson(url);
        (data.rows || []).forEach((row) => {
          rows.push(row);
          if (row.id) afterId = row.id;
        });
        pruneRing(rows);
        paintTraffic();
      } catch (err) {
        if (inner && tab === "traffic" && !rows.length) {
          inner.replaceChildren(el("p", "muted", String(err.message || err)));
        }
      }
    }

    async function pollChallenge() {
      try {
        let url = "/wall/challenge?limit=200";
        if (afterPuzzle) url += "&after=" + encodeURIComponent(afterPuzzle);
        const data = await fetchJson(url);
        (data.rows || []).forEach((row) => {
          puzzles.push(row);
          if (row.id) afterPuzzle = row.id;
        });
        pruneRing(puzzles);
        paintChallenge();
      } catch (err) {
        if (inner && tab === "challenge" && !puzzles.length) {
          inner.replaceChildren(el("p", "muted", String(err.message || err)));
        }
      }
    }

    function filterOptions() {
      if (tab === "challenge") {
        return [
          ["all", "gui.wall.all", "all"],
          ["issued", "gui.wall.issued", "issued"],
          ["solved", "gui.wall.solved", "solved"],
          ["failed", "gui.wall.failed", "failed"],
        ];
      }
      if (tab === "country") return FILTERS.filter((item) => item[0] === "all" || item[0] === "block");
      if (tab === "asn") return FILTERS.filter((item) => item[0] !== "allow");
      return FILTERS;
    }

    function paintFilters() {
      if (!filtersEl) return;
      const options = filterOptions();
      if (!options.some((item) => item[0] === filter)) filter = "all";
      filtersEl.replaceChildren();
      options.forEach(([id, key, fallback]) => {
        const btn = el("button", "log-filter" + (filter === id ? " on" : ""), t(key, fallback));
        btn.type = "button";
        btn.dataset.filter = id;
        btn.addEventListener("click", () => {
          filter = id;
          paintFilters();
          if (tab === "traffic") paintTraffic();
          else if (tab === "challenge") paintChallenge();
          else paintLists();
        });
        filtersEl.append(btn);
      });
    }

    function loadTab() {
      if (poll) {
        window.clearInterval(poll);
        poll = null;
      }
      closeOverlay();
      paintFilters();
      if (tab === "traffic") {
        paintTraffic();
        pollTraffic();
        poll = window.setInterval(pollTraffic, 1000);
        if (!listsLoaded) refreshLists();
        return;
      }
      if (tab === "challenge") {
        paintChallenge();
        pollChallenge();
        poll = window.setInterval(pollChallenge, 1000);
        if (!listsLoaded) refreshLists();
        return;
      }
      if (inner) inner.textContent = t("gui.cache.loading", "Loading…");
      refreshLists();
    }

    function openWall(anchor) {
      if (pop && window.lookingGlassWindows && window.lookingGlassWindows.front(WIN_ID)) {
        loadTab();
        return;
      }
      if (pop && document.body.contains(pop)) {
        loadTab();
        return;
      }
      if (pop) {
        try { pop.remove(); } catch (err) {}
        pop = null;
        inner = null;
        filtersEl = null;
        searchEl = null;
      }
      pop = el("div", "asn-pop inspect-pop log-pop wall-pop");
      pop.setAttribute("role", "dialog");
      const bar = el("div", "inspect-pop-bar");
      bar.append(el("strong", "inspect-pop-title", t("status.wall", "firewall")));
      const close = el("button", "inspect-pop-close", "×");
      close.type = "button";
      close.setAttribute("aria-label", t("gui.close", "Close"));
      close.addEventListener("click", (event) => {
        event.preventDefault();
        closePop();
      });
      bar.append(close);
      const body = el("div", "inspect-pop-body");
      const nav = el("div", "log-tabs");
      TABS.forEach(([id, key, fallback]) => {
        const btn = el("button", "log-tab" + (tab === id ? " on" : ""), t(key, fallback));
        btn.type = "button";
        btn.dataset.tab = id;
        btn.addEventListener("click", () => {
          tab = id;
          nav.querySelectorAll(".log-tab").forEach((n) => n.classList.remove("on"));
          btn.classList.add("on");
          loadTab();
        });
        nav.append(btn);
      });
      filtersEl = el("div", "log-filters");
      searchEl = document.createElement("input");
      searchEl.type = "search";
      searchEl.className = "hist-search";
      searchEl.placeholder = t("gui.wall.search", "Search lists, traffic, or challenge");
      searchEl.setAttribute("aria-label", t("gui.wall.search", "Search lists, traffic, or challenge"));
      rawTextField(searchEl);
      searchEl.value = wallQuery;
      searchEl.addEventListener("input", () => {
        wallQuery = searchEl.value;
        if (tab === "traffic") paintTraffic();
        else if (tab === "challenge") paintChallenge();
        else paintLists();
      });
      inner = el("div", "log-inner");
      body.append(nav, searchEl, filtersEl, inner);
      pop.append(bar, body);
      document.body.append(pop);
      const rect = anchor && anchor.getBoundingClientRect ? anchor.getBoundingClientRect() : { left: 24, bottom: 48 };
      pop.style.left = Math.max(8, rect.left + window.scrollX) + "px";
      pop.style.top = Math.max(8, window.scrollY + 48) + "px";
      if (window.lookingGlassWindows && window.lookingGlassWindows.place) window.lookingGlassWindows.place(pop, anchor);
      if (window.lookingGlassWindows) {
        window.lookingGlassWindows.adopt(pop, {
          id: WIN_ID,
          kind: "wall",
          title: t("status.wall", "firewall"),
          onClose: closePop,
          onRefresh: loadTab,
        });
      }
      loadTab();
    }

    wallBtn.addEventListener("click", (event) => {
      event.preventDefault();
      openWall(wallBtn);
    });
    if (window.lookingGlassWindows) {
      window.lookingGlassWindows.register("wall", function () {
        openWall();
      });
    }
    document.addEventListener("mousedown", (event) => {
      if (!overlay) return;
      if (overlay.contains(event.target)) return;
      if (event.target.closest && event.target.closest(".wall-value")) return;
      closeOverlay();
    });
    document.addEventListener("keydown", (event) => {
      if (event.key !== "Escape") return;
      if (overlay) {
        event.preventDefault();
        closeOverlay();
        return;
      }
      if (pop && !pop.classList.contains("is-minimized")) closePop();
    });
  })();


(function () {
    const configBtn = document.getElementById("status-config");
    if (!configBtn) return;

    let pop = null;
    let form = null;
    let authBox = null;
    let note = null;
    let z = 125;
    const WIN_ID = "config";

    function t(id, fallback) {
      const text = window.t ? window.t(id) : "";
      if (text && text !== id) return text;
      return fallback || id;
    }

    function el(tag, cls, text) {
      const node = document.createElement(tag);
      if (cls) node.className = cls;
      if (text != null) node.textContent = text;
      return node;
    }

    function raise(node) {
      if (window.lookingGlassWindows) {
        window.lookingGlassWindows.raise(node);
        return;
      }
      z += 1;
      node.style.zIndex = String(z);
    }

    function closeConfig() {
      if (window.lookingGlassWindows) window.lookingGlassWindows.detach(WIN_ID);
      if (pop) pop.remove();
      pop = null;
      form = null;
      authBox = null;
      note = null;
    }

    function lockPopSize(node, opts) {
      const rect = node.getBoundingClientRect();
      if ((!opts || opts.width !== false) && rect.width) node.style.width = rect.width + "px";
      if ((!opts || opts.height !== false) && rect.height) node.style.height = rect.height + "px";
    }

    function makeDraggable(node) {
      if (window.lookingGlassWindows) return;
      const bar = node.querySelector(".inspect-pop-bar");
      if (!bar) return;
      let startX = 0, startY = 0, origX = 0, origY = 0;
      bar.addEventListener("pointerdown", (event) => {
        if (event.target.closest("button, a, input, select, textarea, label, .inspect-pop-actions")) return;
        if (event.button != null && event.button !== 0) return;
        event.preventDefault();
        raise(node);
        bar.setPointerCapture(event.pointerId);
        startX = event.clientX;
        startY = event.clientY;
        const rect = node.getBoundingClientRect();
        origX = rect.left + window.scrollX;
        origY = rect.top + window.scrollY;
      });
      bar.addEventListener("pointermove", (event) => {
        if (!bar.hasPointerCapture(event.pointerId)) return;
        node.style.left = Math.max(8, origX + event.clientX - startX) + "px";
        node.style.top = Math.max(8, origY + event.clientY - startY) + "px";
      });
    }

    async function fetchJson(url, opts) {
      const res = await fetch(url, Object.assign({
        credentials: "same-origin",
        cache: "no-store",
        headers: { Accept: "application/json" },
      }, opts || {}));
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.ok === false) {
        throw new Error(data.error || ("HTTP " + res.status));
      }
      return data;
    }

    function field(name, label, type, value, extra) {
      const row = el("label", "config-row");
      row.append(el("span", "config-label", label));
      let input;
      if (type === "select") {
        input = document.createElement("select");
        (extra && extra.options ? extra.options : []).forEach((opt) => {
          const o = document.createElement("option");
          o.value = opt[0];
          o.textContent = opt[1];
          if (String(opt[0]) === String(value)) o.selected = true;
          input.append(o);
        });
      } else if (type === "checkbox") {
        input = document.createElement("input");
        input.type = "checkbox";
        input.checked = !!value;
      } else {
        input = document.createElement("input");
        input.type = type || "text";
        input.value = value == null ? "" : String(value);
        if (extra) Object.assign(input, extra);
        var kind = type || "text";
        if (kind === "password") rawTextField(input, "password");
        else if (kind === "text" || kind === "search" || kind === "url" || kind === "email") rawTextField(input);
      }
      input.name = name;
      row.append(input);
      return row;
    }

    function paintConfig(data) {
      if (!form) return;
      form.innerHTML = "";
      const docs = data.docs || {};
      const cache = data.cache || {};
      const history = data.history || {};
      const wall = data.wall || {};
      const refresh = data.refresh || {};

      const docsSec = el("fieldset", "config-sec");
      docsSec.append(el("legend", null, t("gui.config.docs", "Documentation")));
      docsSec.append(field("docs.enabled", t("gui.config.docs.enabled", "Enable documentation"), "checkbox", docs.enabled));
      form.append(docsSec);

      const locSec = el("fieldset", "config-sec");
      locSec.append(el("legend", null, t("gui.config.locale", "Locale")));
      locSec.append(field(
        "locale",
        t("gui.config.locale", "Locale"),
        "select",
        data.locale || "en",
        { options: (data.locales || ["en"]).map(function (lang) { return [lang, lang]; }) }
      ));
      form.append(locSec);

      const cacheSec = el("fieldset", "config-sec");
      cacheSec.append(el("legend", null, t("gui.config.cache", "Cache")));
      cacheSec.append(field("cache.ttl_days", t("gui.config.cache.ttl_days", "Cache TTL (days)"), "number", cache.ttl_days, { min: "0", step: "1" }));
      cacheSec.append(field("cache.gui", t("gui.config.cache.gui", "Cache GUI"), "checkbox", cache.gui));
      form.append(cacheSec);

      const histSec = el("fieldset", "config-sec");
      histSec.append(el("legend", null, t("gui.config.history", "History")));
      histSec.append(field("history.snapshots", t("gui.config.history.snapshots", "Snapshots"), "number", history.snapshots, { min: "-1", step: "1" }));
      form.append(histSec);

      const wallSec = el("fieldset", "config-sec config-span");
      wallSec.append(el("legend", null, t("gui.config.wall", "Firewall")));
      wallSec.append(field(
        "wall.default",
        t("gui.config.wall.default", "Unmatched traffic"),
        "select",
        wall.default || "allow",
        {
          options: [
            ["allow", t("gui.config.wall.default.allow", "Allow")],
            ["block", t("gui.config.wall.default.block", "Block")],
          ],
        }
      ));
      wallSec.append(field("wall.challenge_ttl_days", t("gui.config.wall.challenge_ttl_days", "Pass cookie TTL (days)"), "number", wall.challenge_ttl_days, { min: "1", step: "1" }));
      wallSec.append(field("wall.challenge_bits", t("gui.config.wall.challenge_bits", "Puzzle bits (8–24)"), "number", wall.challenge_bits, { min: "8", max: "24", step: "1" }));
      const headers = wall.headers || {};
      const headerNames = ["decision", "reason", "asn", "org", "prefix", "country", "flag_url", "timings", "iana"];
      const headerBox = el("div", "config-headers");
      headerNames.forEach((name) => {
        headerBox.append(field(
          "wall.headers." + name,
          t("gui.config.wall.headers." + name, name),
          "checkbox",
          headers[name] !== false
        ));
      });
      wallSec.append(headerBox);
      form.append(wallSec);

      const logs = data.logs || {};
      const logsSec = el("fieldset", "config-sec");
      logsSec.append(el("legend", null, t("gui.config.logs", "Logs")));
      logsSec.append(field("logs.max_bytes", t("gui.config.logs.max_bytes", "Rotate at (bytes)"), "number", logs.max_bytes, { min: "1024", step: "1" }));
      logsSec.append(field("logs.keep", t("gui.config.logs.keep", "Keep rotated files (−1 forever)"), "number", logs.keep, { min: "-1", step: "1" }));
      form.append(logsSec);

      const mtr = data.mtr || {};
      const mtrSec = el("fieldset", "config-sec");
      mtrSec.append(el("legend", null, t("gui.config.mtr", "MTR")));
      mtrSec.append(field("mtr.cycles", t("gui.config.mtr.cycles", "Default passes"), "number", mtr.cycles, { min: "1", max: "50", step: "1" }));
      mtrSec.append(field("mtr.max_cycles", t("gui.config.mtr.max_cycles", "Max passes"), "number", mtr.max_cycles, { min: "1", max: "50", step: "1" }));
      form.append(mtrSec);

      const http = data.http || {};
      const httpSec = el("fieldset", "config-sec config-span");
      httpSec.append(el("legend", null, t("gui.config.http", "HTTPS")));
      httpSec.append(field("http.enabled", t("gui.config.http.enabled", "Serve the GUI over TLS"), "checkbox", http.enabled));
      httpSec.append(field("http.hostname", t("gui.config.http.hostname", "Hostname (FQDN)"), "text", http.hostname || ""));
      httpSec.append(field("http.email", t("gui.config.http.email", "Let's Encrypt email"), "text", http.email || ""));
      httpSec.append(field("http.port", t("gui.config.http.port", "TLS port"), "number", http.port, { min: "1", max: "65535", step: "1" }));
      httpSec.append(field("http.acme_port", t("gui.config.http.acme_port", "ACME HTTP-01 port"), "number", http.acme_port, { min: "1", max: "65535", step: "1" }));
      httpSec.append(field("http.bind", t("gui.config.http.bind", "Bind address (* for both families)"), "text", http.bind || "*"));
      httpSec.append(field("http.workers", t("gui.config.http.workers", "Uvicorn workers"), "number", http.workers, { min: "1", max: "32", step: "1" }));
      httpSec.append(field("http.staging", t("gui.config.http.staging", "Use Let's Encrypt staging"), "checkbox", http.staging));
      const origins = Array.isArray(http.controller_origins) ? http.controller_origins.join(", ") : (http.controller_origins || "");
      httpSec.append(field("http.controller_origins", t("gui.config.http.controller_origins", "Controller origins (CORS, comma-separated)"), "text", origins));
      form.append(httpSec);

      const refSec = el("fieldset", "config-sec config-span");
      refSec.append(el("legend", null, t("gui.config.refresh", "Dataset refresh (days)")));
      ["iana", "dns_types", "tlds", "rdap_dns", "rir", "asn_org", "asn"].forEach((name) => {
        refSec.append(field(
          "refresh." + name,
          t("gui.config.refresh." + name, name),
          "number",
          refresh[name],
          { min: "0", step: "1" }
        ));
      });
      form.append(refSec);

      const meta = el("div", "config-meta");
      meta.append(el("p", "hint", t("gui.config.path", "File") + ": " + (data.path || "")));
      form.append(meta);

      const actions = el("div", "config-actions");
      const save = el("button", "go", t("gui.config.save", "Save"));
      save.type = "submit";
      actions.append(save);
      form.append(actions);
    }

    function paintAuthPanel(data, onceSecret) {
      if (!authBox) return;
      authBox.replaceChildren();
      const sec = el("fieldset", "config-sec");
      sec.append(el("legend", null, t("gui.config.auth", "Admin")));
      sec.append(el(
        "p",
        "hint",
        data.password_set
          ? t("gui.config.password.set", "Password is set.")
          : t("gui.config.password.off", "Login is disabled until a password is set.")
      ));
      const pw = document.createElement("input");
      pw.type = "password";
      pw.autocomplete = "new-password";
      rawTextField(pw, "password");
      pw.placeholder = t("gui.login.password", "Password");
      const setBtn = el("button", "go", t("gui.config.password.save", "Set password"));
      setBtn.type = "button";
      setBtn.addEventListener("click", async () => {
        try {
          await fetchJson("/auth/password", {
            method: "POST",
            headers: { Accept: "application/json", "Content-Type": "application/json" },
            body: JSON.stringify({ password: pw.value }),
          });
          pw.value = "";
          if (note) note.textContent = t("gui.config.saved", "Saved");
          loadAuth();
        } catch (err) {
          if (note) note.textContent = String(err.message || err);
        }
      });
      const clearBtn = el("button", "ghost", t("gui.config.password.clear", "Disable login"));
      clearBtn.type = "button";
      clearBtn.addEventListener("click", async () => {
        try {
          await fetchJson("/auth/password/clear", { method: "POST" });
          if (note) note.textContent = t("gui.config.saved", "Saved");
          loadAuth();
        } catch (err) {
          if (note) note.textContent = String(err.message || err);
        }
      });
      const pwRow = el("div", "config-actions");
      pwRow.append(pw, setBtn, clearBtn);
      sec.append(pwRow);
      const list = el("ul", "config-keys");
      (data.keys || []).forEach((item) => {
        const row = el("li", "config-key");
        row.append(el("span", null, (item.name || item.id) + " · " + item.id));
        const rev = el("button", "ghost", t("gui.config.keys.revoke", "Revoke"));
        rev.type = "button";
        rev.addEventListener("click", async () => {
          try {
            await fetchJson("/auth/keys/" + encodeURIComponent(item.id), { method: "DELETE" });
            loadAuth();
          } catch (err) {
            if (note) note.textContent = String(err.message || err);
          }
        });
        row.append(rev);
        list.append(row);
      });
      sec.append(list);
      const nameInput = document.createElement("input");
      nameInput.type = "text";
      nameInput.placeholder = t("gui.config.keys.name", "Key name");
      rawTextField(nameInput);
      const createBtn = el("button", "go", t("gui.config.keys.create", "Create key"));
      createBtn.type = "button";
      createBtn.addEventListener("click", async () => {
        try {
          const created = await fetchJson("/auth/keys", {
            method: "POST",
            headers: { Accept: "application/json", "Content-Type": "application/json" },
            body: JSON.stringify({ name: nameInput.value || "key" }),
          });
          nameInput.value = "";
          loadAuth(created.secret || "");
        } catch (err) {
          if (note) note.textContent = String(err.message || err);
        }
      });
      const keyRow = el("div", "config-actions");
      keyRow.append(nameInput, createBtn);
      sec.append(keyRow);
      if (onceSecret) {
        sec.append(el(
          "p",
          "hint",
          t("gui.config.keys.secret", "Copy this key now; it is shown once.") + " " + onceSecret
        ));
      }
      authBox.append(sec);
    }

    async function loadAuth(onceSecret) {
      if (!authBox) return;
      try {
        const data = await fetchJson("/auth/keys");
        paintAuthPanel(data, onceSecret);
      } catch (err) {
        if (note) note.textContent = String(err.message || err);
      }
    }

    async function loadConfig() {
      if (note) note.textContent = t("gui.config.loading", "Loading…");
      try {
        const data = await fetchJson("/config");
        paintConfig(data);
        if (window.lookingGlassDocsChrome) {
          window.lookingGlassDocsChrome({
            enabled: !!(data.docs && data.docs.enabled),
            generated: !!data.docs_generated,
          });
        }
        if (note) note.textContent = "";
        await loadAuth();
      } catch (err) {
        if (note) note.textContent = String(err.message || err);
      }
    }

    function readForm() {
      const out = {};
      if (!form) return out;
      form.querySelectorAll("input[name], select[name]").forEach((input) => {
        if (input.type === "checkbox") out[input.name] = input.checked;
        else out[input.name] = input.value;
      });
      return out;
    }

    async function saveConfig(event) {
      event.preventDefault();
      if (note) note.textContent = "";
      try {
        const data = await fetchJson("/config", {
          method: "POST",
          headers: { Accept: "application/json", "Content-Type": "application/json" },
          body: JSON.stringify(readForm()),
        });
        paintConfig(data);
        if (window.lookingGlassDocsChrome) {
          window.lookingGlassDocsChrome({
            enabled: !!(data.docs && data.docs.enabled),
            generated: !!data.docs_generated,
          });
        }
        if (note) note.textContent = t("gui.config.saved", "Saved");
      } catch (err) {
        if (note) note.textContent = String(err.message || err);
      }
    }

    function openConfig(anchor) {
      if (pop && window.lookingGlassWindows && window.lookingGlassWindows.front(WIN_ID)) {
        loadConfig();
        return;
      }
      if (pop && !window.lookingGlassWindows && document.body.contains(pop)) {
        raise(pop);
        loadConfig();
        return;
      }
      if (pop) {
        try { pop.remove(); } catch (err) {}
        pop = null;
        form = null;
        authBox = null;
        note = null;
      }
      pop = el("div", "asn-pop inspect-pop config-pop");
      pop.setAttribute("role", "dialog");
      pop.setAttribute("aria-labelledby", "config-title");
      const bar = el("div", "inspect-pop-bar");
      bar.append(el("strong", "inspect-pop-title", t("gui.config.title", "Config")));
      bar.lastChild.id = "config-title";
      const actions = document.createElement("span");
      actions.className = "inspect-pop-actions";
      const close = el("button", "inspect-pop-close", "×");
      close.type = "button";
      close.setAttribute("aria-label", t("gui.close", "Close"));
      close.addEventListener("click", (event) => {
        event.preventDefault();
        closeConfig();
      });
      actions.append(close);
      bar.append(actions);
      const pane = el("div", "inspect-pop-body");
      note = el("p", "hint");
      form = document.createElement("form");
      form.className = "config-form";
      form.addEventListener("submit", saveConfig);
      authBox = el("div", "config-auth");
      pane.append(note, form, authBox);
      pop.append(bar, pane);
      document.body.append(pop);
      const rect = anchor && anchor.getBoundingClientRect ? anchor.getBoundingClientRect() : { left: 24, bottom: 48 };
      pop.style.left = Math.max(8, rect.left + window.scrollX) + "px";
      pop.style.top = Math.max(8, window.scrollY + 48) + "px";
      if (window.lookingGlassWindows && window.lookingGlassWindows.place) window.lookingGlassWindows.place(pop, anchor || configBtn);
      makeDraggable(pop);
      lockPopSize(pop, { width: false, height: false });
      if (window.lookingGlassWindows) {
        window.lookingGlassWindows.adopt(pop, {
          id: WIN_ID,
          kind: "config",
          title: t("gui.config.title", "Config"),
          onClose: closeConfig,
          onRefresh: loadConfig,
        });
      } else {
        raise(pop);
      }
      loadConfig();
    }

    configBtn.addEventListener("click", () => openConfig(configBtn));
    if (window.lookingGlassWindows) {
      window.lookingGlassWindows.register("config", function () {
        openConfig();
      });
    }
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && pop && !pop.classList.contains("is-minimized")) closeConfig();
    });
  })();


(function () {
    const servicesBtn = document.getElementById("status-services");
    if (!servicesBtn) return;

    let pop = null;
    let inner = null;
    let z = 125;
    const WIN_ID = "services";

    function t(id, fallback) {
      const text = window.t ? window.t(id) : "";
      if (text && text !== id) return text;
      return fallback || id;
    }

    function el(tag, cls, text) {
      const node = document.createElement(tag);
      if (cls) node.className = cls;
      if (text != null) node.textContent = text;
      return node;
    }

    function raise(node) {
      if (window.lookingGlassWindows) {
        window.lookingGlassWindows.raise(node);
        return;
      }
      z += 1;
      node.style.zIndex = String(z);
    }

    function closeServices() {
      if (window.lookingGlassWindows) window.lookingGlassWindows.detach(WIN_ID);
      if (pop) pop.remove();
      pop = null;
      inner = null;
    }

    function lockPopSize(node, opts) {
      const rect = node.getBoundingClientRect();
      if ((!opts || opts.width !== false) && rect.width) node.style.width = rect.width + "px";
      if ((!opts || opts.height !== false) && rect.height) node.style.height = rect.height + "px";
    }

    function makeDraggable(node) {
      if (window.lookingGlassWindows) return;
      const bar = node.querySelector(".inspect-pop-bar");
      if (!bar) return;
      let startX = 0, startY = 0, origX = 0, origY = 0;
      bar.addEventListener("pointerdown", (event) => {
        if (event.target.closest("button, a, input, select, textarea, label, .inspect-pop-actions")) return;
        if (event.button != null && event.button !== 0) return;
        event.preventDefault();
        raise(node);
        bar.setPointerCapture(event.pointerId);
        startX = event.clientX;
        startY = event.clientY;
        const rect = node.getBoundingClientRect();
        origX = rect.left + window.scrollX;
        origY = rect.top + window.scrollY;
      });
      bar.addEventListener("pointermove", (event) => {
        if (!bar.hasPointerCapture(event.pointerId)) return;
        node.style.left = Math.max(8, origX + event.clientX - startX) + "px";
        node.style.top = Math.max(8, origY + event.clientY - startY) + "px";
      });
    }

    function formatDuration(seconds) {
      if (typeof window.lookingGlassFormatDuration === "function") {
        return window.lookingGlassFormatDuration(seconds);
      }
      if (seconds == null || !Number.isFinite(Number(seconds))) return "";
      let s = Math.max(0, Math.floor(Number(seconds)));
      const days = Math.floor(s / 86400);
      s %= 86400;
      const hours = Math.floor(s / 3600);
      s %= 3600;
      const minutes = Math.floor(s / 60);
      const parts = [];
      if (days) parts.push(days + "d");
      if (hours || days) parts.push(hours + "h");
      parts.push(minutes + "m");
      return parts.join(" ");
    }

    function formatList(value) {
      if (Array.isArray(value)) return value.filter((item) => item != null && item !== "").map(String).join(" ");
      if (value == null || value === "") return "";
      return String(value);
    }

    function formatDn(value) {
      if (value == null || value === "") return "";
      if (typeof value === "string") return value;
      if (typeof value !== "object" || Array.isArray(value)) return "";
      const keys = [
        ["commonName", "CN"],
        ["organizationName", "O"],
        ["organizationalUnitName", "OU"],
        ["localityName", "L"],
        ["stateOrProvinceName", "ST"],
        ["countryName", "C"],
      ];
      const parts = [];
      keys.forEach(([key, short]) => {
        const text = value[key];
        if (text) parts.push(short + "=" + text);
      });
      return parts.join(", ");
    }

    function formatBool(value) {
      return value ? t("gui.services.yes", "yes") : t("gui.services.no", "no");
    }

    function formatStarted(ts) {
      const n = Number(ts);
      if (!Number.isFinite(n) || n <= 0) return "";
      const d = new Date(n * 1000);
      if (Number.isNaN(d.getTime())) return "";
      return d.toISOString().replace("T", " ").slice(0, 19) + " UTC";
    }

    function addRow(dl, key, value, cls) {
      if (value == null || value === "") return;
      if (typeof value === "object") return;
      dl.append(el("dt", "", key), el("dd", cls || "", String(value)));
    }

    function intelState(blob) {
      if (blob && blob.ready) return [t("gui.services.up", "up"), "ok"];
      if (blob && blob.running) return [t("gui.services.building", "building"), "warn"];
      return [t("gui.services.down", "down"), "bad"];
    }

    function tlsState(blob) {
      if (blob && blob.running) return [t("gui.services.up", "up"), "ok"];
      if (blob && blob.enabled === false) return [t("gui.services.disabled", "disabled"), ""];
      return [t("gui.services.down", "down"), "bad"];
    }

    function paintCard(title, stateWord, stateCls, rows) {
      const card = document.createElement("fieldset");
      card.className = "services-card";
      const legend = document.createElement("legend");
      legend.append(title + "  ");
      legend.append(el("span", stateCls, stateWord));
      card.append(legend);
      const dl = el("dl", "services-kv");
      rows.forEach((row) => addRow(dl, row[0], row[1], row[2]));
      card.append(dl);
      return card;
    }

    function paintServices(data) {
      if (!inner) return;
      inner.replaceChildren();
      if (!data) {
        inner.append(el("p", "hint", t("gui.cache.loading", "Loading…")));
        return;
      }
      const hostBits = [];
      if (data.hostname) hostBits.push(data.hostname);
      const up = formatDuration(data.uptime);
      if (up) hostBits.push(t("gui.services.system", "system") + " " + up);
      if (Array.isArray(data.load) && data.load.length) {
        hostBits.push(t("gui.services.load", "load") + " " + data.load.map((n) => Number(n).toFixed(2)).join(" "));
      }
      if (data.mode) hostBits.push(String(data.mode).toUpperCase());
      if (hostBits.length) inner.append(el("p", "services-host", hostBits.join("  ·  ")));
      const grid = el("div", "services-grid");
      const serve = data.serve || {};
      const [intelWord, intelCls] = intelState(serve);
      grid.append(paintCard(t("gui.services.intel", "intel"), intelWord, intelCls, [
        [t("gui.services.state", "state"), intelWord, intelCls],
        [t("gui.services.service", "service"), formatDuration(serve.uptime)],
        [t("gui.services.pid", "pid"), serve.pid],
        [t("gui.services.ready", "ready"), serve.running ? formatBool(!!serve.ready) : ""],
        [t("gui.services.started", "started"), formatStarted(serve.started_at)],
        [t("gui.services.stale", "stale pidfile"), serve.stale ? formatBool(true) : ""],
        [t("gui.services.socket", "socket"), serve.socket],
        [t("gui.services.data", "data"), serve.data],
      ]));
      const https = data.https || {};
      const [tlsWord, tlsCls] = tlsState(https);
      const days = https.days_left;
      const daysText = days == null || days === "" ? "" : (Number.isFinite(Number(days)) ? Math.trunc(Number(days)) + "d" : String(days));
      grid.append(paintCard(t("gui.services.tls", "tls"), tlsWord, tlsCls, [
        [t("gui.services.state", "state"), tlsWord, tlsCls],
        [t("gui.services.service", "service"), formatDuration(https.uptime)],
        [t("gui.services.pid", "pid"), https.pid],
        [t("gui.services.enabled", "enabled"), "enabled" in https ? formatBool(!!https.enabled) : ""],
        [t("gui.services.hostname", "hostname"), https.hostname],
        [t("gui.services.port", "port"), https.port],
        [t("gui.services.bind", "bind"), https.bind],
        [t("gui.services.listen", "listen"), formatList(https.listen)],
        [t("gui.services.workers", "workers"), https.workers],
        [t("gui.services.staging", "staging"), "staging" in https ? formatBool(!!https.staging) : ""],
        [t("gui.services.issue", "needs issue"), "needs_issue" in https ? formatBool(!!https.needs_issue) : ""],
        [t("gui.services.days_left", "days left"), daysText],
        [t("gui.services.subject", "subject"), formatDn(https.subject)],
        [t("gui.services.issuer", "issuer"), formatDn(https.issuer)],
        [t("gui.services.san", "SAN"), formatList(https.san)],
        [t("gui.services.cert", "certificate"), https.fullchain],
        [t("gui.services.started", "started"), formatStarted(https.started_at)],
      ]));
      inner.append(grid);
    }

    function loadServices() {
      if (window.lookingGlassStatus) paintServices(window.lookingGlassStatus);
      fetch("/status", {
        cache: "no-store",
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      }).then((res) => {
        if (!res.ok) throw new Error("status");
        return res.json();
      }).then((data) => {
        window.lookingGlassStatus = data;
        paintServices(data);
      }).catch((err) => {
        if (!inner) return;
        inner.replaceChildren(el("p", "hint", String(err.message || err)));
      });
    }

    function onStatusEvent(event) {
      if (!pop || !inner) return;
      paintServices(event.detail || window.lookingGlassStatus);
    }

    function openServices(anchor) {
      if (pop && window.lookingGlassWindows && window.lookingGlassWindows.front(WIN_ID)) {
        loadServices();
        return;
      }
      if (pop && !window.lookingGlassWindows && document.body.contains(pop)) {
        raise(pop);
        loadServices();
        return;
      }
      if (pop) {
        try { pop.remove(); } catch (err) {}
        pop = null;
        inner = null;
      }
      pop = el("div", "asn-pop inspect-pop services-pop");
      pop.setAttribute("role", "dialog");
      pop.setAttribute("aria-labelledby", "services-title");
      const bar = el("div", "inspect-pop-bar");
      bar.append(el("strong", "inspect-pop-title", t("gui.services.title", "Services")));
      bar.lastChild.id = "services-title";
      const close = el("button", "inspect-pop-close", "×");
      close.type = "button";
      close.setAttribute("aria-label", t("gui.close", "Close"));
      close.addEventListener("click", (event) => {
        event.preventDefault();
        closeServices();
      });
      bar.append(close);
      const body = el("div", "inspect-pop-body");
      inner = el("div", "services-inner");
      inner.append(el("p", "hint", t("gui.cache.loading", "Loading…")));
      body.append(inner);
      pop.append(bar, body);
      document.body.append(pop);
      const rect = anchor && anchor.getBoundingClientRect ? anchor.getBoundingClientRect() : { left: 24, bottom: 48 };
      pop.style.left = Math.max(8, rect.left + window.scrollX) + "px";
      pop.style.top = Math.max(8, window.scrollY + 48) + "px";
      if (window.lookingGlassWindows && window.lookingGlassWindows.place) window.lookingGlassWindows.place(pop, anchor || servicesBtn);
      makeDraggable(pop);
      lockPopSize(pop, { width: false });
      if (window.lookingGlassWindows) {
        window.lookingGlassWindows.adopt(pop, {
          id: WIN_ID,
          kind: "services",
          title: t("gui.services.title", "Services"),
          onClose: closeServices,
          onRefresh: loadServices,
        });
      } else {
        raise(pop);
      }
      loadServices();
    }

    servicesBtn.addEventListener("click", () => openServices(servicesBtn));
    document.addEventListener("looking-glass-status", onStatusEvent);
    if (window.lookingGlassWindows) {
      window.lookingGlassWindows.register("services", function () {
        openServices();
      });
    }
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && pop && !pop.classList.contains("is-minimized")) closeServices();
    });
  })();
