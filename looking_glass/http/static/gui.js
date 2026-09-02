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
    if (window.lookingGlassWindows) return;

    const KEY = "looking-glass.windows.v1";
    const BAR_CONTROL = "button, a, input, select, textarea, label, .inspect-pop-actions";
    const BASE_Z = 200;
    let z = BASE_Z;
    let restoring = false;
    const entries = new Map();
    const factories = {};
    let pending = null;

    function t(id, fallback) {
      return window.t ? window.t(id, fallback) : (fallback || id);
    }

    try {
      pending = JSON.parse(sessionStorage.getItem(KEY) || "null");
      if (pending && Number(pending.z) > z) z = Number(pending.z);
    } catch (err) {
      pending = null;
    }

    function persist() {
      if (restoring) return;
      const wins = [];
      for (const e of entries.values()) {
        if (e.kind === "hist-detail" || e.kind === "compare") continue;
        wins.push({
          id: e.id,
          kind: e.kind,
          title: e.title,
          meta: e.meta || {},
          minimized: !!e.minimized,
          maximized: e.node.classList.contains("is-maximized"),
          left: e.node.style.left || "",
          top: e.node.style.top || "",
          width: e.node.style.width || "",
          height: e.node.style.height || "",
        });
      }
      try {
        sessionStorage.setItem(KEY, JSON.stringify({ z, wins }));
      } catch (err) {}
    }

    function dock() {
      return document.getElementById("status-wins");
    }

    function stackKey(entry) {
      if (entry.kind === "logs" || entry.kind === "cache") return entry.kind;
      const meta = entry.meta || {};
      if (meta.reopen === "tool" && meta.kind) return "inspect:" + meta.kind;
      if (meta.reopen === "asn") return "inspect:asn";
      if (meta.reopen === "picker") return "inspect:picker";
      return entry.kind || "inspect";
    }

    function winChrome(entry, extraClass) {
      const row = document.createElement("div");
      row.className = extraClass ? "status-win " + extraClass : "status-win";
      const title = document.createElement("button");
      title.type = "button";
      title.className = "status-win-title";
      title.textContent = entry.title;
      title.title = entry.title;
      title.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        restore(entry.id);
      });
      const max = document.createElement("button");
      max.type = "button";
      max.className = "status-win-max";
      max.setAttribute("aria-label", t("gui.maximize", "Maximize"));
      max.title = t("gui.maximize", "Maximize");
      max.textContent = "□";
      max.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        restore(entry.id);
      });
      const close = document.createElement("button");
      close.type = "button";
      close.className = "status-win-close";
      close.setAttribute("aria-label", t("gui.close", "Close"));
      close.title = t("gui.close", "Close");
      close.textContent = "×";
      close.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        closeWin(entry.id);
      });
      row.addEventListener("click", (event) => {
        if (event.target.closest(".status-win-max, .status-win-close")) return;
        event.preventDefault();
        restore(entry.id);
      });
      row.append(title, max, close);
      return row;
    }

    function paintDock() {
      const host = dock();
      if (!host) return;
      host.replaceChildren();
      const groups = [];
      const index = new Map();
      for (const entry of entries.values()) {
        if (!entry.minimized) continue;
        const key = stackKey(entry);
        if (!index.has(key)) {
          index.set(key, groups.length);
          groups.push({ key, items: [] });
        }
        groups[index.get(key)].items.push(entry);
      }
      for (const group of groups) {
        const items = group.items;
        const top = items[items.length - 1];
        const stack = document.createElement("div");
        stack.className = "status-win-stack" + (items.length > 1 ? " is-many" : "");
        const face = winChrome(top, "status-win-face");
        const title = face.querySelector(".status-win-title");
        if (items.length > 1 && title) {
          title.textContent = top.title + " · " + items.length;
          title.title = items.map((item) => item.title).join("\n");
          face.title = title.title;
          const menu = document.createElement("div");
          menu.className = "status-win-menu";
          for (let i = items.length - 1; i >= 0; i -= 1) {
            menu.append(winChrome(items[i]));
          }
          stack.append(menu);
        }
        stack.append(face);
        host.append(stack);
      }
    }

    function raise(node) {
      if (!node) return;
      z += 1;
      node.style.zIndex = String(z);
      persist();
    }

    function geomPx(value) {
      const n = parseFloat(value);
      if (!Number.isFinite(n) || n <= 0) return 0;
      if (String(value).indexOf("rem") >= 0) return n * 16;
      return n;
    }

    function applyGeom(node, state) {
      if (!node || !state) return;
      if (state.left) node.style.left = state.left;
      if (state.top) node.style.top = state.top;
      const config = (node.classList && node.classList.contains("config-pop")) || state.kind === "config";
      const tiny = config && geomPx(state.width) > 0 && geomPx(state.width) < 640;
      if (state.width && !tiny) node.style.width = state.width;
      if (state.height && !tiny) node.style.height = state.height;
    }

    const GAP = 8;
    const CHROME_FALLBACK = 36;

    function chromeTop() {
      const head = document.querySelector(".site-head");
      if (head) {
        const r = head.getBoundingClientRect();
        if (r.height > 0) return Math.ceil(r.bottom);
      }
      return CHROME_FALLBACK;
    }

    function chromeBottom() {
      const bar = document.querySelector(".status-bar");
      if (bar) {
        const r = bar.getBoundingClientRect();
        if (r.height > 0) return Math.ceil(window.innerHeight - r.top);
      }
      return CHROME_FALLBACK;
    }

    function syncMaxChrome(node) {
      if (!node) return;
      const max = node.querySelector(".inspect-pop-max");
      if (max) max.setAttribute("aria-pressed", node.classList.contains("is-maximized") ? "true" : "false");
    }

    function applyMaximized(node, entry, saved) {
      const on = !!(saved && saved.maximized);
      if (on) {
        if (!entry._preMax) {
          entry._preMax = {
            left: node.style.left || "",
            top: node.style.top || "",
            width: node.style.width || "",
            height: node.style.height || "",
          };
        }
        node.classList.add("is-maximized");
      } else {
        node.classList.remove("is-maximized");
      }
      syncMaxChrome(node);
    }

    function overlapArea(a, b) {
      const x = Math.max(0, Math.min(a.right, b.right) - Math.max(a.left, b.left));
      const y = Math.max(0, Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top));
      return x * y;
    }

    function asRect(left, top, w, h) {
      return { left, top, right: left + w, bottom: top + h, width: w, height: h };
    }

    function inflate(r, g) {
      return { left: r.left - g, top: r.top - g, right: r.right + g, bottom: r.bottom + g };
    }

    function visiblePops(except) {
      return Array.from(document.querySelectorAll(".inspect-pop")).filter((n) => {
        if (n === except) return false;
        if (n.classList.contains("is-minimized")) return false;
        if (n.classList.contains("wall-menu")) return false;
        const r = n.getBoundingClientRect();
        return r.width > 0 && r.height > 0;
      });
    }

    function otherRects(except) {
      return visiblePops(except).map((n) => n.getBoundingClientRect());
    }

    function totalOverlap(rect, others, gap) {
      let sum = 0;
      for (const o of others) sum += overlapArea(rect, gap ? inflate(o, gap) : o);
      return sum;
    }

    function clampView(left, top, w, h) {
      const insetT = chromeTop() + GAP;
      const insetB = chromeBottom() + GAP;
      const maxL = Math.max(GAP, window.innerWidth - w - GAP);
      const maxT = Math.max(insetT, window.innerHeight - h - insetB);
      return {
        left: Math.min(Math.max(GAP, left), maxL),
        top: Math.min(Math.max(insetT, top), maxT),
      };
    }

    function applyView(node, view) {
      node.style.left = view.left + window.scrollX + "px";
      node.style.top = view.top + window.scrollY + "px";
    }

    function sourcePop(anchor) {
      if (!anchor || typeof anchor.closest !== "function") return null;
      const pop = anchor.closest(".inspect-pop");
      if (!pop || pop.classList.contains("wall-menu")) return null;
      return pop;
    }

    function sourceRect(anchor) {
      const pop = sourcePop(anchor);
      if (pop) return pop.getBoundingClientRect();
      if (anchor && typeof anchor.getBoundingClientRect === "function") {
        return anchor.getBoundingClientRect();
      }
      return asRect(24, 48, 136, 32);
    }

    function barHeight(pop) {
      if (pop && pop.querySelector) {
        const bar = pop.querySelector(".inspect-pop-bar");
        if (bar) {
          const h = bar.getBoundingClientRect().height;
          if (h > 0) return h;
        }
      }
      return 36;
    }

    function slotsAround(src, w, h) {
      return [
        { left: src.right + GAP, top: src.top },
        { left: src.left, top: src.bottom + GAP },
        { left: src.left - GAP - w, top: src.top },
        { left: src.left, top: src.top - GAP - h },
      ];
    }

    function uncoverBar(left, top, w, h, src, barH) {
      const bar = asRect(src.left, src.top, src.width, barH);
      const cand = asRect(left, top, w, h);
      if (overlapArea(cand, bar) <= 0) return { left, top };
      return { left, top: src.top + barH + GAP };
    }

    function place(node, anchor) {
      if (!node || restoring) return;
      const box = node.getBoundingClientRect();
      const w = box.width || node.offsetWidth || 320;
      const h = box.height || node.offsetHeight || 240;
      const others = otherRects(node);
      const srcPop = sourcePop(anchor);
      const src = sourceRect(anchor);
      const current = clampView(box.left, box.top, w, h);
      const hasPos = !!(node.style.left || node.style.top);
      if (hasPos && totalOverlap(asRect(current.left, current.top, w, h), others, GAP) <= 0) {
        applyView(node, current);
        return;
      }
      const candidates = [];
      for (const slot of slotsAround(src, w, h)) candidates.push(slot);
      for (const o of others) {
        for (const slot of slotsAround(o, w, h)) candidates.push(slot);
      }
      let best = null;
      let bestOv = Infinity;
      let bestFree = null;
      for (const slot of candidates) {
        const c = clampView(slot.left, slot.top, w, h);
        const ov = totalOverlap(asRect(c.left, c.top, w, h), others, GAP);
        if (ov <= 0 && !bestFree) bestFree = c;
        if (ov < bestOv) {
          bestOv = ov;
          best = c;
        }
      }
      let chosen = bestFree || best || current;
      if (srcPop) {
        const open = uncoverBar(chosen.left, chosen.top, w, h, src, barHeight(srcPop));
        const clamped = clampView(open.left, open.top, w, h);
        const bar = asRect(src.left, src.top, src.width, barHeight(srcPop));
        if (overlapArea(asRect(clamped.left, clamped.top, w, h), bar) > 0) {
          chosen = { left: clamped.left, top: Math.min(open.top, Math.max(chromeTop() + GAP, window.innerHeight - h - chromeBottom() - GAP)) };
          if (overlapArea(asRect(chosen.left, chosen.top, w, h), bar) > 0) {
            chosen = { left: chosen.left, top: src.top + barHeight(srcPop) + GAP };
          }
        } else {
          chosen = clamped;
        }
      }
      applyView(node, chosen);
    }

    function nudge(node) {
      if (!node || restoring) return;
      const a = node.getBoundingClientRect();
      const area = a.width * a.height;
      if (area <= 0) return;
      let worst = null;
      let worstOv = 0;
      for (const other of visiblePops(node)) {
        const b = other.getBoundingClientRect();
        const ov = overlapArea(a, b);
        if (ov > worstOv) {
          worstOv = ov;
          worst = b;
        }
      }
      if (!worst || worstOv <= area * 0.5) return;
      const opts = [
        { left: worst.right + GAP, top: a.top },
        { left: worst.left - GAP - a.width, top: a.top },
        { left: a.left, top: worst.bottom + GAP },
        { left: a.left, top: worst.top - GAP - a.height },
      ];
      let best = null;
      let bestD = Infinity;
      for (const o of opts) {
        const c = clampView(o.left, o.top, a.width, a.height);
        const d = Math.hypot(c.left - a.left, c.top - a.top);
        if (d < bestD) {
          bestD = d;
          best = c;
        }
      }
      if (best) applyView(node, best);
    }

    function unconstrainedWidth(el) {
      if (!el) return 0;
      const s = el.style;
      const prev = { width: s.width, minWidth: s.minWidth, maxWidth: s.maxWidth };
      s.width = "max-content";
      s.minWidth = "max-content";
      s.maxWidth = "none";
      const w = Math.ceil(Math.max(el.scrollWidth || 0, el.getBoundingClientRect().width || 0));
      s.width = prev.width;
      s.minWidth = prev.minWidth;
      s.maxWidth = prev.maxWidth;
      return w;
    }

    function contentWidth(root) {
      if (!root) return 0;
      let need = 0;
      root.querySelectorAll(
        "table, pre, .inspect, .probe, .howto, .apex, .register, .compare-cols, .compare-wrap, .sec-graph, .inspect-with-history"
      ).forEach((node) => {
        need = Math.max(need, unconstrainedWidth(node));
      });
      if (!need) need = unconstrainedWidth(root);
      return need;
    }

    function fit(node) {
      if (!node || node.classList.contains("wall-menu") || node.classList.contains("is-maximized")) return;
      const body = node.querySelector(".inspect-pop-body") || node;
      const need = contentWidth(body);
      if (!need) return;
      const chrome = Math.max(0, node.clientWidth - body.clientWidth);
      const want = Math.ceil(need + chrome + GAP);
      const max = Math.max(GAP, window.innerWidth - GAP * 2);
      const cur = node.getBoundingClientRect().width;
      const width = Math.max(cur, Math.min(max, want));
      if (width <= cur + 1) return;
      node.style.width = width + "px";
      const box = node.getBoundingClientRect();
      if (box.left + width > window.innerWidth - GAP) {
        node.style.left = Math.max(GAP, window.innerWidth - width - GAP) + window.scrollX + "px";
      }
      persist();
    }

    function ensureChrome(node, id) {
      const bar = node.querySelector(".inspect-pop-bar");
      if (!bar) return;
      let actions = bar.querySelector(".inspect-pop-actions");
      const close = bar.querySelector(".inspect-pop-close");
      if (!actions && close) {
        const parent = close.parentElement;
        if (parent && parent !== bar) {
          parent.classList.add("inspect-pop-actions");
          actions = parent;
        } else {
          actions = document.createElement("span");
          actions.className = "inspect-pop-actions";
          close.replaceWith(actions);
          actions.append(close);
        }
      }
      if (!actions) {
        actions = document.createElement("span");
        actions.className = "inspect-pop-actions";
        bar.append(actions);
      }
      const entry = entries.get(id);
      const closeBtn = actions.querySelector(".inspect-pop-close");
      if (entry && typeof entry.onRefresh === "function" && !actions.querySelector(".inspect-pop-refresh")) {
        const refresh = document.createElement("button");
        refresh.type = "button";
        refresh.className = "inspect-pop-refresh";
        refresh.setAttribute("aria-label", t("gui.refresh", "Refresh"));
        refresh.title = t("gui.refresh", "Refresh");
        refresh.textContent = "↻";
        refresh.addEventListener("click", (event) => {
          event.preventDefault();
          event.stopPropagation();
          try { entry.onRefresh(); } catch (err) {}
        });
        const minBtn = actions.querySelector(".inspect-pop-min");
        if (minBtn) minBtn.before(refresh);
        else if (closeBtn) closeBtn.before(refresh);
        else actions.append(refresh);
      }
      if (!actions.querySelector(".inspect-pop-min")) {
        const min = document.createElement("button");
        min.type = "button";
        min.className = "inspect-pop-min";
        min.setAttribute("aria-label", t("gui.minimize", "Minimize"));
        min.textContent = "–";
        min.addEventListener("click", (event) => {
          event.preventDefault();
          event.stopPropagation();
          minimize(id);
        });
        if (closeBtn) closeBtn.before(min);
        else actions.append(min);
      }
      if (!actions.querySelector(".inspect-pop-max")) {
        const max = document.createElement("button");
        max.type = "button";
        max.className = "inspect-pop-max";
        max.setAttribute("aria-label", t("gui.maximize", "Maximize"));
        max.title = t("gui.maximize", "Maximize");
        max.setAttribute("aria-pressed", node.classList.contains("is-maximized") ? "true" : "false");
        max.textContent = "□";
        max.addEventListener("click", (event) => {
          event.preventDefault();
          event.stopPropagation();
          toggleMax(id);
        });
        if (actions.querySelector(".inspect-pop-close")) actions.querySelector(".inspect-pop-close").before(max);
        else actions.append(max);
      }
    }

    function makeDraggable(node) {
      const bar = node.querySelector(".inspect-pop-bar");
      if (!bar || bar.dataset.winDrag === "1") return;
      bar.dataset.winDrag = "1";
      let startX = 0, startY = 0, origX = 0, origY = 0, moved = false;
      bar.addEventListener("pointerdown", (event) => {
        if (node.classList.contains("is-maximized")) return;
        if (event.target.closest(BAR_CONTROL)) return;
        if (event.button != null && event.button !== 0) return;
        event.preventDefault();
        raise(node);
        bar.setPointerCapture(event.pointerId);
        moved = false;
        startX = event.clientX;
        startY = event.clientY;
        const rect = node.getBoundingClientRect();
        origX = rect.left + window.scrollX;
        origY = rect.top + window.scrollY;
      });
      bar.addEventListener("pointermove", (event) => {
        if (node.classList.contains("is-maximized")) return;
        if (!bar.hasPointerCapture(event.pointerId)) return;
        if (Math.abs(event.clientX - startX) + Math.abs(event.clientY - startY) > 2) moved = true;
        node.style.left = Math.max(GAP, origX + event.clientX - startX) + "px";
        node.style.top = Math.max(chromeTop() + GAP, origY + event.clientY - startY) + "px";
      });
      bar.addEventListener("pointerup", () => {
        if (moved) nudge(node);
        persist();
      });
    }

    function adopt(node, spec) {
      if (!node || !spec || !spec.id) return;
      const prev = entries.get(spec.id);
      if (prev && prev.node !== node) prev.node.remove();
      const entry = {
        id: spec.id,
        kind: spec.kind || spec.id,
        title: spec.title || spec.id,
        meta: spec.meta || {},
        onClose: typeof spec.onClose === "function" ? spec.onClose : null,
        onRefresh: typeof spec.onRefresh === "function" ? spec.onRefresh : null,
        node,
        minimized: false,
      };
      entries.set(spec.id, entry);
      node.dataset.winId = spec.id;
      node.classList.remove("is-minimized");
      if (node._raiseHandler) node.removeEventListener("pointerdown", node._raiseHandler);
      node._raiseHandler = function () { raise(node); };
      node.addEventListener("pointerdown", node._raiseHandler);
      node.addEventListener("pointerup", persist);
      ensureChrome(node, spec.id);
      makeDraggable(node);
      raise(node);
      paintDock();
      persist();
      return entry;
    }

    function minimize(id) {
      const e = entries.get(id);
      if (!e) return;
      e.minimized = true;
      e.node.classList.add("is-minimized");
      paintDock();
      persist();
    }

    function restore(id) {
      const e = entries.get(id);
      if (!e) return;
      e.minimized = false;
      e.node.classList.remove("is-minimized");
      raise(e.node);
      paintDock();
      persist();
    }

    function toggleMax(id) {
      const e = entries.get(id);
      if (!e || !e.node) return;
      const node = e.node;
      if (node.classList.contains("is-maximized")) {
        node.classList.remove("is-maximized");
        const pre = e._preMax || {};
        if (pre.left != null) node.style.left = pre.left;
        if (pre.top != null) node.style.top = pre.top;
        if (pre.width != null) node.style.width = pre.width;
        if (pre.height != null) node.style.height = pre.height;
        e._preMax = null;
      } else {
        e._preMax = {
          left: node.style.left || "",
          top: node.style.top || "",
          width: node.style.width || "",
          height: node.style.height || "",
        };
        node.classList.add("is-maximized");
      }
      syncMaxChrome(node);
      persist();
    }

    function front(id) {
      const e = entries.get(id);
      if (!e || !e.node || !document.body.contains(e.node)) {
        if (e) {
          entries.delete(id);
          paintDock();
          persist();
        }
        return false;
      }
      if (e.minimized) restore(id);
      else raise(e.node);
      return true;
    }

    function closeWin(id) {
      const e = entries.get(id);
      if (!e) return;
      const fn = e.onClose;
      entries.delete(id);
      paintDock();
      persist();
      if (typeof fn === "function") {
        try { fn(); } catch (err) {}
        return;
      }
      if (e.node && e.node.remove) e.node.remove();
    }

    function detach(id) {
      const e = entries.get(id);
      if (!e) return;
      entries.delete(id);
      paintDock();
      persist();
    }

    function top() {
      let best = null;
      let bestZ = -1;
      for (const e of entries.values()) {
        if (e.minimized) continue;
        const n = Number(e.node.style.zIndex || 0);
        if (n >= bestZ) {
          bestZ = n;
          best = e.node;
        }
      }
      return best;
    }

    function flushRestore() {
      if (!pending || !Array.isArray(pending.wins) || !pending.wins.length) {
        pending = null;
        return;
      }
      restoring = true;
      const leftover = [];
      for (const win of pending.wins) {
        if (entries.has(win.id)) {
          const e = entries.get(win.id);
          applyGeom(e.node, win);
          applyMaximized(e.node, e, win);
          if (win.minimized) minimize(win.id);
          else restore(win.id);
          continue;
        }
        const fn = factories[win.kind];
        if (!fn) {
          leftover.push(win);
          continue;
        }
        try {
          fn(win);
        } catch (err) {
          leftover.push(win);
          continue;
        }
        const e = entries.get(win.id);
        if (!e) {
          leftover.push(win);
          continue;
        }
        applyGeom(e.node, win);
        applyMaximized(e.node, e, win);
        if (win.minimized) minimize(win.id);
      }
      pending = leftover.length ? { z, wins: leftover } : null;
      restoring = false;
      paintDock();
      if (!pending) persist();
    }

    function register(kind, factory) {
      factories[kind] = factory;
      flushRestore();
    }

    window.addEventListener("pagehide", persist);
    window.addEventListener("beforeunload", persist);
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", function () {
        paintDock();
        flushRestore();
      });
    } else {
      paintDock();
    }

    function popConfirm(host, copy, opts) {
      opts = opts || {};
      return new Promise(function (resolve) {
        if (!host) {
          resolve(false);
          return;
        }
        const existing = host.querySelector(".pop-confirm");
        if (existing) {
          if (typeof existing._popCancel === "function") existing._popCancel();
          else existing.remove();
        }
        const previous = document.activeElement;
        const panel = document.createElement("div");
        panel.className = "pop-confirm";
        panel.setAttribute("role", "alertdialog");
        panel.setAttribute("aria-modal", "true");
        const copyId = "pop-confirm-copy-" + String(Date.now());
        const p = document.createElement("p");
        p.className = "pop-confirm-copy";
        p.id = copyId;
        p.textContent = copy || "";
        const actions = document.createElement("div");
        actions.className = "pop-confirm-actions";
        const cancelBtn = document.createElement("button");
        cancelBtn.type = "button";
        cancelBtn.className = "ghost pop-confirm-cancel";
        cancelBtn.textContent = t("gui.cancel", "Cancel");
        const okBtn = document.createElement("button");
        okBtn.type = "button";
        okBtn.className = "go pop-confirm-ok";
        okBtn.textContent = opts.okLabel || t("gui.ok", "OK");
        actions.append(cancelBtn, okBtn);
        panel.append(p, actions);
        panel.setAttribute("aria-describedby", copyId);
        let done = false;
        function finish(ok) {
          if (done) return;
          done = true;
          document.removeEventListener("keydown", onKey, true);
          panel.remove();
          if (previous && typeof previous.focus === "function") {
            try { previous.focus(); } catch (err) {}
          }
          resolve(!!ok);
        }
        function onKey(event) {
          if (!panel.isConnected) return;
          if (event.key === "Escape") {
            event.preventDefault();
            event.stopPropagation();
            finish(false);
            return;
          }
          if (event.key !== "Tab") return;
          const first = cancelBtn;
          const last = okBtn;
          if (event.shiftKey && document.activeElement === first) {
            event.preventDefault();
            last.focus();
          } else if (!event.shiftKey && document.activeElement === last) {
            event.preventDefault();
            first.focus();
          }
        }
        panel._popCancel = function () { finish(false); };
        okBtn.addEventListener("click", function () { finish(true); });
        cancelBtn.addEventListener("click", function () { finish(false); });
        document.addEventListener("keydown", onKey, true);
        host.append(panel);
        okBtn.focus();
      });
    }

    window.lookingGlassPopConfirm = popConfirm;

    window.lookingGlassWindows = {
      raise,
      adopt,
      minimize,
      restore,
      front,
      close: closeWin,
      detach,
      top,
      register,
      persist,
      applyGeom,
      place,
      nudge,
      fit,
      contentWidth,
    };
  })();


(function () {
  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }

  function setSafeHref(node, url) {
    const href = typeof window.safeHref === "function" ? window.safeHref(url) : "";
    if (href) node.setAttribute("href", href);
    else node.removeAttribute("href");
  }

  function inspectBtn(kind, value, cls, label) {
    const btn = el("button", cls, label == null ? String(value) : label);
    btn.type = "button";
    if (kind === "asn") btn.dataset.asn = String(value);
    else if (kind === "ip") btn.dataset.ip = String(value);
    else btn.dataset.domain = String(value).replace(/\.$/, "");
    return btn;
  }

  function renderRegistration(payload, rdap, kicker) {
    payload = payload || {};
    rdap = rdap || {};
    const result = payload.result || {};
    const dnssec = rdap.dnssec || {};
    const dates = rdap.dates || {};
    const registrar = rdap.registrar || {};
    const nsRows = rdap.nameserver_details || [];
    const wrap = el("div", "apex inspect");
    const hero = el("div", "apex-hero");
    const left = document.createElement("div");
    left.append(el("p", "apex-kicker", kicker || window.t("rdap.kicker_asn")));
    const title = payload.kind === "asn"
      ? `AS${result.asn || payload.query || ""}`
      : (rdap.unicode_name || rdap.name || rdap.query || payload.query || "—");
    left.append(el("h2", "apex-domain", title));
    const subBits = rdap.timeline
      ? [rdap.timeline]
      : [rdap.name, rdap.type, rdap.country, rdap.handle].filter(Boolean);
    left.append(el("p", "apex-sub", subBits.join(" · ") || "—"));
    const counts = el("div", "apex-counts");
    const addChip = (strong, label, cls) => {
      const chip = el("span", `apex-count ${cls || ""}`.trim());
      chip.append(el("strong", "", strong));
      chip.append(document.createTextNode(" " + label));
      counts.append(chip);
    };
    if (dnssec.label && dnssec.label !== "unknown") {
      addChip(dnssec.label, "dnssec", dnssec.signed ? "pass" : "warn");
    } else if (rdap.type === "domain") {
      addChip("unknown", "dnssec");
    }
    if (rdap.registered_age) addChip(rdap.registered_age, "old");
    addChip(String((rdap.nameservers || []).length), "ns");
    addChip(String((rdap.status || []).length), "status");
    hero.append(left, counts);
    wrap.append(hero);

    const kv = (rows) => {
      const dl = el("dl", "inspect-kv");
      for (const [dt, dd] of rows) {
        if (dd == null || dd === "") continue;
        const div = document.createElement("div");
        div.append(el("dt", "", dt));
        const cell = el("dd", "");
        if (dd instanceof Node) cell.append(dd);
        else cell.textContent = String(dd);
        div.append(cell);
        dl.append(div);
      }
      return dl;
    };
    const zone = (heading, nodes, cls) => {
      const card = el("section", `inspect-zone ${cls || ""}`.trim());
      card.append(el("h3", "", heading));
      for (const node of nodes) card.append(node);
      wrap.append(card);
    };
    const bullets = (items) => {
      const ul = el("ul", "inspect-keys");
      for (const item of items) {
        const li = document.createElement("li");
        if (item instanceof Node) li.append(item);
        else li.textContent = String(item);
        ul.append(li);
      }
      return ul;
    };

    const regRows = [
      [window.t("rdap.registrar"), registrar.name ? (registrar.iana_id ? `${registrar.name} (IANA ${registrar.iana_id})` : registrar.name) : null],
      [window.t("rdap.registered"), [dates.registered, rdap.registered_ago].filter(Boolean).join(" · ")],
      [window.t("rdap.expires"), [dates.expires, rdap.expires_in].filter(Boolean).join(" · ")],
      [window.t("rdap.last_changed"), dates.last_changed],
      [window.t("rdap.handle"), rdap.handle],
      [window.t("rdap.object"), rdap.object_class],
      [window.t("rdap.type"), rdap.type_field],
      [window.t("rdap.country"), rdap.country],
      [window.t("rdap.port43"), rdap.port43],
      ["WHOIS server", rdap.server],
    ];
    const regNodes = [kv(regRows)];
    if ((rdap.status || []).length) regNodes.push(el("p", "apex-sub", rdap.status.join(", ")));
    zone(window.t("rdap.registration"), regNodes);

    if (dnssec.present || (dnssec.label && dnssec.label !== "unknown") || (dnssec.ds || []).length) {
      const dnsNodes = [kv([
        [window.t("rdap.status"), dnssec.label || window.t("rdap.unknown")],
        [window.t("rdap.delegation_signed"), dnssec.delegation_signed == null ? null : (dnssec.delegation_signed ? window.t("rdap.yes") : window.t("rdap.no"))],
        [window.t("rdap.zone_signed"), dnssec.zone_signed == null ? null : (dnssec.zone_signed ? window.t("rdap.yes") : window.t("rdap.no"))],
        ["WHOIS", dnssec.raw],
      ])];
      if ((dnssec.ds || []).length) {
        const table = el("table", "dns-rr");
        const thead = document.createElement("thead");
        const hr = document.createElement("tr");
        for (const h of ["key tag", "algorithm", "digest"]) hr.append(el("th", "", h));
        thead.append(hr);
        const tbody = document.createElement("tbody");
        for (const ds of dnssec.ds) {
          const tr = document.createElement("tr");
          tr.append(el("td", "", ds.key_tag || ds.key_tag || "—"));
          const algo = ds.algorithm_name || ds.algorithm || "—";
          const digestType = ds.digest_type_name || ds.digest_type;
          tr.append(el("td", "", digestType ? `${algo} / ${digestType}` : String(algo)));
          tr.append(el("td", "", ds.digest || "—"));
          tbody.append(tr);
        }
        table.append(thead, tbody);
        dnsNodes.push(table);
      }
      const cls = dnssec.signed ? "secure" : (dnssec.signed === false ? "insecure" : "");
      zone(window.t("gui.dnssec.tab"), dnsNodes, cls);
    }

    if (nsRows.length || (rdap.nameservers || []).length) {
      const items = nsRows.length
        ? nsRows.map((ns) => {
            const wrap = document.createElement("span");
            wrap.append(inspectBtn("domain", ns.host, "probe-host", ns.host));
            for (const ip of [...(ns.v4 || ns.v4 || []), ...(ns.v6 || ns.v6 || [])]) {
              wrap.append(document.createTextNode(" · "));
              wrap.append(inspectBtn("ip", ip, "probe-ip", ip));
            }
            return wrap;
          })
        : (rdap.nameservers || []).map((h) => inspectBtn("domain", h, "probe-host", h));
      zone(window.t("inspect.nameservers"), [bullets(items)]);
    }
    if ((rdap.cidr || []).length) zone(window.t("rdap.prefixes"), [bullets(rdap.cidr)]);
    if (rdap.start_address || rdap.end_address) {
      const origin = document.createElement("span");
      (rdap.origin_asns || []).forEach((n, i) => {
        if (i) origin.append(document.createTextNode(", "));
        origin.append(inspectBtn("asn", n, "probe-asn", `AS${n}`));
      });
      zone(window.t("rdap.range"), [kv([
        [window.t("rdap.start"), rdap.start_address ? inspectBtn("ip", rdap.start_address, "probe-ip", rdap.start_address) : null],
        [window.t("rdap.end"), rdap.end_address ? inspectBtn("ip", rdap.end_address, "probe-ip", rdap.end_address) : null],
        [window.t("rdap.parent"), rdap.parent_handle],
        [window.t("rdap.origin_as"), (rdap.origin_asns || []).length ? origin : null],
      ])]);
    }
    if ((rdap.entities || []).length) {
      zone(window.t("rdap.entities"), [bullets(rdap.entities.map((ent) => [
        ent.name || ent.handle,
        (ent.roles || []).join(", "),
        ent.org && ent.org !== ent.name ? ent.org : null,
        ent.email,
        ent.tel,
        ent.address,
      ].filter(Boolean).join(" · ")))]);
    }
    if ((rdap.events || []).length) {
      zone(window.t("rdap.events"), [bullets(rdap.events.map((ev) => `${ev.action || "event"} · ${ev.date_display || ev.date || "—"}`))]);
    }
    if ((rdap.remarks || []).length) {
      zone(window.t("rdap.remarks"), [bullets(rdap.remarks.map((note) => [note.title, note.description].filter(Boolean).join(" · ")))]);
    }
    if (rdap.text) {
      const pre = document.createElement("pre");
      pre.className = "result";
      pre.textContent = rdap.text;
      zone(window.t("rdap.port43_response"), [pre]);
    }
    return wrap;
  }

  window.renderRegistration = renderRegistration;
})();


(function () {
  function encodeToken(value) {
    return encodeURIComponent(value).replace(/%3A/gi, ":").replace(/%2F/gi, "/");
  }

  function httpInspectPath(raw) {
    const text = String(raw || "").trim() || "example.com";
    if (/^https?:\/\//i.test(text)) {
      return "/http?url=" + encodeURIComponent(text);
    }
    let url;
    try {
      const withScheme = /^[a-z][a-z0-9+.-]*:/i.test(text) || text.startsWith("//")
        ? text
        : `https://${text}`;
      url = new URL(withScheme);
    } catch {
      return `/http/${encodeToken(text)}`;
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return `/http/${encodeToken(text)}`;
    }
    let path = `/http/${encodeToken(url.host)}`;
    for (const seg of url.pathname.split("/")) {
      if (!seg) continue;
      path += `/${encodeToken(seg)}`;
    }
    if (url.search) path += encodeURIComponent(url.search);
    if (url.protocol === "http:") path += "?scheme=http";
    return path;
  }

  const INSPECT_TOOLS = [
    { kind: "ip", label: window.t("inspect.ip.label"), group: window.t("gui.group.lookup"), accepts: ["ip"], loading: window.t("inspect.ip.loading") },
    { kind: "rdap", label: window.t("inspect.rdap.label"), group: window.t("gui.group.lookup"), accepts: ["ip", "host"], loading: window.t("inspect.rdap.loading") },
    { kind: "bgp", label: window.t("inspect.bgp.label"), group: window.t("gui.group.lookup"), accepts: ["ip"], loading: window.t("inspect.bgp.loading") },
    { kind: "ptr", label: window.t("inspect.ptr.label"), group: window.t("gui.group.lookup"), accepts: ["ip"], loading: window.t("inspect.ptr.loading") },
    { kind: "reputation", label: window.t("inspect.reputation.label"), group: window.t("gui.group.lookup"), accepts: ["ip", "host"], loading: window.t("inspect.reputation.loading") },
    { kind: "dns", label: window.t("inspect.dns.label"), group: window.t("gui.group.dns"), accepts: ["host"], loading: window.t("inspect.dns.loading") },
    { kind: "dnstrace", label: window.t("inspect.dnstrace.label"), group: window.t("gui.group.dns"), accepts: ["host"], loading: window.t("inspect.dnstrace.loading") },
    { kind: "dnssec", label: window.t("inspect.dnssec.label"), group: window.t("gui.group.dns"), accepts: ["host"], loading: window.t("inspect.dnssec.loading") },
    { kind: "apex", label: window.t("inspect.apex.label"), group: window.t("gui.group.dns"), accepts: ["host"], loading: window.t("inspect.apex.loading") },
    { kind: "register", label: window.t("inspect.register.label"), group: window.t("gui.group.dns"), accepts: ["host"], loading: window.t("inspect.register.loading") },
    { kind: "tls", label: window.t("inspect.tls.label"), group: window.t("gui.group.web"), accepts: ["ip", "host"], loading: window.t("inspect.tls.loading") },
    { kind: "http", label: window.t("inspect.http.label"), group: window.t("gui.group.web"), accepts: ["ip", "host"], loading: window.t("inspect.http.loading") },
    { kind: "mail", label: window.t("inspect.mail.label"), group: window.t("gui.group.mail"), accepts: ["host"], loading: window.t("inspect.mail.loading") },
    { kind: "ping", label: window.t("inspect.ping.label"), group: window.t("gui.group.path"), accepts: ["ip", "host"], loading: window.t("inspect.ping.loading") },
    { kind: "traceroute", label: window.t("inspect.traceroute.label"), group: window.t("gui.group.path"), accepts: ["ip", "host"], loading: window.t("inspect.traceroute.loading") },
    { kind: "mtr", label: window.t("inspect.mtr.label"), group: window.t("gui.group.path"), accepts: ["ip", "host"], loading: window.t("inspect.mtr.loading") },
    { kind: "tcptraceroute", label: window.t("inspect.tcptraceroute.label"), group: window.t("gui.group.path"), accepts: ["ip", "host"], loading: window.t("inspect.tcptraceroute.loading") },
    { kind: "tcp", label: window.t("inspect.tcp.label"), group: window.t("gui.group.path"), accepts: ["ip", "host"], loading: window.t("inspect.tcp.loading") },
    { kind: "pmtu", label: window.t("inspect.pmtu.label"), group: window.t("gui.group.path"), accepts: ["ip", "host"], loading: window.t("inspect.pmtu.loading") },
  ];

  function toolsFor(accept) {
    return INSPECT_TOOLS.filter((tool) => tool.accepts.includes(accept));
  }

  function mtrBoot() {
    try {
      const boot = JSON.parse((document.getElementById("boot") || {}).textContent || "{}");
      const mtr = (boot && boot.mtr) || {};
      const def = parseInt(mtr.cycles, 10);
      const cap = parseInt(mtr.max_cycles, 10);
      return {
        cycles: Number.isFinite(def) && def >= 1 ? def : 10,
        max_cycles: Number.isFinite(cap) && cap >= 1 ? Math.min(cap, 50) : 30,
      };
    } catch (err) {
      return { cycles: 10, max_cycles: 30 };
    }
  }

  function mtrCyclesQuery(raw) {
    const text = String(raw == null ? "" : raw).trim();
    if (!text) return null;
    const n = parseInt(text, 10);
    if (!Number.isFinite(n)) return null;
    const cap = Math.max(1, mtrBoot().max_cycles);
    return String(Math.max(1, Math.min(n, cap)));
  }

  function splitTlsHostPort(value, defaultPort) {
    defaultPort = defaultPort || "443";
    const text = String(value || "").trim();
    if (!text) return { host: text, port: defaultPort };
    if (text.startsWith("[")) {
      const close = text.indexOf("]");
      if (close > 1) {
        const host = text.slice(1, close);
        const rest = text.slice(close + 1);
        if (rest.startsWith(":") && rest.slice(1)) return { host, port: rest.slice(1) };
        return { host, port: defaultPort };
      }
    }
    const colon = text.lastIndexOf(":");
    if (colon > 0) {
      const host = text.slice(0, colon);
      const port = text.slice(colon + 1);
      if (/^\d+$/.test(port) && host.indexOf(":") < 0) return { host, port };
    }
    return { host: text.replace(/^\[|\]$/g, ""), port: defaultPort };
  }

  function toolPath(kind, target, extras) {
    extras = extras || {};
    const t = String(target || "").trim();
    if (kind === "self") return "/";
    if (kind === "ip") return t ? `/${encodeToken(t)}` : "/";
    if (kind === "asn") {
      const raw = t.replace(/^(as)/i, "");
      return raw ? `/AS${encodeToken(raw)}` : "/AS13335";
    }
    if (kind === "dns") {
      const type = extras.type || "A";
      const name = t || "example.com";
      let path = `/dns/${encodeToken(name)}`;
      if (type && type !== "A") path += `/${encodeToken(type)}`;
      const qs = new URLSearchParams();
      if (extras.server) qs.set("server", extras.server);
      if (extras.port && extras.port !== "53") qs.set("port", extras.port);
      const q = qs.toString();
      return q ? `${path}?${q}` : path;
    }
    if (kind === "apex") return t ? `/apex/${encodeToken(t)}` : "/apex/example.com";
    if (kind === "register") {
      let raw = String(t || "example").trim();
      if (/^[a-z][a-z0-9+.-]*:/i.test(raw) || raw.indexOf("://") >= 0 || raw.startsWith("//")) {
        return `/register/${encodeURIComponent(raw)}`;
      }
      raw = raw.replace(/^\[|\]$/g, "").replace(/\.$/, "");
      const label = raw.split(".")[0] || "example";
      return `/register/${encodeURIComponent(label)}`;
    }
    if (kind === "dnssec") return t ? `/dnssec/${encodeToken(t)}` : "/dnssec/example.com";
    if (kind === "tls") {
      let host = t || "example.com";
      let port = String(extras.port || "").trim();
      if (!port) {
        const split = splitTlsHostPort(host);
        host = split.host;
        port = split.port;
      }
      let path = port && port !== "443" ? `/tls/${encodeToken(host)}/${encodeToken(port)}` : `/tls/${encodeToken(host)}`;
      const sni = String(extras.sni || "").trim();
      if (sni) path += `?sni=${encodeURIComponent(sni)}`;
      return path;
    }
    if (kind === "bgp") return t ? `/bgp/${encodeToken(t)}` : "/bgp/1.1.1.1";
    if (kind === "dnstrace") {
      const name = t || "example.com";
      const type = String(extras.type || "A").toUpperCase();
      return type !== "A" ? `/dnstrace/${encodeToken(name)}/${encodeToken(type)}` : `/dnstrace/${encodeToken(name)}`;
    }
    if (kind === "ptr") return t ? `/ptr/${encodeToken(t)}` : "/ptr/1.1.1.1";
    if (kind === "http") return httpInspectPath(t || "example.com");
    if (kind === "mail") return t ? `/mail/${encodeToken(t)}` : "/mail/example.com";
    if (kind === "tcp") {
      const host = t || "example.com";
      const port = extras.port || "443";
      return `/tcp/${encodeToken(host)}/${encodeToken(port)}`;
    }
    if (kind === "pmtu") return `/pmtu/${encodeToken(t || "1.1.1.1")}`;
    if (kind === "rdap" || kind === "whois") {
      const q = t || "1.1.1.1";
      if (extras.legacy) return `/whois/${encodeToken(q)}?legacy=1`;
      return `/rdap/${encodeToken(q)}`;
    }
    if (kind === "ping" || kind === "traceroute") {
      return `/${kind}/${encodeToken(t || "1.1.1.1")}`;
    }
    if (kind === "mtr") {
      const host = t || "1.1.1.1";
      const cycles = mtrCyclesQuery(extras.cycles);
      let path = `/mtr/${encodeToken(host)}`;
      if (cycles) path += `?cycles=${encodeURIComponent(cycles)}`;
      return path;
    }
    if (kind === "tcptraceroute") {
      const host = t || "1.1.1.1";
      const port = extras.port || "443";
      return `/tcptraceroute/${encodeToken(host)}/${encodeToken(port)}`;
    }
    if (kind === "reputation") return t ? `/reputation/${encodeToken(t)}` : "/reputation/example.com";
    return t ? `/${encodeToken(t)}` : "/";
  }

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text != null) node.textContent = text;
  return node;
}

function reportShell(kicker, title, sub, chips) {
  const wrap = el("div", "apex inspect");
  const hero = el("div", "apex-hero");
  const left = document.createElement("div");
  left.append(el("p", "apex-kicker", kicker));
  left.append(el("h2", "apex-domain", title || "—"));
  if (sub instanceof Node) {
    if (!/\bapex-sub\b/.test(sub.className || "")) sub.className = `${sub.className || ""} apex-sub`.trim();
    left.append(sub);
  } else if (sub) {
    left.append(el("p", "apex-sub", sub));
  }
  hero.append(left);
  if (chips && chips.length) {
    const counts = el("div", "apex-counts");
    for (const chip of chips) {
      if (!chip) continue;
      const node = el("span", `apex-count ${chip.cls || ""}`.trim());
      node.append(el("strong", "", chip.strong));
      if (chip.label) node.append(document.createTextNode(" " + chip.label));
      counts.append(node);
    }
    hero.append(counts);
  }
  wrap.append(hero);
  return wrap;
}

function inspectZone(title, nodes, cls) {
  const card = el("section", `inspect-zone ${cls || ""}`.trim());
  if (title) card.append(el("h3", "", title));
  for (const node of nodes || []) if (node) card.append(node);
  return card;
}

function observationLine(payload) {
  const probe = payload && payload.probe && typeof payload.probe === "object" ? payload.probe : {};
  const bits = [probe.host, probe.ip, payload && payload.observed_at].filter(Boolean);
  if (!bits.length) return null;
  return el("p", "probe-observed", bits.join(" · "));
}

function diffSummaryBits(diff) {
  if (!diff || typeof diff !== "object") return [];
  const bits = [];
  if (diff.cert_changed) bits.push(window.t("inspect.diff.cert_changed"));
  if (diff.path_changed) bits.push(window.t("inspect.diff.path_changed"));
  if (diff.peer_changed) bits.push(window.t("inspect.diff.peer_changed"));
  if (diff.ok_changed) bits.push(window.t("inspect.diff.ok_changed"));
  if (diff.rtt_ms_delta != null && diff.rtt_ms_delta !== "") {
    const n = Number(diff.rtt_ms_delta);
    const signed = (n > 0 ? "+" : "") + String(n);
    bits.push(window.t("inspect.diff.rtt_delta", { n: signed }));
  }
  return bits;
}

function historyUrl(payload) {
  if (!payload) return "";
  const raw = payload.history || payload.id;
  if (!raw) return "";
  const text = String(raw);
  if (/^https?:\/\//i.test(text)) return text;
  const path = text.startsWith("/") ? text : "/history/" + encodeURIComponent(text);
  const origin = (location.origin || "").replace(/\/$/, "");
  return origin + path;
}

function onHistoryReplayPage() {
  return /^\/history\/[^/]+\/?$/.test(location.pathname || "");
}

function copyText(node, text) {
  const value = String(text || "");
  if (!value) return;
  const mark = function () {
    if (!node) return;
    node.classList.add("copied");
    window.setTimeout(function () { node.classList.remove("copied"); }, 1200);
  };
  const fallback = function () {
    const ta = document.createElement("textarea");
    ta.value = value;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); mark(); } catch (err) {}
    ta.remove();
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(value).then(mark).catch(fallback);
  } else {
    fallback();
  }
}

let histMenu = null;

function closeHistMenu() {
  if (!histMenu) return;
  histMenu.remove();
  histMenu = null;
}

function histLookupBody(data, fallback) {
  if (fallback && typeof fallback === "object" && (fallback.result || fallback.kind)) {
    return fallback;
  }
  if (!data || typeof data !== "object") return null;
  if (
    data.payload &&
    typeof data.payload === "object" &&
    (data.payload.result || data.payload.kind)
  ) {
    return data.payload;
  }
  if (data.result || data.kind) return data;
  return null;
}

function openHistInWindow(url, payload) {
  const go = function (body, path) {
    if (!body || typeof window.openLookupPayload !== "function") return;
    window.openLookupPayload(body, path || body.path);
  };
  const ready = histLookupBody(null, payload);
  if (ready) {
    go(ready, payload && payload.path);
    return;
  }
  fetch(url, {
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  })
    .then(function (res) { return res.json(); })
    .then(function (data) {
      go(histLookupBody(data), data && data.path);
    })
    .catch(function () {});
}

function bindHistPermalink(link, url, payload) {
  if (!link || !url) return;
  link.setAttribute("data-copied", window.t ? window.t("term.copied") : " copied");
  link.addEventListener("click", (event) => {
    event.preventDefault();
    event.stopPropagation();
    if (histMenu && histMenu.dataset.for === url) {
      closeHistMenu();
      return;
    }
    closeHistMenu();
    const menu = document.createElement("div");
    menu.className = "hist-action";
    menu.dataset.for = url;
    menu.setAttribute("role", "menu");
    const copyBtn = document.createElement("button");
    copyBtn.type = "button";
    copyBtn.setAttribute("role", "menuitem");
    copyBtn.textContent = window.t ? window.t("gui.history.copy") : "copy";
    copyBtn.addEventListener("click", (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      copyText(link, url);
      closeHistMenu();
    });
    const openBtn = document.createElement("button");
    openBtn.type = "button";
    openBtn.setAttribute("role", "menuitem");
    openBtn.textContent = window.t ? window.t("gui.history.open") : "open";
    openBtn.addEventListener("click", (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      openHistInWindow(url, payload);
      closeHistMenu();
    });
    menu.append(copyBtn, openBtn);
    document.body.append(menu);
    const rect = link.getBoundingClientRect();
    const width = menu.offsetWidth || 0;
    let left = rect.left + window.scrollX;
    const maxLeft = window.scrollX + window.innerWidth - width - 8;
    if (left > maxLeft) left = Math.max(8, maxLeft);
    menu.style.left = left + "px";
    menu.style.top = rect.bottom + window.scrollY + 4 + "px";
    histMenu = menu;
  });
}

document.addEventListener("click", closeHistMenu);
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeHistMenu();
});

function paintHistoryBar(host, payload) {
  if (!host) return null;
  host.replaceChildren();
  const url = historyUrl(payload);
  const replay = onHistoryReplayPage();
  const bits = diffSummaryBits(payload && payload.diff);
  const hasPrev = !!(payload && payload.prev_id);
  if ((!url && !hasPrev && !bits.length) || (replay && !hasPrev && !bits.length)) {
    host.hidden = true;
    host.classList.add("is-empty");
    return host;
  }
  host.hidden = false;
  host.classList.remove("is-empty");
  const row = el("div", "result-history-row");
  if (url && !replay) {
    const link = document.createElement("a");
    link.className = "hist-permalink";
    setSafeHref(link, url);
    link.textContent = url;
    bindHistPermalink(link, url, payload);
    row.append(link);
  }
  if (hasPrev) {
    const vs = el("button", "hist-link hist-vs", window.t("inspect.diff.vs_previous"));
    vs.type = "button";
    vs.addEventListener("click", (event) => {
      event.preventDefault();
      if (typeof window.openHistoryCompare === "function") window.openHistoryCompare(payload, vs);
    });
    row.append(vs);
    if (bits.length) row.append(el("span", "muted result-history-bits", bits.join(" · ")));
  }
  host.append(row);
  return host;
}

function decorateReport(wrap, payload) {
  const line = observationLine(payload);
  const hero = wrap.querySelector(".apex-hero, .probe-hero, .register-hero");
  const left = hero && hero.firstElementChild;
  if (line) {
    if (left) left.append(line);
    else wrap.append(line);
  }
  return wrap;
}

function renderRegister(payload) {
  const result = payload.result || {};
  const wrap = el("div", "register");
  const hero = el("div", "register-hero");
  const left = document.createElement("div");
  left.append(el("p", "register-kicker", window.t("gui.register.kicker")));
  left.append(el("h2", "register-label", result.label || payload.query || "—"));
  left.append(el("p", "register-sub", window.t("gui.register.sub")));
  const counts = el("div", "register-counts");
  const chips = [
    ["no-dns", result.no_dns, "no-dns"],
    ["has-ns", result.has_ns, "has-ns"],
    ["unknown", result.unknown, "unknown"],
  ];
  const tools = el("div", "register-tools");
  const filters = el("div", "register-filters");
  const filterKeys = ["all", "no-dns", "has-ns", "unknown"];
  let active = "all";
  const search = document.createElement("input");
  search.type = "search";
  search.className = "register-search";
  search.setAttribute("aria-label", window.t("gui.register.search"));
  search.placeholder = window.t("gui.register.search");
  rawTextField(search);
  const board = el("div", "register-board");
  const cells = [];

  function applyFilter() {
    const q = String(search.value || "").trim().toLowerCase().replace(/^\./, "");
    for (const cell of cells) {
      const status = cell.dataset.status || "";
      const hay = (cell.dataset.search || "").toLowerCase();
      const statusOk = active === "all" || status === active;
      const searchOk = !q || hay.indexOf(q) >= 0;
      cell.hidden = !(statusOk && searchOk);
    }
  }

  function setFilter(key) {
    active = key;
    for (const node of filters.querySelectorAll(".register-filter")) {
      node.classList.toggle("is-on", node.dataset.filter === key);
    }
    applyFilter();
  }

  for (const [cls, n, key] of chips) {
    const chip = el("span", `register-count ${cls}`);
    chip.append(el("strong", "", String(n || 0)));
    chip.append(document.createTextNode(` ${window.t("gui.register." + key)}`));
    chip.style.cursor = "pointer";
    chip.addEventListener("click", () => setFilter(key));
    counts.append(chip);
  }
  hero.append(left, counts);
  wrap.append(hero);
  if (!payload.ok) wrap.append(el("p", "register-error", payload.error || window.t("inspect.failed")));

  for (const key of filterKeys) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "register-filter" + (key === "all" ? " is-on" : "");
    btn.dataset.filter = key;
    btn.textContent = window.t("gui.register.filter." + key);
    btn.addEventListener("click", () => setFilter(key));
    filters.append(btn);
  }
  search.addEventListener("input", applyFilter);
  tools.append(filters, search);
  wrap.append(tools);

  for (const row of result.squares || []) {
    const status = row.status || "unknown";
    const tld = String(row.tld || "");
    const shown = String(row.label || tld);
    const fqdn = String(row.name || (result.ascii || result.label ? `${result.ascii || result.label}.${tld}` : tld));
    const cell = document.createElement("button");
    cell.type = "button";
    cell.className = `register-cell ${status} inspect-tool`;
    cell.dataset.status = status;
    cell.dataset.search = `${shown} ${tld} ${fqdn}`;
    cell.dataset.toolKind = "rdap";
    cell.dataset.toolTarget = fqdn;
    const reason = row.reason ? ` · ${row.reason}` : "";
    cell.title = `${fqdn} · ${status}${reason}`;
    cell.append(el("span", "register-dot", "." + shown));
    board.append(cell);
    cells.push(cell);
  }
  wrap.append(board);
  wrap.append(el("p", "register-legend", window.t("gui.register.legend")));
  return decorateReport(wrap, payload);
}

function renderApex(payload) {
  const result = payload.result || {};
  const summary = result.summary || {};
  const wrap = el("div", "apex");
  const hero = el("div", "apex-hero");
  const left = document.createElement("div");
  left.append(el("p", "apex-kicker", window.t("inspect.apex.kicker")));
  left.append(el("h2", "apex-domain", result.domain || payload.query || "—"));
  left.append(el("p", "apex-sub", `Parent ${result.parent || "—"} · zone and mail health`));
  const counts = el("div", "apex-counts");
  for (const key of ["pass", "warn", "fail", "info"]) {
    const chip = el("span", `apex-count ${key}`);
    chip.append(el("strong", "", String(summary[key] || 0)));
    chip.append(document.createTextNode(` ${key}`));
    counts.append(chip);
  }
  hero.append(left, counts);
  wrap.append(hero);
  if (!payload.ok) wrap.append(el("p", "apex-error", payload.error || window.t("inspect.apex.failed")));
  for (const section of result.sections || []) {
    const card = el("section", "apex-section");
    card.append(el("h3", "", section.title || section.id || window.t("inspect.section")));
    const list = el("ol", "apex-rows");
    for (const check of section.checks || []) {
      const row = el("li", `apex-row ${check.status || "info"}`);
      const head = el("div", "apex-row-head");
      head.append(el("span", "apex-status", check.status || "info"));
      head.append(el("strong", "", check.title || check.id || ""));
      row.append(head);
      row.append(el("p", "", check.detail || ""));
      if (check.rfcs && check.rfcs.length) {
        const rfcs = el("p", "apex-rfcs");
        for (const rfc of check.rfcs) {
          const a = el("a", "rfc", rfc.section ? `RFC ${rfc.rfc} §${rfc.section}` : `RFC ${rfc.rfc}`);
          setSafeHref(a, rfc.url || `https://www.rfc-editor.org/rfc/rfc${rfc.rfc}`);
          a.target = "_blank";
          a.rel = "noopener";
          rfcs.append(a);
        }
        row.append(rfcs);
      }
      list.append(row);
    }
    card.append(list);
    wrap.append(card);
  }
  const standards = result.standards || [];
  if (standards.length) {
    const card = el("section", "apex-section");
    card.append(el("h3", "", window.t("inspect.rfcs")));
    const hint = el("p", "apex-sub", window.t("inspect.rfcs.hint"));
    hint.style.margin = "-0.2rem 0 0.85rem";
    card.append(hint);
    const ul = el("ul", "apex-standards");
    for (const row of standards) {
      const li = document.createElement("li");
      const a = el("a", "", `RFC ${row.rfc}`);
      setSafeHref(a, row.url || `https://www.rfc-editor.org/rfc/rfc${row.rfc}`);
      a.target = "_blank";
      a.rel = "noopener";
      li.append(a);
      li.append(el("span", "", row.title || ""));
      const bits = [row.why, (row.sections || []).join(", ")].filter(Boolean);
      li.append(el("small", "", bits.join(" · ")));
      ul.append(li);
    }
    card.append(ul);
    wrap.append(card);
  }
  return wrap;
}

function inspectBtn(kind, value, cls, label) {
  const btn = el("button", cls, label == null ? String(value) : label);
  btn.type = "button";
  if (kind === "asn") btn.dataset.asn = String(value);
  else if (kind === "ip") btn.dataset.ip = String(value);
  else btn.dataset.domain = String(value).replace(/\.$/, "");
  return btn;
}

function looksLikeIp(value) {
  const t = String(value || "").trim();
  if (!t) return false;
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(t)) return true;
  return t.includes(":") && /^[0-9a-fA-F:.]+$/.test(t);
}

function looksLikeDomain(value) {
  const t = String(value || "").trim().replace(/\.$/, "");
  if (!t || /\s/.test(t) || looksLikeIp(t)) return false;
  return /^(?=.{1,253}$)(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z]{2,63}$/.test(t);
}

function hopIdentity(name, ip) {
  if (name && ip) {
    const wrap = document.createElement("span");
    wrap.append(inspectBtn("domain", name, "probe-host", name));
    wrap.append(document.createTextNode(" ("));
    wrap.append(inspectBtn("ip", ip, "probe-ip", ip));
    wrap.append(document.createTextNode(")"));
    return wrap;
  }
  if (ip && ip !== "*") return inspectBtn("ip", ip, "probe-ip", ip);
  return el("span", "probe-ip", ip || "*");
}

function hopCell(row, ip) {
  const td = document.createElement("td");
  td.className = "host";
  const main = el("div", "hop-main");
  if (row && row.flag_url && (!row.scope || row.scope === "public")) {
    const img = document.createElement("img");
    img.className = "looking-glass-flag";
    img.src = row.flag_url;
    img.alt = row.flag || row.country || "";
    img.title = [row.country, row.country_name].filter(Boolean).join(" — ");
    main.append(img);
  } else if (row && row.scope && row.scope !== "public") {
    const chip = el("span", `scope-chip ${row.scope}`, row.scope_label || row.scope);
    chip.title = row.scope_detail || row.scope_label || "";
    main.append(chip);
  } else if (row && row.flag) {
    main.append(el("span", "looking-glass-flag-emoji", row.flag));
  }
  main.append(hopIdentity(row && row.name, ip));
  if (row && row.asn && (!row.scope || row.scope === "public")) {
    const btn = el("button", "probe-asn", `AS${row.asn}`);
    btn.type = "button";
    btn.dataset.asn = String(row.asn);
    main.append(btn);
  }
  td.append(main);
  const meta = el("div", "hop-meta");
  if (row && row.place) {
    let loc = `${row.place} (hostname)`;
    if (row.place_country && row.country && row.place_country !== row.country) {
      loc += ` · GeoIP ${row.country_name || row.country}`;
    }
    meta.append(el("span", "", loc));
  }
  if (row && row.scope === "none") {
    meta.append(el("span", "", window.t("inspect.no_icmp")));
  } else if (row && row.scope && row.scope !== "public" && row.scope_detail) {
    meta.append(el("span", "", row.scope_detail));
  } else if (row && row.org_name) {
    meta.append(el("span", "", [row.org_name, row.country].filter(Boolean).join(" · ")));
  }
  for (const alt of (row && row.hosts_detail) || []) {
    if (!alt.ip || alt.ip === ip) continue;
    const line = el("span", "hop-alt");
    line.append(document.createTextNode("+ "));
    line.append(hopIdentity(alt.name, alt.ip));
    if (alt.scope === "public" && alt.asn) {
      line.append(" ");
      const btn = el("button", "probe-asn", `AS${alt.asn}`);
      btn.type = "button";
      btn.dataset.asn = String(alt.asn);
      line.append(btn);
    }
    if (alt.scope && alt.scope !== "public" && alt.scope_label) line.append(` · ${alt.scope_label}`);
    if (alt.scope === "public" && alt.org_name) line.append(` · ${[alt.org_name, alt.country].filter(Boolean).join(" · ")}`);
    meta.append(line);
  }
  if (meta.childNodes.length) td.append(meta);
  return td;
}

function renderSummary(summary, kind) {
  if (!["traceroute", "mtr", "tcptraceroute"].includes(kind)) return null;
  summary = summary || {};
  const card = el("section", "probe-summary");
  card.setAttribute("aria-label", window.t("inspect.route_summary"));
  card.append(el("p", "probe-kicker", window.t("inspect.route_summary")));
  const dl = document.createElement("dl");
  const add = (dt, dd, ddCls, wrapCls) => {
    const wrap = document.createElement("div");
    if (wrapCls) wrap.className = wrapCls;
    wrap.append(el("dt", "", dt));
    wrap.append(el("dd", ddCls || "", dd));
    dl.append(wrap);
  };
  add(window.t("inspect.path_geoip"), summary.route_text || window.t("inspect.no_public_hops"));
  if (summary.inferred_text) add(window.t("inspect.path_hostname"), summary.inferred_text);
  add(window.t("inspect.dest_reached"), summary.reached ? window.t("inspect.yes") : window.t("inspect.no"), summary.reached ? "ok" : "bad");
  add(window.t("inspect.end_to_end_loss"), summary.loss_percent == null ? "—" : `${summary.loss_percent}%`);
  add(window.t("inspect.latency"), summary.latency_ms == null ? "—" : `~${summary.latency_ms} ms`);
  if (summary.as_path && summary.as_path.length) {
    const wrap = document.createElement("div");
    wrap.append(el("dt", "", window.t("inspect.as_transitions")));
    const dd = el("dd", "probe-as-path");
    summary.as_path.forEach((asn, i) => {
      if (i) dd.append(" → ");
      const btn = el("button", "probe-asn", `AS${asn}`);
      btn.type = "button";
      btn.dataset.asn = String(asn);
      dd.append(btn);
    });
    wrap.append(dd);
    dl.append(wrap);
  }
  for (const note of summary.warnings || []) add(window.t("inspect.transit_warning"), note, "", "warn");
  card.append(dl);
  return card;
}

function probeMethod(result, kind) {
  if (result && result.probe) return "python-" + result.probe;
  if (kind === "tcptraceroute") return "python-tcp";
  if (kind === "traceroute" || kind === "mtr") return "python-udp";
  return (result && result.via) || "python-icmp";
}

function renderProbe(payload) {
  const result = payload.result || {};
  const kind = payload.kind || "ping";
  const wrap = el("div", "probe");
  const hero = el("div", "probe-hero");
  const left = document.createElement("div");
  left.append(el("p", "probe-kicker", kind));
  const title = result.target || payload.query || "—";
  const h = el("h2", "probe-domain");
  if (result.ip && title !== result.ip && looksLikeDomain(title)) {
    h.append(inspectBtn("domain", title, "probe-host", title));
  } else if (result.ip && (title === result.ip || looksLikeIp(title))) {
    h.append(inspectBtn("ip", result.ip, "probe-ip", title));
  } else {
    h.textContent = title;
  }
  left.append(h);
  const sub = document.createElement("p");
  sub.className = "probe-sub";
  if (result.flag_url && (!result.scope || result.scope === "public")) {
    const img = document.createElement("img");
    img.className = "looking-glass-flag";
    img.src = result.flag_url;
    img.alt = result.flag || result.country || "";
    img.title = [result.country, result.country_name].filter(Boolean).join(" — ");
    sub.append(img, document.createTextNode(" "));
  } else if (result.scope && result.scope !== "public") {
    sub.append(el("span", `scope-chip ${result.scope}`, result.scope_label || result.scope), document.createTextNode(" "));
  }
  if (result.ip) sub.append(inspectBtn("ip", result.ip, "probe-ip", result.ip));
  else sub.append(document.createTextNode("—"));
  if (result.family) sub.append(document.createTextNode(` · ${result.family}`));
  if (result.asn) {
    sub.append(document.createTextNode(" · "));
    const btn = el("button", "probe-asn", `AS${result.asn}`);
    btn.type = "button";
    btn.dataset.asn = String(result.asn);
    sub.append(btn);
  }
  const rest = [result.org_name, result.port ? `TCP ${result.port}` : "", probeMethod(result, kind)].filter(Boolean);
  if (rest.length) sub.append(document.createTextNode(" · " + rest.join(" · ")));
  left.append(sub);
  const counts = el("div", "probe-counts");
  if (kind === "ping") {
    for (const [label, value] of [["recv", result.received || 0], ["sent", result.transmitted || 0], ["loss", `${result.loss_percent ?? "—"}%`]]) {
      const chip = el("span", "probe-count");
      chip.append(el("strong", "", String(value)));
      chip.append(document.createTextNode(` ${label}`));
      counts.append(chip);
    }
  } else {
    const chips = [["hops", (result.hops || []).length], ["dest", result.reached ? "yes" : "no"]];
    if (result.cycles) chips.push(["cycles", result.cycles]);
    for (const [label, value] of chips) {
      const chip = el("span", "probe-count");
      chip.append(el("strong", "", String(value)));
      chip.append(document.createTextNode(` ${label}`));
      counts.append(chip);
    }
  }
  hero.append(left, counts);
  wrap.append(hero);
  const summary = renderSummary(result.summary, kind);
  if (summary) wrap.append(summary);
  const section = el("section", "probe-section");
  const table = document.createElement("table");
  const thead = document.createElement("thead");
  const tbody = document.createElement("tbody");
  const header = document.createElement("tr");
  const addHead = (labels) => {
    for (const label of labels) header.append(el("th", "", label));
    thead.append(header);
  };
  if (kind === "ping") {
    addHead(["seq", "from", "rtt", ""]);
    for (const row of result.probes || []) {
      const tr = document.createElement("tr");
      tr.append(el("td", "", String(row.seq)));
      tr.append(hopCell(row, row.from));
      tr.append(el("td", "", row.rtt_ms == null ? "—" : `${Number(row.rtt_ms).toFixed(3)} ms`));
      tr.append(el("td", row.ok ? "ok" : "bad", row.ok ? "ok" : (row.error || "lost")));
      tbody.append(tr);
    }
    table.append(thead, tbody);
    section.append(table);
    section.append(el("p", "probe-sub", `min ${result.min_ms ?? "—"} · avg ${result.avg_ms ?? "—"} · max ${result.max_ms ?? "—"} ms`));
  } else if (kind === "mtr") {
    addHead(["hop", "host", "loss", "sent", "last", "avg", "best", "wrst", "stdev"]);
    for (const row of result.hops || []) {
      const tr = document.createElement("tr");
      tr.append(el("td", "", String(row.hop)));
      tr.append(hopCell(row, row.host));
      tr.append(el("td", "", `${row.loss_percent}%`));
      tr.append(el("td", "", String(row.sent)));
      tr.append(el("td", "", row.last_ms == null ? "—" : String(row.last_ms)));
      tr.append(el("td", "", row.avg_ms == null ? "—" : String(row.avg_ms)));
      tr.append(el("td", "", row.best_ms == null ? "—" : String(row.best_ms)));
      tr.append(el("td", "", row.worst_ms == null ? "—" : String(row.worst_ms)));
      tr.append(el("td", "", row.stdev_ms == null ? "—" : String(row.stdev_ms)));
      tbody.append(tr);
    }
    table.append(thead, tbody);
    section.append(table);
  } else {
    addHead(["hop", "host", "rtt", ""]);
    for (const row of result.hops || []) {
      const tr = document.createElement("tr");
      tr.append(el("td", "", String(row.hop)));
      tr.append(hopCell(row, row.host));
      tr.append(el("td", "", row.rtt_ms == null ? "—" : `${Number(row.rtt_ms).toFixed(3)} ms`));
      tr.append(el("td", row.status === "reply" ? "ok" : "muted", row.status || ""));
      tbody.append(tr);
    }
    table.append(thead, tbody);
    section.append(table);
  }
  wrap.append(section);
  return decorateReport(wrap, payload);
}

function statusChip(status) {
  return el("span", "apex-status", status || "info");
}

function dnssecBadge(status) {
  if (status === "insecure") return { cls: "warn", label: "unsigned", rest: "" };
  if (status === "bogus") return { cls: "fail", label: "bogus", rest: " chain" };
  if (status === "secure") return { cls: "pass", label: "secure", rest: " chain" };
  return { cls: "warn", label: status || "—", rest: " chain" };
}

function nsTable(rows, columns) {
  const table = el("table", "inspect-table sec-ns");
  const thead = document.createElement("thead");
  const hr = document.createElement("tr");
  for (const h of columns) hr.append(el("th", "", h));
  thead.append(hr);
  const tbody = document.createElement("tbody");
  for (const ns of rows) {
    const tr = document.createElement("tr");
    if (!ns.ok) tr.className = "down";
    const host = document.createElement("td");
    host.append(el("span", "host", ns.host || "—"));
    if (ns.ip) host.append(el("span", "ip", ns.ip));
    tr.append(host);
    for (const cell of ns.cells) tr.append(el("td", "", cell));
    tbody.append(tr);
  }
  table.append(thead, tbody);
  return table;
}

function renderDnssecGraph(graph) {
  const wrap = el("div", "sec-graph");
  for (const group of graph.groups || []) {
    const col = el("div", "sec-group");
    col.append(el("p", "sec-group-title", group.title || ""));
    for (const node of group.nodes || []) {
      const card = el("div", `sec-node ${node.status || ""}`);
      card.append(el("span", "kind", node.kind || ""));
      card.append(el("span", "label", node.label || ""));
      if (node.sub) card.append(el("span", "sub", node.sub));
      col.append(card);
    }
    wrap.append(col);
    if (group.link) {
      const link = el("div", `sec-link ${group.link.status || ""}`);
      link.append(el("span", "sec-arrow", group.link.status === "bogus" ? "✕" : "→"));
      link.append(el("span", "", group.link.label || ""));
      wrap.append(link);
    }
  }
  return wrap;
}

function renderDnssec(payload) {
  const result = payload.result || {};
  const issue = result.issue || {};
  const wrap = el("div", "apex inspect");
  const hero = el("div", "apex-hero");
  const left = document.createElement("div");
  left.append(el("p", "apex-kicker", window.t("gui.dnssec.tab")));
  left.append(el("h2", "apex-domain", result.name || payload.query || "—"));
  left.append(el("p", "apex-sub", `Apex ${result.apex || "—"} · chain of trust from the IANA root anchors`));
  const counts = el("div", "apex-counts");
  const badge = dnssecBadge(result.status);
  const chip = el("span", `apex-count ${badge.cls}`);
  chip.append(el("strong", "", badge.label));
  if (badge.rest) chip.append(document.createTextNode(badge.rest));
  counts.append(chip);
  hero.append(left, counts);
  wrap.append(hero);
  if (result.broken || issue.severity === "error") {
    const box = el("div", "sec-callout error");
        box.append(el("h3", "", issue.title || `Breaks at ${result.broken_at || "this zone"}`));
    box.append(el("p", "", issue.what || result.broken_reason || ""));
    if (issue.effect) box.append(el("p", "", issue.effect));
    if (issue.fix) box.append(el("p", "", issue.fix));
    if (issue.rfc) box.append(el("p", "sec-meta", issue.rfc));
    wrap.append(box);
  } else if (result.status === "insecure") {
    const box = el("div", "sec-callout warn");
    box.append(el("h3", "", issue.title || window.t("inspect.unsigned")));
    box.append(el("p", "", issue.what || window.t("inspect.unsigned_path")));
    if (issue.effect) box.append(el("p", "", issue.effect));
    wrap.append(box);
  } else if (issue.severity === "ok") {
    const box = el("div", "sec-callout ok");
    box.append(el("h3", "", issue.title || window.t("inspect.chain_holds")));
    if (issue.what) box.append(el("p", "", issue.what));
    wrap.append(box);
  }
  for (const zone of result.chain || []) {
    const card = el("section", `inspect-zone ${zone.status || ""}`);
    const head = el("div", "apex-row-head");
    head.style.display = "flex";
    head.style.gap = "0.5rem";
    head.append(statusChip(zone.status));
    head.append(el("h3", "", zone.zone));
    card.append(head);
    card.append(el("p", "apex-sub", zone.detail || ""));
    const zIssue = zone.issue || {};
    if (zIssue.severity === "error" || zIssue.severity === "warn") {
      const dl = el("dl", "sec-explain");
      const add = (dt, dd) => {
        if (!dd) return;
        const div = document.createElement("div");
        div.append(el("dt", "", dt));
        div.append(el("dd", "", dd));
        dl.append(div);
      };
      add(window.t("inspect.whats_wrong"), zIssue.what);
      add(window.t("inspect.what_resolvers"), zIssue.effect);
      add(window.t("inspect.how_to_fix"), zIssue.fix);
      card.append(dl);
    }
    if (zone.graph && (zone.graph.groups || []).length) card.append(renderDnssecGraph(zone.graph));
    const dsRows = zone.ds || [];
    if (dsRows.length) {
      const ul = el("ul", "inspect-keys");
      for (const ds of dsRows) {
        const matched = ds.matches_dnskey;
        ul.append(el("li", "", `${ds.key_tag} · ${ds.algorithm_name || ds.algorithm || ""} · ${ds.digest_name || ""} · ${matched ? "matches DNSKEY" : "no matching DNSKEY"}`));
      }
      card.append(ul);
    }
    const keys = zone.dnskeys || [];
    if (keys.length) {
      const p = el("p", "apex-sub", zone.dnskey_rrsig ? `DNSKEY · RRSIG ${zone.dnskey_rrsig}` : "DNSKEY");
      p.style.margin = "0";
      card.append(p);
      const ul = el("ul", "inspect-keys");
      for (const key of keys) {
        ul.append(el("li", "", `${key.role} ${key.key_tag} · flags ${key.flags} · ${key.algorithm_name || ""}`));
      }
      card.append(ul);
    }
    const keySigs = zone.dnskey_rrsigs || [];
    if (keySigs.length) {
      const p = el("p", "apex-sub", "RRSIGs over DNSKEY");
      p.style.margin = "0";
      card.append(p);
      const ul = el("ul", "inspect-keys");
      for (const sig of keySigs) {
        ul.append(el("li", "", `key ${sig.key_tag} · ${sig.algorithm_name || ""} · signer ${sig.signer || "—"}`));
      }
      card.append(ul);
    }
    const servers = zone.nameservers || [];
    if (servers.length) {
      const agree = zone.ns_agreement || {};
      const caption = el("p", "apex-sub", agree.ok === false ? window.t("inspect.nameservers_disagree") : window.t("inspect.nameservers"));
      caption.style.margin = "0";
      card.append(caption);
      card.append(nsTable(servers.map((ns) => ({
        ...ns,
        cells: [
          `${ns.side || ""} ${ns.qtype || ""}`.trim(),
          ns.ok ? (ns.rcode || "—") : (ns.error || "timeout"),
          ns.ok ? (ns.aa ? "yes" : "no") : "—",
          ns.ok ? ((ns.tags || []).join(", ") || String(ns.count || 0)) + (ns.rrsig ? " · RRSIG" : "") : "—",
          ns.ms == null ? "—" : String(ns.ms),
        ],
      })), ["server", "side", "rcode", "AA", "records", "ms"]));
    }
    wrap.append(card);
  }
  if (result.leaf) {
    const card = el("section", `inspect-zone ${result.leaf.status || ""}`);
    const head = el("div", "apex-row-head");
    head.style.display = "flex";
    head.style.gap = "0.5rem";
    head.append(statusChip(result.leaf.status));
    head.append(el("h3", "", `${result.leaf.type || ""} ${result.leaf.name || ""}`.trim()));
    card.append(head);
    card.append(el("p", "apex-sub", result.leaf.detail || ""));
    const leafMeta = el("dl", "inspect-kv");
    const addMeta = (dt, dd) => {
      const div = document.createElement("div");
      div.append(el("dt", "", dt));
      div.append(el("dd", "", dd));
      leafMeta.append(div);
    };
    addMeta("RRSIG", result.leaf.rrsig || "—");
    addMeta(window.t("inspect.authenticated"), result.leaf.authenticated ? window.t("rdap.yes") : window.t("rdap.no"));
    addMeta(window.t("inspect.chain_secure"), result.leaf.chain_secure ? window.t("rdap.yes") : window.t("rdap.no"));
    card.append(leafMeta);
    const leafSigs = result.leaf.rrsigs || [];
    if (leafSigs.length) {
      const ul = el("ul", "inspect-keys");
      for (const sig of leafSigs) {
        ul.append(el("li", "", `RRSIG key ${sig.key_tag} · ${sig.algorithm_name || ""} · signer ${sig.signer || "—"}`));
      }
      card.append(ul);
    }
    const leafNs = result.leaf.nameservers || [];
    if (leafNs.length) {
      card.append(nsTable(leafNs.map((ns) => ({
        ...ns,
        cells: [
          ns.ok ? (ns.rcode || "—") : (ns.error || "timeout"),
          ns.ok ? (ns.aa ? "yes" : "no") : "—",
          ns.ok ? String(ns.count || 0) + (ns.rrsig ? " · RRSIG" : "") : "—",
          ns.ms == null ? "—" : String(ns.ms),
        ],
      })), ["server", "rcode", "AA", "records", "ms"]));
    }
    wrap.append(card);
  }
  return wrap;
}

function renderTls(payload) {
  const result = payload.result || {};
  const leaf = result.leaf || {};
  const wrap = el("div", "apex inspect");
  const hero = el("div", "apex-hero");
  const left = document.createElement("div");
  left.append(el("p", "apex-kicker", "TLS"));
  const hostTitle = result.host || payload.query || "—";
  const hostH = el("h2", "apex-domain");
  if (looksLikeDomain(hostTitle)) hostH.append(inspectBtn("domain", hostTitle, "probe-host", hostTitle));
  else hostH.textContent = hostTitle;
  left.append(hostH);
  const sub = el("p", "probe-sub");
  if (result.flag_url) {
    const img = document.createElement("img");
    img.className = "looking-glass-flag";
    img.src = result.flag_url;
    sub.append(img, document.createTextNode(" "));
  }
  if (result.ip) {
    const shown = result.ip.includes(":") ? `[${result.ip}]` : result.ip;
    sub.append(inspectBtn("ip", result.ip, "probe-ip", shown));
  } else sub.append(document.createTextNode("—"));
  sub.append(document.createTextNode(`:${result.port || 443}`));
  if (result.asn) {
    sub.append(document.createTextNode(" · "));
    const btn = el("button", "probe-asn", `AS${result.asn}`);
    btn.type = "button";
    btn.dataset.asn = String(result.asn);
    sub.append(btn);
  }
  if (result.org_name) sub.append(document.createTextNode(` · ${result.org_name}`));
  if (result.country) sub.append(document.createTextNode(` · ${result.country}`));
  left.append(sub);
  const counts = el("div", "apex-counts");
  const v = el("span", `apex-count ${result.verified ? "pass" : "fail"}`);
  v.append(el("strong", "", result.verified ? "yes" : "no"));
  v.append(document.createTextNode(" verified"));
  const proto = el("span", "apex-count");
  proto.append(el("strong", "", result.protocol || "—"));
  proto.append(document.createTextNode(" tls"));
  counts.append(v, proto);
  hero.append(left, counts);
  wrap.append(hero);
  const tlsErr = payload.error || result.error;
  if (tlsErr) wrap.append(el("p", "inspect-break", tlsErr));
  const kv = (rows) => {
    const dl = el("dl", "inspect-kv");
    for (const [dt, dd] of rows) {
      const div = document.createElement("div");
      div.append(el("dt", "", dt));
      div.append(el("dd", "", dd));
      dl.append(div);
    }
    return dl;
  };
  const hs = el("section", `inspect-zone ${result.verified ? "secure" : "bogus"}`);
  hs.append(el("h3", "", window.t("inspect.handshake")));
  hs.append(kv([
    ["SNI", result.sni || "—"],
    [window.t("inspect.hostname_match"), result.hostname_matches == null ? "—" : (result.hostname_matches ? window.t("rdap.yes") : window.t("rdap.no"))],
    [window.t("inspect.cipher"), ((result.cipher || {}).name || "—") + ((result.cipher || {}).bits ? ` (${result.cipher.bits} bit)` : "")],
    ["ALPN", result.alpn || "—"],
  ]));
  wrap.append(hs);
  const cert = el("section", "inspect-zone");
  cert.append(el("h3", "", window.t("inspect.leaf_cert")));
  const sans = (leaf.sans || []).map((s) => s.value).join(", ");
  cert.append(kv([
    [window.t("inspect.subject_cn"), (leaf.subject || {}).commonName || "—"],
    [window.t("inspect.issuer"), (leaf.issuer || {}).commonName || "—"],
    [window.t("inspect.serial"), leaf.serial || "—"],
    [window.t("inspect.not_before"), leaf.not_before || "—"],
    [window.t("inspect.not_after"), (leaf.not_after || "—") + (leaf.days_remaining != null ? ` · ${leaf.days_remaining}d` : "") + (leaf.expired ? " · " + window.t("inspect.expired") : "")],
    [window.t("inspect.sha256"), leaf.sha256 || "—"],
    [window.t("inspect.san"), sans || "—"],
  ]));
  wrap.append(cert);
  const chain = result.chain || [];
  if (chain.length) {
    const sec = el("section", "inspect-zone");
    sec.append(el("h3", "", window.t("inspect.chain")));
    const ul = el("ul", "inspect-keys");
    for (const certRow of chain) {
      ul.append(el("li", "", `${certRow.leaf ? "leaf" : certRow.index} · ${certRow.sha256 || ""}`));
    }
    sec.append(ul);
    wrap.append(sec);
  }
  if (leaf.pem) {
    const sec = el("section", "inspect-zone");
    sec.append(el("h3", "", window.t("inspect.pem")));
    sec.append(el("pre", "pem", leaf.pem));
    wrap.append(sec);
  }
  return decorateReport(wrap, payload);
}

function renderRdap(payload) {
  const result = payload.result || {};
  const rdap = payload.kind === "asn" ? (result.rdap || {}) : result;
  const kicker = payload.kind === "asn"
    ? window.t("rdap.kicker_asn")
    : payload.kind === "whois"
      ? (rdap.mode === "legacy" ? window.t("rdap.kicker_legacy") : window.t("rdap.kicker"))
      : window.t("rdap.kicker_rdap");
  return window.renderRegistration(payload, rdap, kicker);
}

function renderDns(payload) {
  const result = payload.result || {};
  const wrap = el("div", "apex inspect");
  const hero = el("div", "apex-hero");
  const left = document.createElement("div");
  left.append(el("p", "apex-kicker", window.t("inspect.dns.label")));
  left.append(el("h2", "apex-domain", result.name || payload.query || "—"));
  const bits = [
    result.qtype || payload.qtype || "A",
    result.status || "—",
  ];
  if (payload.total_ms != null) bits.push(`${Number(payload.total_ms).toFixed(1)} ms`);
  left.append(el("p", "apex-sub", bits.join(" · ")));
  const counts = el("div", "apex-counts");
  const addCount = (n, label) => {
    const chip = el("span", "apex-count");
    chip.append(el("strong", "", String(n)));
    chip.append(document.createTextNode(" " + label));
    counts.append(chip);
  };
  addCount((result.answers || []).length, window.t("inspect.answer"));
  addCount((result.authority || []).length, window.t("inspect.authority"));
  addCount((result.additional || []).length, window.t("inspect.additional"));
  hero.append(left, counts);
  wrap.append(hero);
  if (payload.error) wrap.append(el("p", "inspect-break", payload.error));
  const section = (title, rows, emptyText) => {
    const card = el("section", "inspect-zone");
    card.append(el("h3", "", title));
    if (!rows.length) {
      card.append(el("p", "dns-empty", emptyText));
      wrap.append(card);
      return;
    }
    const table = el("table", "dns-rr");
    const thead = document.createElement("thead");
    const hr = document.createElement("tr");
    for (const h of ["name", "ttl", "type", "data"]) hr.append(el("th", "", h));
    thead.append(hr);
    const tbody = document.createElement("tbody");
    for (const row of rows) {
      const tr = document.createElement("tr");
      const nameTd = document.createElement("td");
      const nm = row.name || "—";
      if (nm !== "—" && looksLikeDomain(nm)) nameTd.append(inspectBtn("domain", nm, "probe-host", nm));
      else nameTd.textContent = nm;
      tr.append(nameTd);
      tr.append(el("td", "", row.ttl == null ? "—" : String(row.ttl)));
      tr.append(el("td", "", row.type || "—"));
      const dataTd = document.createElement("td");
      const data = String(row.data || "").trim();
      const rr = String(row.type || "").toUpperCase();
      if (!data) dataTd.textContent = "—";
      else if (rr === "A" || rr === "AAAA" || looksLikeIp(data)) {
        dataTd.append(inspectBtn("ip", data, "probe-ip", data));
      } else if (["NS", "CNAME", "PTR", "DNAME"].includes(rr) || looksLikeDomain(data)) {
        dataTd.append(inspectBtn("domain", data, "probe-host", data));
      } else {
        dataTd.textContent = data;
      }
      tr.append(dataTd);
      tbody.append(tr);
    }
    table.append(thead, tbody);
    card.append(table);
    wrap.append(card);
  };
  const qtype = result.qtype || payload.qtype || "records";
  let emptyAnswers = `No ${qtype} records`;
  if (result.status === "NXDOMAIN") emptyAnswers = window.t("inspect.nxdomain");
  else if (result.status === "NOERROR" && !((result.answers || []).length)) {
    emptyAnswers = `NODATA — no ${qtype} records at this name. DS lives at the zone apex.`;
  }
  section(window.t("inspect.answer"), result.answers || [], emptyAnswers);
  section(window.t("inspect.authority"), result.authority || [], window.t("inspect.no_authority"));
  section(window.t("inspect.additional"), result.additional || [], window.t("inspect.no_additional"));
  return wrap;
}


function ianaSummary(entry) {
  if (!entry || typeof entry !== "object") return null;
  const rfcField = [entry.description, entry.references].find(function (v) {
    return /rfc/i.test(String(v || ""));
  }) || entry.references || "";
  const rfc = String(rfcField).replace(/^\[+|\]+$/g, "").trim();
  const bits = [entry.cidr || entry.prefix, entry.designation, rfc].filter(Boolean);
  return bits.length ? bits.join(" · ") : null;
}


function kvTable(rows) {
  const dl = el("dl", "inspect-kv");
  for (const [k, v] of rows) {
    if (v == null || v === "") continue;
    const div = document.createElement("div");
    div.append(el("dt", "", k));
    const dd = el("dd", "");
    if (v instanceof Node) dd.append(v);
    else dd.textContent = String(v);
    div.append(dd);
    dl.append(div);
  }
  return dl;
}

function renderIp(payload) {
  const r = payload.result || {};
  const sub = el("p", "apex-sub", "");
  if (r.flag_url || r.flag_html) {
    if (r.flag_url) {
      const img = document.createElement("img");
      img.className = "looking-glass-flag";
      img.src = r.flag_url;
      img.alt = r.country || "";
      sub.append(img, document.createTextNode(" "));
    }
    sub.append(document.createTextNode([r.country, r.country_name].filter(Boolean).join(" — ")));
  } else {
    sub.textContent = [r.country, r.country_name, r.source].filter(Boolean).join(" · ") || "—";
  }
  const wrap = reportShell(payload.kind === "country" ? window.t("inspect.country") : window.t("inspect.ip"), r.ip || payload.query || "—", sub);
  wrap.append(inspectZone(window.t("inspect.network"), [kvTable([
    ["ASN", r.asn != null && r.asn !== false ? inspectBtn("asn", r.asn, "probe-asn", `AS${r.asn}`) : "—"],
    [window.t("inspect.prefix"), r.prefix],
    [window.t("inspect.org"), r.org_name],
    [window.t("inspect.source"), r.source],
    ["IANA", r.iana && ianaSummary(r.iana)],
  ])]));
  return wrap;
}

function renderReputation(payload) {
  const r = payload.result || {};
  const wrap = reportShell(window.t("inspect.reputation.label"), r.ip || r.domain || payload.query || "—", [
    r.status || "—",
    (r.resolver || []).length ? window.t("inspect.resolver", { value: (r.resolver || []).join(", ") }) : window.t("inspect.system_resolver"),
  ].join(" · "), [
    { strong: r.listed ? window.t("inspect.listed") : window.t("inspect.clean"), label: "", cls: r.listed ? "fail" : "pass" },
    r.sender_score && r.sender_score.score != null
      ? { strong: String(r.sender_score.score), label: window.t("inspect.sender_score") }
      : null,
  ]);
  if (r.sender_score && r.sender_score.error && r.sender_score.score == null) {
    wrap.append(el("p", "muted", `Sender Score: ${r.sender_score.error}`));
  }
  const lists = r.lists || {};
  const table = el("table", "inspect-table");
  const thead = document.createElement("thead");
  const hr = document.createElement("tr");
  for (const h of [window.t("inspect.list"), window.t("inspect.status"), window.t("inspect.detail")]) hr.append(el("th", "", h));
  thead.append(hr);
  const tbody = document.createElement("tbody");
  for (const [name, item] of Object.entries(lists)) {
    const tr = document.createElement("tr");
    tr.append(el("td", "", name));
    const st = item.status || (item.listed ? "listed" : "clean");
    tr.append(el("td", item.error ? "bad" : (item.listed ? "bad" : "ok"), st));
    const detail = item.error || (item.flags || []).join(", ") || (item.txt || []).join(" ") || item.query || "—";
    tr.append(el("td", "fill", detail));
    tbody.append(tr);
  }
  table.append(thead, tbody);
  wrap.append(inspectZone(window.t("inspect.lists"), [table]));
  return wrap;
}

function renderBgp(payload) {
  const r = payload.result || {};
  const rpki = r.rpki || {};
  const wrap = reportShell(window.t("inspect.bgp.label"), r.prefix || r.query || payload.query || "—", rpki.status || r.holder || "");
  wrap.append(inspectZone(window.t("inspect.announcement"), [kvTable([
    [window.t("inspect.origin_asn"), r.origin_asn != null ? inspectBtn("asn", r.origin_asn, "probe-asn", `AS${r.origin_asn}`) : "—"],
    [window.t("inspect.holder"), r.holder],
    [window.t("inspect.announced"), r.announced == null ? "—" : String(r.announced)],
    ["RPKI", rpki.status || "—"],
    [window.t("inspect.origins"), (r.origins || []).map((o) => `AS${o.asn} ${o.holder || ""}`.trim()).join(", ")],
  ])]));
  return wrap;
}

function shortTraceError(text) {
  const raw = String(text || "");
  const m = raw.match(/(\d+(?:\.\d+)?)\s*s/i);
  if (/timed out/i.test(raw)) return m ? `timed out after ${Number(m[1]).toFixed(0)}s` : "timed out";
  return raw;
}

function renderDnstrace(payload) {
  const r = payload.result || {};
  const hops = r.hops || [];
  const failed = hops.filter((h) => h.error).length;
  const wrap = reportShell(
    window.t("inspect.dnstrace.label"),
    r.name || payload.query || "—",
    `${r.qtype || "A"} · ${window.t("inspect.iterative_iana")}`,
    [
      { strong: String(hops.length), label: window.t("inspect.hops") },
      failed ? { strong: String(failed), label: window.t("inspect.timeouts"), cls: "fail" } : null,
    ],
  );
  if (payload.error || r.error) wrap.append(el("p", "inspect-break", payload.error || r.error));
  const list = el("div", "trace-hops");
  hops.forEach((hop, i) => {
    const card = el("section", `inspect-zone ${hop.error ? "bogus" : "secure"}`.trim());
    const head = el("div", "trace-hop-head");
    head.append(el("h3", "", hop.zone || `hop ${i + 1}`));
    head.append(el("span", "server", hop.server || "—"));
    card.append(head);
    card.append(el("p", hop.error ? "bad" : "muted", hop.error ? shortTraceError(hop.error) : (hop.rcode || "—")));
    const rows = (hop.answers && hop.answers.length) ? hop.answers : (hop.authority || []);
    if (rows.length) {
      const ul = el("ul", "inspect-keys");
      for (const rr of rows) {
        const li = document.createElement("li");
        li.append(el("b", "", rr.type || "RR"));
        li.append(document.createTextNode(" " + (rr.data || "")));
        ul.append(li);
      }
      card.append(ul);
    }
    list.append(card);
  });
  wrap.append(list);
  return wrap;
}

function renderHttpInspect(payload) {
  const r = payload.result || {};
  const wrap = reportShell(window.t("inspect.http.label"), r.final_url || r.query || payload.query || "—", r.status != null ? String(r.status) : "");
  wrap.append(inspectZone(window.t("inspect.response"), [kvTable([
    [window.t("inspect.status"), r.status],
    [window.t("inspect.version"), r.http_version],
    ["ALPN", r.alpn],
    ["TTFB", r.ttfb_ms != null ? window.t("status.ms", { n: r.ttfb_ms }) : null],
    [window.t("inspect.redirects"), r.redirects],
    ["HSTS", r.hsts],
  ])]));
  for (const hop of r.chain || []) {
    const card = inspectZone(
      `${hop.status} ${hop.reason || ""} · ${hop.url || ""}`.trim(),
      [el("p", "muted", `TTFB ${hop.ttfb_ms ?? "—"} ms · ${hop.http_version || ""} · ${hop.server || ""}`)],
    );
    const headers = hop.headers || {};
    const rows = Object.entries(headers).slice(0, 24).map(([k, v]) => [k, v]);
    if (rows.length) card.append(kvTable(rows));
    wrap.append(card);
  }
  return decorateReport(wrap, payload);
}

function renderPtr(payload) {
  const r = payload.result || {};
  const wrap = reportShell(
    window.t("inspect.ptr.label"),
    r.ip || payload.query || "—",
    r.detail || (r.fcrdns ? window.t("inspect.forward_confirmed") : window.t("inspect.not_confirmed")),
    [{ strong: r.fcrdns ? window.t("rdap.yes") : window.t("rdap.no"), label: "FCrDNS", cls: r.fcrdns ? "pass" : "fail" }],
  );
  wrap.append(inspectZone(window.t("inspect.reverse"), [kvTable([["PTR", (r.ptr || []).join(", ") || window.t("inspect.none")]])]));
  if ((r.forward || []).length) {
    const table = el("table", "inspect-table");
    const tbody = document.createElement("tbody");
    for (const row of r.forward) {
      const tr = document.createElement("tr");
      tr.append(el("td", "fill", row.name));
      tr.append(el("td", "fill", (row.addresses || []).join(", ")));
      tr.append(el("td", row.matches ? "ok" : "bad", row.matches ? window.t("inspect.matches") : window.t("inspect.no_match")));
      tbody.append(tr);
    }
    table.append(tbody);
    wrap.append(inspectZone(window.t("inspect.forward_confirm"), [table]));
  }
  return wrap;
}

function renderMail(payload) {
  const r = payload.result || {};
  const sub = r.null_mx
    ? window.t("inspect.mail.null_mx")
    : ((r.mx || []).length ? `${r.mx.length} MX` : window.t("inspect.no_mx"));
  const wrap = reportShell(window.t("inspect.mail.label"), r.domain || payload.query || "—", sub);
  wrap.append(inspectZone(window.t("inspect.records"), [kvTable([
    ["MX", (r.mx || []).map((m) => `${m.preference} ${m.host}`).join(", ") || window.t("inspect.none")],
    ["SPF", (r.spf || []).join(" ") || window.t("inspect.none")],
    ["DMARC", (r.dmarc || []).join(" ") || window.t("inspect.none")],
    ["DKIM", (r.dkim || []).map((d) => d.selector).join(", ") || window.t("inspect.no_common_dkim")],
  ])]));
  if (r.smtp) {
    wrap.append(inspectZone("SMTP", [kvTable([
      [window.t("inspect.smtp_host"), `${r.smtp.host}:${r.smtp.port}`],
      [window.t("inspect.banner"), r.smtp.banner],
      ["EHLO", r.smtp.ehlo],
      ["STARTTLS", r.smtp.starttls ? window.t("rdap.yes") : window.t("rdap.no")],
      ["SMTP error", r.smtp.error],
    ])]));
  }
  return wrap;
}

function renderTcp(payload) {
  const r = payload.result || {};
  const status = r.status || (r.ok === false ? "error" : (payload.ok === false ? "error" : "ok"));
  const statusLabel = window.t(`inspect.tcp.status.${status}`);
  const wrap = reportShell(
    window.t("inspect.tcp.label"),
    `${r.host || payload.query}:${r.port || ""}`,
    r.peer || statusLabel,
  );
  wrap.append(inspectZone(window.t("inspect.session"), [kvTable([
    [window.t("inspect.status"), statusLabel],
    [window.t("inspect.peer"), r.peer],
    ["RTT", r.rtt_ms != null ? window.t("status.ms", { n: r.rtt_ms }) : null],
    [window.t("inspect.banner"), r.banner],
    [window.t("result.error"), r.error],
  ])]));
  return decorateReport(wrap, payload);
}

function renderPmtu(payload) {
  const r = payload.result || {};
  const wrap = reportShell(window.t("inspect.pmtu.label"), r.host || payload.query || "—", r.path_mtu != null ? window.t("inspect.bytes", { n: r.path_mtu }) : window.t("rdap.unknown"));
  wrap.append(inspectZone(window.t("inspect.probe"), [kvTable([
    [window.t("inspect.pmtu.label"), r.path_mtu != null ? window.t("inspect.bytes", { n: r.path_mtu }) : window.t("rdap.unknown")],
    [window.t("inspect.payload"), r.payload_bytes],
    [window.t("inspect.note"), r.note],
  ])]));
  return decorateReport(wrap, payload);
}

function renderWhois(payload) {
  const r = payload.result || {};
  const wrap = renderRdap(payload);
  return wrap;
}

  function printableError(err) {
    const text = String(err == null ? "" : err);
    if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(text)) {
      return window.t("inspect.http.protocol_error");
    }
    return text;
  }

  function paintInspect(payload) {
    payload = payload || {};
    const kind = payload.kind;
    const result = payload.result;
    if (kind === "apex" && result && result.sections) return renderApex(payload);
    if (kind === "register" && result && result.squares) return renderRegister(payload);
    if (["ping", "traceroute", "mtr", "tcptraceroute"].includes(kind) && result) return renderProbe(payload);
    if (kind === "dnssec" && result) return renderDnssec(payload);
    if (kind === "tls") return renderTls(payload);
    if (kind === "dns" && result) return renderDns(payload);
    if ((kind === "rdap" || kind === "asn" || kind === "whois") && result) return renderRdap(payload);
    if ((kind === "ip" || kind === "country") && result) return renderIp(payload);
    if (kind === "reputation" && result) return renderReputation(payload);
    if (kind === "bgp" && result) return renderBgp(payload);
    if (kind === "dnstrace" && result) return renderDnstrace(payload);
    if (kind === "http" && result) return renderHttpInspect(payload);
    if (kind === "ptr" && result) return renderPtr(payload);
    if (kind === "mail" && result) return renderMail(payload);
    if (kind === "tcp" && result) return renderTcp(payload);
    if (kind === "pmtu" && result) return renderPmtu(payload);
    const err = payload.error || (payload.ok === false ? window.t("inspect.failed") : null);
    if (err) {
      const p = el("p");
      p.textContent = printableError(err);
      return p;
    }
    const pre = document.createElement("pre");
    pre.textContent = JSON.stringify(payload, null, 2);
    return pre;
  }

  window.encodeToken = encodeToken;
  window.mtrCyclesQuery = mtrCyclesQuery;
  window.toolPath = toolPath;
  window.toolsFor = toolsFor;
  window.INSPECT_TOOLS = INSPECT_TOOLS;
  window.paintInspect = paintInspect;
  window.paintHistoryBar = paintHistoryBar;
  window.historyUrl = historyUrl;
  window.diffSummaryBits = diffSummaryBits;
  window.copyText = copyText;
  window.bindHistPermalink = bindHistPermalink;
  window.el = el;
})();

(function () {
  function fillPageHistory() {
    if (document.getElementById("result-box")) return;
    const host = document.getElementById("result-history");
    const node = document.getElementById("report-payload");
    if (!host || !node || typeof window.paintHistoryBar !== "function") return;
    let payload;
    try { payload = JSON.parse(node.textContent); }
    catch (err) { return; }
    window.paintHistoryBar(host, payload);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", fillPageHistory);
  else fillPageHistory();
})();


(function () {
  const cache = new Map();
  const open = new Map();
  let z = 80;

  function encodeToken(value) {
    return (window.encodeToken || function (v) {
      return encodeURIComponent(v).replace(/%3A/gi, ":").replace(/%2F/gi, "/");
    })(value);
  }

  const aborts = new Map();
  const waitTimers = new Map();
  let howtoSeq = 0;

  function wallCli(path) {
    const raw = String(path || "/");
    let p = raw, query = "";
    const qi = raw.indexOf("?");
    if (qi >= 0) { p = raw.slice(0, qi); query = raw.slice(qi + 1); }
    const qs = new URLSearchParams(query);
    const parts = p.replace(/^\/+/, "").replace(/\/+$/, "").split("/").filter(Boolean).map((s) => {
      try { return decodeURIComponent(s); } catch { return s; }
    });
    if (!parts.length) return "looking-glass ip";
    const head = parts[0].toLowerCase();
    if (head === "as" && parts.length === 1) return "looking-glass asn";
    if (head.startsWith("as") && /^\d+$/.test(head.slice(2))) return `looking-glass asn ${head.slice(2)}`;
    if (head === "dns") {
      const bits = ["looking-glass", "dns"];
      const server = qs.get("server");
      const port = qs.get("port");
      if (server) bits.push("@" + server + (port ? `:${port}` : ""));
      bits.push(parts[1] || "example.com");
      if (parts[2] && parts[2].toUpperCase() !== "A") bits.push(parts[2]);
      else if (port && !server) bits.push("-p", port);
      return bits.join(" ");
    }
    const map = {
      dnssec: "dnssec", tls: "tls", apex: "apex", ping: "ping", traceroute: "traceroute",
      mtr: "mtr", tcptraceroute: "tcptraceroute", rdap: "rdap", whois: "whois",
      reputation: "reputation", bgp: "bgp", dnstrace: "dnstrace", http: "http",
      ptr: "ptr", mail: "mail", tcp: "tcp", pmtu: "pmtu",
    };
    if (map[head]) {
      if (head === "http") {
        const urlParam = (qs.get("url") || "").trim();
        if (urlParam) return ["looking-glass", "http", urlParam].join(" ");
        const extra = parts.slice(1);
        let target = "";
        if (extra.length && ["http:", "https:"].includes(extra[0].toLowerCase()) && extra.length > 1) {
          target = extra[0] + "//" + extra.slice(1).join("/");
        } else {
          target = extra.join("/");
        }
        const scheme = (qs.get("scheme") || "").toLowerCase();
        if ((scheme === "http" || scheme === "https") && target && !target.includes("://")) {
          target = `${scheme}://${target}`;
        }
        return ["looking-glass", "http", target].filter(Boolean).join(" ");
      }
      const cmd = ["looking-glass", map[head]];
      if (parts[1]) cmd.push(parts[1]);
      if ((head === "tls" || head === "tcptraceroute" || head === "tcp") && parts[2]) cmd.push("-p", parts[2]);
      if (head === "whois" && ["1", "true", "yes", "legacy", "whois"].includes((qs.get("legacy") || "").toLowerCase())) cmd.push("--legacy");
      if (head === "tls") {
        const sni = (qs.get("sni") || "").trim();
        if (sni) cmd.push("--sni", sni);
      }
      if (head === "dnstrace" && parts[2]) cmd.push("-t", parts[2]);
      if (head === "mtr") {
        const cycles = (qs.get("cycles") || "").trim();
        if (cycles) cmd.push("--cycles", cycles);
      }
      return cmd.join(" ");
    }
    return `looking-glass ip ${parts[0]}`;
  }

  function lookupHowto(path) {
    const origin = (location.origin || "").replace(/\/$/, "");
    const host = origin.replace(/^https?:\/\//, "");
    const https = origin.startsWith("https://");
    const url = (!path || path === "/") ? `${origin}/` : origin + (path.startsWith("/") ? path : `/${path}`);
    const prog = https ? "https" : "http";
    const tail = path === "/" ? "/" : path;
    return {
      curl: `curl -sS -H 'Accept: application/json' ${url}`,
      httpie: `${prog} ${host}${tail} Accept:application/json`,
      cli: wallCli(path),
    };
  }

  function howtoPath(path, payload) {
    const q = payload && payload.query;
    if (payload && payload.kind === "http" && q && String(q).includes("://")) {
      return "/http?url=" + encodeURIComponent(q);
    }
    if (payload && (payload.kind === "tls" || payload.kind === "tcp") && q && !String(q).includes("://")) {
      const host = String(q).trim();
      const port = payload.result && payload.result.port;
      if (payload.kind === "tls") {
        if (port && Number(port) !== 443) return "/tls/" + host + "/" + port;
        return "/tls/" + host;
      }
      return "/tcp/" + host + "/" + (port || 443);
    }
    return path;
  }

  function bindHowtoCopy(root) {
    if (!root) return;
    root.querySelectorAll(".term pre, .howto pre, pre.cli").forEach(function (node) {
      if (node.dataset.copyBound) return;
      node.dataset.copyBound = "1";
      if (!node.getAttribute("data-copied")) {
        node.setAttribute("data-copied", window.t ? window.t("term.copied") : " copied");
      }
      node.addEventListener("dblclick", function (event) {
        event.preventDefault();
        const text = node.innerText.replace(/\s*copied\s*$/, "").trim();
        if (!text) return;
        if (typeof window.copyText === "function") {
          window.copyText(node, text);
          return;
        }
        navigator.clipboard.writeText(text).then(function () {
          node.classList.add("copied");
          setTimeout(function () { node.classList.remove("copied"); }, 1200);
        }).catch(function () {
          const range = document.createRange();
          range.selectNodeContents(node);
          const sel = window.getSelection();
          sel.removeAllRanges();
          sel.addRange(range);
        });
      });
    });
  }

  function paintHowto(path) {
    const lines = lookupHowto(path);
    const uid = "howto-" + (++howtoSeq);
    const wrap = document.createElement("section");
    wrap.className = "howto";
    wrap.title = window.t ? window.t("gui.howto.copy", "Double-click a command to copy") : "";
    const tabs = document.createElement("div");
    tabs.className = "tabs term";
    function radio(id, checked) {
      const input = document.createElement("input");
      input.type = "radio";
      input.name = uid;
      input.id = id;
      if (checked) input.checked = true;
      return input;
    }
    tabs.append(radio(uid + "-curl", true), radio(uid + "-httpie", false), radio(uid + "-cli", false));
    const bar = document.createElement("div");
    bar.className = "term-bar";
    const tablist = document.createElement("div");
    tablist.className = "tablist";
    function tabLabel(id, key, fallback) {
      const label = document.createElement("label");
      label.htmlFor = id;
      label.textContent = window.t ? window.t(key, fallback) : fallback;
      return label;
    }
    tablist.append(
      tabLabel(uid + "-curl", "gui.howto.curl", "curl"),
      tabLabel(uid + "-httpie", "gui.howto.httpie", "HTTPie"),
      tabLabel(uid + "-cli", "gui.howto.cli", "CLI")
    );
    bar.append(tablist);
    tabs.append(bar);
    function panel(cls) {
      const div = document.createElement("div");
      div.className = "panel " + cls;
      div.append(document.createElement("pre"));
      return div;
    }
    tabs.append(panel("panel-curl"), panel("panel-httpie"), panel("panel-cli"));
    wrap.append(tabs);
    wrap.querySelector(".panel-curl pre").textContent = lines.curl;
    wrap.querySelector(".panel-httpie pre").textContent = lines.httpie;
    wrap.querySelector(".panel-cli pre").textContent = lines.cli;
    bindHowtoCopy(wrap);
    return wrap;
  }

  function probeKindFromPath(path) {
    const hrefPath = String(path || "/").split("?")[0];
    const match = hrefPath.match(/^\/(ping|traceroute|mtr|tcptraceroute|dnssec|tls|rdap|whois|bgp|dnstrace|http|mail|pmtu|tcp|ptr|reputation)\//);
    if (match) return match[1];
    if (/^\/AS\d+/i.test(hrefPath)) return "rdap";
    return "";
  }

  function probeWaitNode(path) {
    const kind = probeKindFromPath(path);
    const hrefPath = String(path || "/").split("?")[0];
    const qs = new URLSearchParams(String(path || "").includes("?") ? String(path).slice(String(path).indexOf("?") + 1) : "");
    let target = "";
    try {
      target = /^\/AS\d+/i.test(hrefPath)
        ? hrefPath.replace(/^\//, "")
        : decodeURIComponent(hrefPath.split("/").slice(kind ? 2 : 1).join("/") || hrefPath.replace(/^\//, ""));
    } catch (err) {
      target = hrefPath.replace(/^\//, "");
    }
    let mtrN = qs.get("cycles");
    if (!mtrN) {
      try {
        const boot = JSON.parse((document.getElementById("boot") || {}).textContent || "{}");
        mtrN = (boot.mtr && boot.mtr.cycles) || 10;
      } catch (err) {
        mtrN = 10;
      }
    }
    const wrap = document.createElement("div");
    wrap.className = "probe-wait";
    const kicker = document.createElement("p");
    kicker.className = "probe-kicker";
    kicker.textContent = kind || (window.t ? window.t("gui.pill.loading") : "Loading…");
    const title = document.createElement("h2");
    title.className = "probe-domain";
    title.textContent = target || "…";
    const hints = {
      ping: window.t("gui.wait.ping"),
      traceroute: window.t("gui.wait.traceroute"),
      tcptraceroute: window.t("gui.wait.tcptraceroute"),
      mtr: window.t("gui.wait.mtr", { n: mtrN }),
      dnssec: window.t("gui.wait.dnssec"),
      tls: window.t("gui.wait.tls"),
      rdap: window.t("gui.wait.rdap"),
      whois: window.t("gui.wait.whois"),
      bgp: window.t("gui.wait.bgp"),
      dnstrace: window.t("gui.wait.dnstrace"),
      http: window.t("gui.wait.http"),
      ptr: window.t("gui.wait.ptr"),
      mail: window.t("gui.wait.mail"),
      tcp: window.t("gui.wait.tcp"),
      pmtu: window.t("gui.wait.pmtu"),
      reputation: window.t("gui.wait.reputation"),
      register: window.t("gui.wait.register"),
    };
    const sub = document.createElement("p");
    sub.className = "probe-sub";
    sub.textContent = hints[kind] || (window.t ? window.t("gui.working") : "Working…");
    const bar = document.createElement("div");
    bar.className = "probe-progress";
    bar.append(document.createElement("span"));
    const elapsed = document.createElement("p");
    elapsed.className = "probe-sub";
    elapsed.textContent = window.t("gui.elapsed", { n: 0 });
    wrap.append(kicker, title, sub, bar, elapsed);
    wrap._elapsed = elapsed;
    wrap._started = Date.now();
    return wrap;
  }

  function raise(pop) {
    if (window.lookingGlassWindows) {
      window.lookingGlassWindows.raise(pop);
      return;
    }
    z += 1;
    pop.style.zIndex = String(z);
  }

  function closePop(pop) {
    if (!pop) return;
    const winId = pop.dataset.winId;
    if (window.lookingGlassWindows && winId) window.lookingGlassWindows.detach(winId);
    for (const [id, node] of [...open.entries()]) {
      if (node !== pop) continue;
      const ctrl = aborts.get(id);
      if (ctrl) ctrl.abort();
      aborts.delete(id);
      const timer = waitTimers.get(id);
      if (timer) clearInterval(timer);
      waitTimers.delete(id);
      open.delete(id);
    }
    pop.remove();
  }

  function topPop() {
    if (window.lookingGlassWindows) return window.lookingGlassWindows.top();
    let best = null;
    let bestZ = -1;
    for (const pop of open.values()) {
      const n = Number(pop.style.zIndex || 0);
      if (n >= bestZ) {
        bestZ = n;
        best = pop;
      }
    }
    return best;
  }

  function makeDraggable(pop) {
    if (window.lookingGlassWindows) return;
    const bar = pop.querySelector(".inspect-pop-bar");
    if (!bar) return;
    let startX = 0;
    let startY = 0;
    let origX = 0;
    let origY = 0;
    let moved = false;
    bar.addEventListener("pointerdown", (event) => {
      if (event.target.closest("button, a, input, select, textarea, label, .inspect-pop-actions")) return;
      if (event.button != null && event.button !== 0) return;
      event.preventDefault();
      raise(pop);
      bar.setPointerCapture(event.pointerId);
      moved = false;
      startX = event.clientX;
      startY = event.clientY;
      const rect = pop.getBoundingClientRect();
      origX = rect.left + window.scrollX;
      origY = rect.top + window.scrollY;
    });
    bar.addEventListener("pointermove", (event) => {
      if (!bar.hasPointerCapture(event.pointerId)) return;
      if (Math.abs(event.clientX - startX) + Math.abs(event.clientY - startY) > 2) moved = true;
      pop.style.left = `${Math.max(8, origX + event.clientX - startX)}px`;
      pop.style.top = `${Math.max(8, origY + event.clientY - startY)}px`;
    });
    bar.addEventListener("pointerup", () => {
      if (moved && window.lookingGlassWindows && window.lookingGlassWindows.nudge) window.lookingGlassWindows.nudge(pop);
    });
  }

  function lockPopSize(pop, opts) {
    const rect = pop.getBoundingClientRect();
    if ((!opts || opts.width !== false) && rect.width) pop.style.width = `${rect.width}px`;
    if ((!opts || opts.height !== false) && rect.height) pop.style.height = `${rect.height}px`;
  }

  function placePop(pop, anchor) {
    if (window.lookingGlassWindows && typeof window.lookingGlassWindows.place === "function") {
      window.lookingGlassWindows.place(pop, anchor);
      return;
    }
    const n = open.size;
    const rect = anchor && anchor.getBoundingClientRect ? anchor.getBoundingClientRect() : { left: 24, bottom: 24 };
    pop.style.left = `${Math.max(8, rect.left + window.scrollX + n * 28)}px`;
    pop.style.top = `${Math.max(8, (rect.bottom || 24) + window.scrollY + 8 + n * 20)}px`;
  }

  function createPop(id, title, loadingText, anchor, meta) {
    const existing = open.get(id);
    if (existing && document.body.contains(existing)) {
      if (window.lookingGlassWindows) window.lookingGlassWindows.front(id);
      else raise(existing);
      return existing;
    }
    if (existing) {
      open.delete(id);
      try { existing.remove(); } catch (err) {}
    }
    const pop = document.createElement("div");
    pop.className = "asn-pop inspect-pop loading";
    if (meta && meta.kind === "compare") pop.classList.add("compare-pop");
    pop.setAttribute("role", "dialog");
    pop.setAttribute("aria-busy", "true");
    const bar = document.createElement("div");
    bar.className = "inspect-pop-bar";
    const heading = document.createElement("strong");
    heading.className = "inspect-pop-title";
    heading.textContent = title;
    const close = document.createElement("button");
    close.type = "button";
    close.className = "inspect-pop-close";
    close.setAttribute("aria-label", window.t ? window.t("gui.close") : "Close");
    close.textContent = "×";
    close.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      closePop(pop);
    });
    bar.append(heading, close);
    const body = document.createElement("div");
    body.className = "inspect-pop-body";
    body.textContent = loadingText || (window.t ? window.t("gui.cache.loading") : "Loading…");
    pop.append(bar, body);
    document.body.append(pop);
    placePop(pop, anchor);
    makeDraggable(pop);
    lockPopSize(pop, { width: false });
    open.set(id, pop);
    if (window.lookingGlassWindows) {
      window.lookingGlassWindows.adopt(pop, {
        id,
        kind: (meta && meta.kind) || "inspect",
        title,
        meta: meta || {},
        onClose: function () { closePop(pop); },
      });
    } else {
      raise(pop);
    }
    return pop;
  }

  function unconstrainedFitWidth(root) {
    if (!root) return 0;
    function one(el) {
      if (!el) return 0;
      const s = el.style;
      const prev = { width: s.width, minWidth: s.minWidth, maxWidth: s.maxWidth };
      s.width = "max-content";
      s.minWidth = "max-content";
      s.maxWidth = "none";
      const w = Math.ceil(Math.max(el.scrollWidth || 0, el.getBoundingClientRect().width || 0));
      s.width = prev.width;
      s.minWidth = prev.minWidth;
      s.maxWidth = prev.maxWidth;
      return w;
    }
    let need = 0;
    root.querySelectorAll(
      "table, pre, .inspect, .probe, .howto, .apex, .compare-cols, .compare-wrap, .sec-graph, .inspect-with-history"
    ).forEach((node) => {
      need = Math.max(need, one(node));
    });
    return need || one(root);
  }

  function setBody(pop, node, loading) {
    const body = pop.querySelector(".inspect-pop-body");
    if (loading) {
      pop.classList.add("loading");
      pop.setAttribute("aria-busy", "true");
      body.textContent = typeof node === "string" ? node : (window.t ? window.t("gui.cache.loading") : "Loading…");
      return;
    }
    pop.classList.remove("loading");
    pop.removeAttribute("aria-busy");
    body.replaceChildren();
    if (typeof node === "string") body.textContent = node;
    else if (node) body.append(node);
    if (window.lookingGlassWindows && typeof window.lookingGlassWindows.fit === "function") {
      window.lookingGlassWindows.fit(pop);
    } else {
      const measure = window.lookingGlassWindows && typeof window.lookingGlassWindows.contentWidth === "function"
        ? window.lookingGlassWindows.contentWidth
        : null;
      const need = measure ? measure(body) : unconstrainedFitWidth(body);
      if (!need) return;
      const chrome = Math.max(0, pop.clientWidth - body.clientWidth);
      const want = Math.ceil(need + chrome + 8);
      const max = Math.max(8, window.innerWidth - 16);
      const cur = pop.getBoundingClientRect().width;
      const width = Math.max(cur, Math.min(max, want));
      if (width <= cur + 1) return;
      pop.style.width = width + "px";
      const box = pop.getBoundingClientRect();
      if (box.left + width > window.innerWidth - 8) {
        pop.style.left = Math.max(8, window.innerWidth - width - 8) + window.scrollX + "px";
      }
    }
  }

  function unwrapPayload(data) {
    if (!data || typeof data !== "object") return data || {};
    let body = data;
    if (
      data.payload &&
      typeof data.payload === "object" &&
      (data.payload.result || data.payload.kind) &&
      data.result == null
    ) {
      body = data.payload;
    }
    if (!body.kind && data.kind) {
      body = Object.assign({}, body, { kind: data.kind });
    }
    return body;
  }

  function paintPayload(data) {
    const payload = unwrapPayload(data);
    if (typeof window.paintInspect === "function") return window.paintInspect(payload);
    const pre = document.createElement("pre");
    pre.textContent = JSON.stringify(payload, null, 2);
    return pre;
  }

  function renderCompare(previous, current) {
    const wrap = document.createElement("div");
    wrap.className = "compare-wrap";
    const bits = typeof window.diffSummaryBits === "function" ? window.diffSummaryBits(current && current.diff) : [];
    if (bits.length) {
      const summary = document.createElement("section");
      summary.className = "inspect-zone compare-summary";
      const heading = document.createElement("h3");
      heading.textContent = window.t("inspect.diff.vs_previous");
      summary.append(heading);
      const p = document.createElement("p");
      p.className = "muted";
      p.textContent = bits.join(" · ");
      summary.append(p);
      wrap.append(summary);
    }
    const cols = document.createElement("div");
    cols.className = "compare-cols";
    function side(label, payload) {
      const card = document.createElement("section");
      card.className = "inspect-zone compare-side";
      const h = document.createElement("h3");
      h.textContent = label;
      card.append(h);
      const url = typeof window.historyUrl === "function" ? window.historyUrl(payload) : "";
      if (url) {
        const a = document.createElement("a");
        a.className = "hist-permalink";
        setSafeHref(a, url);
        a.textContent = url;
        if (typeof window.bindHistPermalink === "function") window.bindHistPermalink(a, url, payload);
        card.append(a);
      }
      card.append(paintPayload(payload));
      return card;
    }
    cols.append(
      side(window.t("inspect.diff.previous"), previous),
      side(window.t("inspect.diff.current"), current)
    );
    wrap.append(cols);
    return wrap;
  }

  async function openHistoryCompare(current, anchor) {
    const title = window.t("inspect.diff.vs_previous");
    const query = current && current.query ? String(current.query) : "";
    const headingText = query ? `${title} · ${query}` : title;
    let pop = open.get("compare");
    if (!pop || !document.body.contains(pop)) {
      pop = createPop("compare", headingText, window.t("gui.cache.loading"), anchor, { kind: "compare" });
      pop.classList.add("compare-pop");
    } else if (window.lookingGlassWindows) {
      window.lookingGlassWindows.front("compare");
    } else {
      raise(pop);
    }
    const heading = pop.querySelector(".inspect-pop-title");
    if (heading) heading.textContent = headingText;
    const prevId = current && current.prev_id;
    if (!prevId) {
      setBody(pop, window.t("inspect.diff.no_previous"));
      return;
    }
    setBody(pop, window.t("gui.cache.loading"), true);
    try {
      const res = await fetch("/history/" + encodeURIComponent(prevId), {
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      });
      const data = await res.json();
      const previous = unwrapPayload(data);
      if (!res.ok || !(previous.result || previous.kind)) {
        setBody(pop, window.t("inspect.diff.no_previous"));
        return;
      }
      setBody(pop, renderCompare(previous, current));
    } catch (err) {
      setBody(pop, window.t("inspect.diff.no_previous"));
    }
  }

  function fillFetched(pop, id, data, path) {
    const timer = waitTimers.get(id);
    if (timer) clearInterval(timer);
    waitTimers.delete(id);
    if (!data) {
      setBody(pop, window.t ? window.t("inspect.failed") : "Lookup failed");
      return;
    }
    const payload = unwrapPayload(data);
    const wrap = document.createElement("div");
    wrap.className = "inspect-with-history";
    wrap.append(paintPayload(payload));
    const hist = (payload.id || payload.history) ? payload : data;
    if (typeof window.paintHistoryBar === "function" && (hist.id || hist.history)) {
      const bar = document.createElement("div");
      bar.className = "result-history inspect-history";
      window.paintHistoryBar(bar, hist);
      wrap.append(bar);
    }
    const howtoPathUsed = howtoPath(path || pop.dataset.lookupPath || "", payload);
    if (howtoPathUsed) wrap.append(paintHowto(howtoPathUsed));
    setBody(pop, wrap);
  }

  function lookupTitle(path, fallback) {
    const hrefPath = String(path || "/").split("?")[0];
    const kind = probeKindFromPath(path);
    let target = "";
    try {
      target = decodeURIComponent(hrefPath.replace(/^\//, ""));
    } catch (err) {
      target = hrefPath.replace(/^\//, "");
    }
    if (fallback) return fallback;
    return kind ? `${kind} · ${target}` : (target || path || "/");
  }

  async function openLookup(path, opts) {
    opts = opts || {};
    path = path || "/";
    const id = opts.id || ("lookup:" + path);
    const title = opts.title || lookupTitle(path);
    const loadingText = opts.loadingText || (window.t ? window.t("gui.cache.loading") : "Loading…");
    const prev = aborts.get(id);
    if (prev) prev.abort();
    const ctrl = new AbortController();
    aborts.set(id, ctrl);
    cache.delete(id);
    let pop = open.get(id);
    if (!pop || !document.body.contains(pop)) {
      pop = createPop(id, title, loadingText, opts.anchor, opts.meta || { reopen: "lookup", path });
    } else if (window.lookingGlassWindows) {
      window.lookingGlassWindows.front(id);
    } else {
      raise(pop);
    }
    pop.dataset.lookupPath = path;
    const heading = pop.querySelector(".inspect-pop-title");
    if (heading) heading.textContent = title;
    const wait = probeWaitNode(path);
    setBody(pop, wait);
    const timer = setInterval(function () {
      if (!wait._elapsed) return;
      wait._elapsed.textContent = window.t("gui.elapsed", { n: Math.max(0, Math.round((Date.now() - wait._started) / 1000)) });
    }, 250);
    waitTimers.set(id, timer);
    try {
      const res = await fetch(path, {
        credentials: "same-origin",
        headers: { Accept: "application/json" },
        signal: ctrl.signal,
      });
      const data = await res.json();
      cache.set(id, data);
      if (aborts.get(id) !== ctrl) return;
      if (!open.has(id)) return;
      fillFetched(pop, id, data, path);
      if (typeof window.refreshHistory === "function") window.refreshHistory();
    } catch (err) {
      if (err.name === "AbortError") return;
      if (!open.has(id)) return;
      fillFetched(pop, id, { ok: false, error: String(err) }, path);
    }
  }

  function openLookupPayload(payload, path) {
    if (!payload) return;
    const used = path || payload.path || "/";
    const id = payload.id ? ("history:" + payload.id) : ("lookup:" + used);
    const title = lookupTitle(used, (payload.kind && payload.query) ? `${payload.kind} · ${payload.query}` : "");
    const pop = createPop(id, title, window.t ? window.t("gui.cache.loading") : "Loading…", null, { reopen: "payload" });
    pop.dataset.lookupPath = used;
    fillFetched(pop, id, payload, used);
  }

  async function openFetched(id, title, loadingText, url, anchor, meta) {
    return openLookup(url, { id, title, loadingText, anchor, meta });
  }

  function pickerBody(accept, target) {
    const tools = typeof window.toolsFor === "function" ? window.toolsFor(accept) : [];
    const wrap = document.createElement("div");
    wrap.className = "inspect-tool-picker";
    const hint = document.createElement("p");
    hint.className = "inspect-tool-hint";
    hint.textContent = accept === "ip"
      ? (window.t ? window.t("gui.tool.against_ip") : "Run a tool against this address.")
      : (window.t ? window.t("gui.tool.against_host") : "Run a tool against this hostname.");
    wrap.append(hint);
    let group = null;
    let list = null;
    for (const tool of tools) {
      if (tool.group !== group) {
        group = tool.group;
        const label = document.createElement("p");
        label.className = "inspect-tool-group";
        label.textContent = group;
        wrap.append(label);
        list = document.createElement("div");
        list.className = "inspect-tool-list";
        wrap.append(list);
      }
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "inspect-tool";
      btn.dataset.toolKind = tool.kind;
      btn.dataset.toolTarget = target;
      btn.textContent = tool.label;
      list.append(btn);
    }
    return wrap;
  }

  function openPicker(accept, target, anchor) {
    const id = `pick:${accept}:${target}`;
    const existing = open.get(id);
    if (existing && document.body.contains(existing)) {
      if (window.lookingGlassWindows) window.lookingGlassWindows.front(id);
      else raise(existing);
      return;
    }
    if (existing) open.delete(id);
    const pop = createPop(id, target, window.t ? window.t("gui.choose_tool") : "Choose a tool…", anchor, {
      reopen: "picker",
      accept,
      target,
    });
    setBody(pop, pickerBody(accept, target));
  }

  function openTool(kind, target, anchor, extras) {
    const tools = typeof window.toolsFor === "function" ? window.toolsFor("ip").concat(window.toolsFor("host")) : [];
    const tool = tools.find((row) => row.kind === kind) || { kind, label: kind, loading: window.t ? window.t("gui.cache.loading") : "Loading…" };
    extras = extras && typeof extras === "object" ? extras : {};
    const path = window.toolPath(kind, target, extras);
    openLookup(path, {
      title: `${tool.label} · ${target}`,
      loadingText: tool.loading,
      anchor,
      meta: { reopen: "tool", kind, target, extras },
    });
  }

  function openInspect(kind, key, anchor) {
    if (kind === "asn") {
      openFetched(`asn:${key}`, `AS${key}`, window.t ? window.t("gui.looking_up") : "Looking up…", `/AS${encodeToken(key)}`, anchor, {
        reopen: "asn",
        key,
      });
      return;
    }
    if (kind === "ip") {
      openPicker("ip", key, anchor);
      return;
    }
    openPicker("host", key, anchor);
  }

  document.addEventListener("click", (event) => {
    const toolBtn = event.target.closest(".inspect-tool");
    if (toolBtn) {
      event.preventDefault();
      const kind = toolBtn.getAttribute("data-tool-kind");
      const target = toolBtn.getAttribute("data-tool-target");
      if (kind && target) openTool(kind, target, toolBtn);
      return;
    }
    const asnBtn = event.target.closest("[data-asn]");
    const ipBtn = event.target.closest("[data-ip]");
    const domainBtn = event.target.closest("[data-domain]");
    if (!asnBtn && !ipBtn && !domainBtn) return;
    if (event.target.closest(".inspect-pop-close, .inspect-pop-min, .inspect-pop-refresh")) return;
    event.preventDefault();
    if (asnBtn) {
      const asn = String(asnBtn.getAttribute("data-asn") || "").replace(/^AS/i, "");
      if (asn) openInspect("asn", asn, asnBtn);
      return;
    }
    if (ipBtn) {
      const ip = String(ipBtn.getAttribute("data-ip") || "").trim();
      if (ip) openInspect("ip", ip, ipBtn);
      return;
    }
    const domain = String(domainBtn.getAttribute("data-domain") || "").trim().replace(/\.$/, "");
    if (domain) openInspect("domain", domain, domainBtn);
  });

  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    const node = topPop();
    if (!node) return;
    for (const owned of open.values()) {
      if (owned === node) {
        closePop(node);
        return;
      }
    }
  });

  window.clearAsnPopCache = function () {
    cache.clear();
  };
  window.openInspect = openInspect;
  window.openTool = openTool;
  window.openLookup = openLookup;
  window.openLookupPayload = openLookupPayload;
  window.paintHowto = paintHowto;
  window.wallCli = wallCli;
  window.showResult = function (payload, path) {
    openLookupPayload(payload, typeof path === "string" ? path : undefined);
  };
  window.openHistoryCompare = openHistoryCompare;
  if (window.lookingGlassWindows) {
    window.lookingGlassWindows.register("inspect", function (state) {
      const meta = (state && state.meta) || {};
      if (meta.reopen === "picker" && meta.accept && meta.target) {
        openPicker(meta.accept, meta.target);
        return;
      }
      if (meta.reopen === "asn" && meta.key) {
        openInspect("asn", meta.key);
        return;
      }
      if (meta.reopen === "tool" && meta.kind && meta.target) {
        openTool(meta.kind, meta.target, undefined, meta.extras);
        return;
      }
      if (meta.reopen === "lookup" && meta.path) {
        openLookup(meta.path);
      }
    });
  }
})();


document.querySelectorAll(".term pre, .howto pre, pre.cli").forEach(function (el) {
    if (el.dataset.copyBound) return;
    el.dataset.copyBound = "1";
    if (!el.getAttribute("data-copied")) {
      el.setAttribute("data-copied", window.t ? window.t("term.copied") : " copied");
    }
    el.addEventListener("dblclick", function (event) {
      event.preventDefault();
      const text = el.innerText.replace(/\s*copied\s*$/, "").trim();
      if (!text) return;
      if (typeof window.copyText === "function") {
        window.copyText(el, text);
        return;
      }
      navigator.clipboard.writeText(text).then(function () {
        el.classList.add("copied");
        setTimeout(function () { el.classList.remove("copied"); }, 1200);
      }).catch(function () {
        const range = document.createRange();
        range.selectNodeContents(el);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
      });
    });
  });


(function () {
    const docsLink = document.getElementById("status-docs");
    const onDocs =
      document.body.classList.contains("docs-page") ||
      /^\/docs\/?$/.test(location.pathname || "");
    if (docsLink && onDocs) {
      docsLink.textContent = window.t ? window.t("status.exit") : "exit";
      docsLink.setAttribute("href", "/");
      docsLink.removeAttribute("target");
      docsLink.removeAttribute("rel");
      docsLink.hidden = false;
    }
    const localeEl = document.getElementById("status-locale");
    if (localeEl && localeEl.tagName === "SELECT") {
      localeEl.addEventListener("change", function () {
        const code = String(localeEl.value || "").trim();
        if (!code) return;
        let cookie = "looking_glass_lang=" + encodeURIComponent(code)
          + "; Path=/; SameSite=Lax; Max-Age=31536000";
        if (location.protocol === "https:") cookie += "; Secure";
        document.cookie = cookie;
        location.reload();
      });
    }
    const hostEl = document.getElementById("status-host");
    const ipEl = document.getElementById("status-ip");
    const timeEl = document.getElementById("status-time");
    const rttEl = document.getElementById("status-rtt");
    const uptimeEl = document.getElementById("status-uptime");
    const loadEl = document.getElementById("status-load");
    const memEl = document.getElementById("status-mem");
    const vmEl = document.getElementById("status-vm");
    const ioEl = document.getElementById("status-io");
    const netEl = document.getElementById("status-net");
    const hostStatSeps = document.querySelectorAll(".site-head-cluster .status-host-sep");
    const modeEl = document.getElementById("status-mode");
    const verEl = document.getElementById("status-ver");
    const servicesBtn = document.getElementById("status-services");
    const authedEl = document.getElementById("status-auth-user");
    const regenBtn = document.getElementById("status-docs-regen");
    const dash = "—";
    let clockSkewMs = 0;
    let utcOffsetSec = 0;
    let tzLabel = "";
    let clockKnown = false;
    let signedIn = !!authedEl;
    let docsEnabled = false;
    let docsGenerated = false;
    try {
      const boot = JSON.parse(document.getElementById("status-boot").textContent);
      docsEnabled = !!boot.docs_enabled;
      docsGenerated = !!boot.docs_generated;
    } catch (err) {}

    function paintDocsChrome() {
      if (docsLink && !onDocs) docsLink.hidden = !docsEnabled;
      if (docsLink && onDocs) docsLink.hidden = false;
      if (regenBtn) regenBtn.hidden = !(signedIn && (onDocs || (docsEnabled && !docsGenerated)));
    }

    function applyDocsStatus(docs) {
      if (!docs || typeof docs !== "object") return;
      if ("enabled" in docs) docsEnabled = !!docs.enabled;
      if ("generated" in docs) docsGenerated = !!docs.generated;
      paintDocsChrome();
    }
    window.lookingGlassDocsChrome = applyDocsStatus;

    function pad(n) {
      return String(n).padStart(2, "0");
    }

    function formatServerTime(epochMs, utcOffset, tz) {
      const shifted = new Date(epochMs + utcOffset * 1000);
      return (
        shifted.getUTCFullYear() +
        "-" +
        pad(shifted.getUTCMonth() + 1) +
        "-" +
        pad(shifted.getUTCDate()) +
        " " +
        pad(shifted.getUTCHours()) +
        ":" +
        pad(shifted.getUTCMinutes()) +
        ":" +
        pad(shifted.getUTCSeconds()) +
        " " +
        tz
      );
    }

    function paintTime() {
      if (!clockKnown) {
        timeEl.textContent = dash;
        return;
      }
      timeEl.textContent = formatServerTime(Date.now() + clockSkewMs, utcOffsetSec, tzLabel);
    }

    function formatDuration(seconds) {
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

    function formatUptime(seconds) {
      const dur = formatDuration(seconds);
      const value = dur || dash;
      return window.t ? window.t("status.up", { value: value }) : ("system uptime " + value);
    }

    function fmtBytes(n) {
      const v = Number(n);
      if (!Number.isFinite(v) || v < 0) return dash;
      const units = ["B", "K", "M", "G", "T"];
      let x = v;
      let i = 0;
      while (x >= 1024 && i < units.length - 1) {
        x /= 1024;
        i += 1;
      }
      return (x >= 10 || i === 0 ? x.toFixed(0) : x.toFixed(1)) + units[i];
    }

    function setStat(el, sep, text) {
      if (!el) return;
      if (!text) {
        el.hidden = true;
        el.textContent = "";
        if (sep) sep.hidden = true;
      } else {
        el.hidden = false;
        el.textContent = text;
        if (sep) sep.hidden = false;
      }
    }

    function paintHostStats(data) {
      const mem = data && data.memory;
      setStat(
        memEl,
        hostStatSeps[0],
        mem && mem.total ? ("mem " + fmtBytes(mem.used) + "/" + fmtBytes(mem.total)) : ""
      );
      const vm = data && data.vm;
      setStat(
        vmEl,
        hostStatSeps[1],
        vm ? ("vm maj " + (vm.pgmajfault || 0) + " so " + (vm.pswpout || 0)) : ""
      );
      const io = data && data.io;
      let ioText = "";
      if (io && typeof io === "object") {
        const name = Object.keys(io)[0];
        if (name) {
          const row = io[name] || {};
          ioText = name + " " + fmtBytes((row.rsec || 0) * 512) + "/" + fmtBytes((row.wsec || 0) * 512);
        }
      }
      setStat(ioEl, hostStatSeps[2], ioText);
      const net = data && data.net;
      let netText = "";
      if (net && typeof net === "object") {
        const name = Object.keys(net)[0];
        if (name) {
          const row = net[name] || {};
          netText = name + " " + fmtBytes(row.rx_bytes) + "/" + fmtBytes(row.tx_bytes);
        }
      }
      setStat(netEl, hostStatSeps[3], netText);
    }

    window.lookingGlassFormatDuration = formatDuration;

    function paintAuth(user) {
      const name = user == null ? "" : String(user);
      if (!!name !== signedIn) {
        location.reload();
        return;
      }
      paintDocsChrome();
    }

    let serveHint = "";
    let httpsHint = "";
    let serveKind = "down";
    let httpsKind = "down";

    function paintServicesBtn() {
      if (!servicesBtn) return;
      const parts = [serveHint, httpsHint].filter(Boolean);
      servicesBtn.title = parts.join(" · ");
      servicesBtn.classList.toggle("is-down", serveKind === "down" || httpsKind === "down");
      servicesBtn.classList.toggle("is-warn", serveKind === "building" && httpsKind !== "down");
    }

    function paintServe(running, ready, uptime) {
      if (ready) {
        const dur = formatDuration(uptime);
        const label = window.t ? window.t("status.serve.up") : "intel up";
        serveHint = dur ? (label + " " + dur) : label;
        serveKind = "up";
      } else if (running) {
        serveHint = window.t ? window.t("status.serve.building") : "intel building";
        serveKind = "building";
      } else {
        serveHint = window.t ? window.t("status.serve.down") : "intel down";
        serveKind = "down";
      }
      paintServicesBtn();
    }

    function paintHttps(running, uptime) {
      if (running) {
        const dur = formatDuration(uptime);
        const label = window.t ? window.t("status.https.up") : "tls up";
        httpsHint = dur ? (label + " " + dur) : label;
        httpsKind = "up";
      } else {
        httpsHint = window.t ? window.t("status.https.down") : "tls down";
        httpsKind = "down";
      }
      paintServicesBtn();
    }

    function paintFail() {
      hostEl.textContent = dash;
      ipEl.textContent = "";
      clockKnown = false;
      paintTime();
      rttEl.textContent = dash;
      uptimeEl.textContent = window.t ? window.t("status.up", { value: dash }) : ("up " + dash);
      loadEl.textContent = window.t ? window.t("status.load", { value: dash }) : ("load " + dash);
      paintHostStats(null);
      modeEl.textContent = dash;
      if (verEl) verEl.textContent = dash;
      paintServe(false, false);
      paintHttps(false);
    }

    async function poll() {
      const started = performance.now();
      try {
        const res = await fetch("/status", {
          cache: "no-store",
          credentials: "same-origin",
          headers: { Accept: "application/json" },
        });
        const rtt = performance.now() - started;
        if (!res.ok) throw new Error("status");
        const data = await res.json();
        paintAuth(data.user);
        if (data.docs) applyDocsStatus(data.docs);
        hostEl.textContent = data.hostname || dash;
        const parts = [];
        if (data.ipv4) parts.push(data.ipv4);
        if (data.ipv6) parts.push(data.ipv6);
        ipEl.textContent = parts.join(" ") || data.ip || "";
        const epoch = Number(data.time_epoch);
        if (Number.isFinite(epoch)) {
          clockSkewMs = epoch * 1000 - Date.now();
          utcOffsetSec = Number(data.utc_offset) || 0;
          tzLabel = data.tz || "UTC";
          clockKnown = true;
        } else {
          clockKnown = false;
        }
        paintTime();
        rttEl.textContent = window.t ? window.t("status.ms", { n: Math.round(rtt) }) : (Math.round(rtt) + " ms");
        uptimeEl.textContent = formatUptime(data.uptime);
        if (Array.isArray(data.load) && data.load.length) {
          const loadVal = data.load.map((n) => Number(n).toFixed(2)).join(" ");
          loadEl.textContent = window.t ? window.t("status.load", { value: loadVal }) : ("load " + loadVal);
        } else {
          loadEl.textContent = window.t ? window.t("status.load", { value: dash }) : ("load " + dash);
        }
        paintHostStats(data);
        const mode = String(data.mode || "").toUpperCase();
        modeEl.textContent = mode === "ASGI" || mode === "WSGI" ? mode : dash;
        if (verEl) verEl.textContent = data.version || dash;
        if (data.serve) paintServe(data.serve.running, data.serve.ready, data.serve.uptime);
        if (data.https) paintHttps(data.https.running, data.https.uptime);
        window.lookingGlassStatus = data;
        document.dispatchEvent(new CustomEvent("looking-glass-status", { detail: data }));
      } catch (err) {
        paintFail();
      }
    }

    const loginBtn = document.getElementById("status-login");
    const loginLayer = document.getElementById("login-layer");
    const loginForm = document.getElementById("login-form");
    const loginClose = document.getElementById("login-close");
    const loginError = document.getElementById("login-error");

    function openLogin() {
      if (!loginLayer) return;
      loginLayer.hidden = false;
      const first = loginForm && loginForm.querySelector("input");
      if (first) first.focus();
    }

    function closeLogin() {
      if (loginLayer) loginLayer.hidden = true;
      if (loginError) {
        loginError.hidden = true;
        loginError.textContent = "";
      }
    }

    if (loginBtn) loginBtn.addEventListener("click", () => openLogin());
    if (loginClose) loginClose.addEventListener("click", () => closeLogin());
    if (loginLayer) {
      loginLayer.addEventListener("click", (event) => {
        if (event.target.id === "login-layer") closeLogin();
      });
    }
    if (loginForm) {
      loginForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const fd = new FormData(loginForm);
        try {
          const res = await fetch("/login", {
            method: "POST",
            credentials: "same-origin",
            headers: { Accept: "application/json", "Content-Type": "application/json" },
            body: JSON.stringify({
              password: String(fd.get("password") || ""),
            }),
          });
          const data = await res.json().catch(() => ({}));
          if (!res.ok || data.ok === false) {
            if (loginError) {
              loginError.hidden = false;
              loginError.textContent = data.error || (window.t ? window.t("gui.login.error") : "login failed");
            }
            return;
          }
          closeLogin();
          location.reload();
        } catch (err) {
          if (loginError) {
            loginError.hidden = false;
            loginError.textContent = String(err);
          }
        }
      });
    }

    const logoutBtn = document.getElementById("status-logout");
    if (logoutBtn) {
      logoutBtn.addEventListener("click", async () => {
        await fetch("/logout", { method: "POST", credentials: "same-origin", headers: { Accept: "application/json" } });
        location.reload();
      });
    }

    if (regenBtn) {
      regenBtn.addEventListener("click", async () => {
        regenBtn.disabled = true;
        try {
          const res = await fetch("/docs", {
            method: "POST",
            credentials: "same-origin",
            cache: "no-store",
            headers: { Accept: "application/json" },
          });
          if (res.ok) {
            if (onDocs) location.reload();
            else await poll();
          }
        } finally {
          regenBtn.disabled = false;
        }
      });
    }

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") closeLogin();
    });

    paintAuth(signedIn ? "admin" : "");
    poll();
    setInterval(poll, 5000);
    setInterval(paintTime, 1000);
  })();
