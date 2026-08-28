    const boot = JSON.parse(document.getElementById("boot").textContent);
    const typeSelect = document.getElementById("dns-type");
    const typeFilter = document.getElementById("type-filter");
    const tools = ["ip", "asn", "bgp", "dns", "dnstrace", "dnssec", "ptr", "register", "tls", "http", "apex", "mail", "reputation", "ping", "traceroute", "mtr", "tcptraceroute", "tcp", "pmtu", "rdap"];
    const toolAlias = { lookup: "ip", auto: "ip", path: "ping", trace: "traceroute", tcptrace: "tcptraceroute", whois: "rdap", rpki: "bgp", httpinspect: "http" };
    const toolNav = document.querySelector(".tool-nav");
    const toolTabs = [...toolNav.querySelectorAll("[role=tab]")];
    const toolPanels = [...document.querySelectorAll(".tool-panel")];
    const el = window.el;

    function showTool(id, { focus = false, hash = true } = {}) {
      if (!tools.includes(id)) id = "ip";
      for (const tab of toolTabs) {
        const on = tab.dataset.tool === id;
        tab.setAttribute("aria-selected", on ? "true" : "false");
        tab.tabIndex = on ? 0 : -1;
      }
      for (const panel of toolPanels) {
        panel.hidden = panel.dataset.tool !== id;
      }
      if (hash) {
        const next = `#${id}`;
        if (location.hash !== next) history.replaceState(null, "", next);
      }
      if (focus) {
        const input = document.querySelector(".tool-panel:not([hidden]) input, .tool-panel:not([hidden]) select");
        if (input) input.focus();
      }
    }

    function toolFromHash() {
      const raw = (location.hash || "").replace(/^#/, "").toLowerCase() || "ip";
      return toolAlias[raw] || raw;
    }

    function fillTypes() {
      const types = boot.types || [];
      const common = types.filter((t) => t.common);
      const rest = types.filter((t) => !t.common);
      typeSelect.replaceChildren();
      const addGroup = (label, rows) => {
        if (!rows.length) return;
        const group = document.createElement("optgroup");
        group.label = label;
        for (const row of rows) {
          const opt = document.createElement("option");
          opt.value = row.name;
          opt.textContent = row.meaning ? `${row.name} — ${row.meaning}` : `${row.name} (${row.value})`;
          opt.dataset.hay = `${row.name} ${row.value} ${row.meaning || ""}`.toLowerCase();
          if (row.name === "A") opt.selected = true;
          group.append(opt);
        }
        typeSelect.append(group);
      };
      addGroup(window.t("gui.common"), common);
      addGroup(window.t("gui.all_lookup_types"), rest.length ? rest : types);
    }

    function filterTypes() {
      const needle = typeFilter.value.trim().toLowerCase();
      let firstVisible = null;
      for (const opt of typeSelect.querySelectorAll("option")) {
        const hide = Boolean(needle) && !opt.dataset.hay.includes(needle);
        opt.hidden = hide;
        if (!hide && !firstVisible) firstVisible = opt;
      }
      const selected = typeSelect.selectedOptions[0];
      if (selected && selected.hidden && firstVisible) firstVisible.selected = true;
    }

    function formVal(sel) {
      const node = document.querySelector(sel);
      return node ? node.value.trim() : "";
    }

    function pathFromForms(kind) {
      const path = window.toolPath;
      if (kind === "self") return "/";
      if (kind === "ip") return path("ip", formVal("#form-ip [name=q]"));
      if (kind === "asn") return path("asn", formVal("#form-asn [name=q]"));
      if (kind === "dns") {
        return path("dns", formVal("#form-dns [name=name]"), {
          type: typeSelect.value || "A",
          server: formVal("#form-dns [name=server]"),
          port: formVal("#form-dns [name=port]"),
        });
      }
      if (kind === "apex") return path("apex", formVal("#form-apex [name=domain]"));
      if (kind === "dnssec") return path("dnssec", formVal("#form-dnssec [name=domain]"));
      if (kind === "tls") {
        return path("tls", formVal("#form-tls [name=host]") || "example.com", {
          port: formVal("#form-tls [name=port]"),
          sni: formVal("#form-tls [name=sni]"),
        });
      }
      if (kind === "bgp") return path("bgp", formVal("#form-bgp [name=target]"));
      if (kind === "dnstrace") {
        return path("dnstrace", formVal("#form-dnstrace [name=name]") || "example.com", {
          type: formVal("#form-dnstrace [name=type]") || "A",
        });
      }
      if (kind === "ptr") return path("ptr", formVal("#form-ptr [name=target]"));
      if (kind === "register") return path("register", formVal("#form-register [name=name]"));
      if (kind === "http") return path("http", formVal("#form-http [name=target]") || "example.com");
      if (kind === "mail") return path("mail", formVal("#form-mail [name=domain]"));
      if (kind === "tcp") {
        return path("tcp", formVal("#form-tcp [name=host]") || "example.com", {
          port: formVal("#form-tcp [name=port]") || "443",
        });
      }
      if (kind === "pmtu") return path("pmtu", formVal("#form-pmtu [name=target]") || "1.1.1.1");
      if (kind === "rdap") {
        return path("rdap", formVal("#form-rdap [name=target]") || "1.1.1.1", {
          legacy: (document.querySelector("#form-rdap [name=mode]:checked") || {}).value === "legacy",
        });
      }
      if (kind === "ping" || kind === "traceroute") {
        return path(kind, formVal(`#form-${kind} [name=target]`));
      }
      if (kind === "mtr") {
        const form = document.getElementById("form-mtr");
        const target = form ? String((form.querySelector("[name=target]") || {}).value || "").trim() : "";
        const cycles = form ? String((form.querySelector("[name=cycles]") || {}).value || "").trim() : "";
        return path("mtr", target, { cycles });
      }
      if (kind === "tcptraceroute") {
        return path("tcptraceroute", formVal("#form-tcptraceroute [name=target]") || "1.1.1.1", {
          port: formVal("#form-tcptraceroute [name=port]") || "443",
        });
      }
      return path("reputation", formVal("#form-rep [name=target]"));
    }

    function syncMtrRoute() {
      const code = document.getElementById("mtr-route");
      const form = document.getElementById("form-mtr");
      if (!code || !form) return;
      const raw = String((form.querySelector("[name=target]") || {}).value || "").trim();
      const cycles = String((form.querySelector("[name=cycles]") || {}).value || "").trim();
      const token = raw ? window.encodeToken(raw) : "<host>";
      const built = window.toolPath("mtr", raw || "x", { cycles });
      const qs = built.includes("?") ? built.slice(built.indexOf("?")) : "";
      code.textContent = `GET /mtr/${token}${qs}`;
    }

    function syncRdapRoute() {
      const code = document.getElementById("rdap-route");
      if (!code) return;
      const raw = formVal("#form-rdap [name=target]");
      const token = raw ? window.encodeToken(raw) : "<token>";
      const legacy = (document.querySelector("#form-rdap [name=mode]:checked") || {}).value === "legacy";
      code.textContent = legacy ? `GET /whois/${token}?legacy=1` : `GET /rdap/${token}`;
    }

    function runLookup(path) {
      if (typeof window.openLookup === "function") window.openLookup(path);
    }

    function bindForm(id, kind) {
      const form = document.getElementById(id);
      form.addEventListener("submit", (event) => {
        event.preventDefault();
        if (kind === "mtr") {
          const target = String((form.querySelector("[name=target]") || {}).value || "").trim();
          const cycles = String((form.querySelector("[name=cycles]") || {}).value || "").trim();
          runLookup(window.toolPath("mtr", target, { cycles }));
          return;
        }
        runLookup(pathFromForms(kind));
      });
    }

    fillTypes();
    typeFilter.addEventListener("input", filterTypes);
    bindForm("form-ip", "ip");
    bindForm("form-asn", "asn");
    bindForm("form-dns", "dns");
    bindForm("form-apex", "apex");
    bindForm("form-dnssec", "dnssec");
    bindForm("form-tls", "tls");
    bindForm("form-bgp", "bgp");
    bindForm("form-dnstrace", "dnstrace");
    bindForm("form-ptr", "ptr");
    bindForm("form-register", "register");
    bindForm("form-http", "http");
    bindForm("form-mail", "mail");
    bindForm("form-rdap", "rdap");
    const rdapForm = document.getElementById("form-rdap");
    rdapForm.querySelectorAll("[name=mode]").forEach((node) => {
      node.addEventListener("change", syncRdapRoute);
    });
    const rdapTarget = rdapForm.querySelector("[name=target]");
    if (rdapTarget) rdapTarget.addEventListener("input", syncRdapRoute);
    syncRdapRoute();
    bindForm("form-rep", "reputation");
    bindForm("form-ping", "ping");
    bindForm("form-traceroute", "traceroute");
    bindForm("form-mtr", "mtr");
    const mtrForm = document.getElementById("form-mtr");
    if (mtrForm) {
      mtrForm.querySelectorAll("[name=target], [name=cycles]").forEach((node) => {
        node.addEventListener("input", syncMtrRoute);
      });
      syncMtrRoute();
    }
    bindForm("form-tcptraceroute", "tcptraceroute");
    bindForm("form-tcp", "tcp");
    bindForm("form-pmtu", "pmtu");
    document.getElementById("lookup-self").addEventListener("click", () => {
      showTool("ip");
      runLookup("/");
    });
    toolNav.addEventListener("click", (event) => {
      const tab = event.target.closest("[role=tab]");
      if (!tab || !toolNav.contains(tab)) return;
      showTool(tab.dataset.tool, { focus: true });
    });
    toolNav.addEventListener("keydown", (event) => {
      const tab = event.target.closest("[role=tab]");
      if (!tab) return;
      const i = toolTabs.indexOf(tab);
      let next = -1;
      if (event.key === "ArrowRight" || event.key === "ArrowDown") next = (i + 1) % toolTabs.length;
      else if (event.key === "ArrowLeft" || event.key === "ArrowUp") next = (i - 1 + toolTabs.length) % toolTabs.length;
      else if (event.key === "Home") next = 0;
      else if (event.key === "End") next = toolTabs.length - 1;
      if (next < 0) return;
      event.preventDefault();
      toolTabs[next].focus();
      showTool(toolTabs[next].dataset.tool);
    });
    window.addEventListener("hashchange", () => showTool(toolFromHash(), { hash: false }));
    showTool(toolFromHash(), { hash: false });
