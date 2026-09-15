/* The site renders what the build computed. It does not evaluate filters.
 *
 * Every verdict on this page came out of c7n's own engine at build time,
 * through c7n-kit's trace(). Reimplementing ValueFilter here would produce a
 * second opinion that looks authoritative and drifts from the first one on
 * the day c7n changes, which is the failure the catalogue argues against.
 */

const DATA = { catalog: null, results: null };

const LABEL = { match: "fires", no_match: "no match", unknown: "unknown" };
const CLASS = { match: "is-fires", no_match: "is-clean", unknown: "is-unknown" };

const state = { policy: null, example: 0, framework: "fsbp", query: "", source: "examples" };

const $ = (id) => document.getElementById(id);

function escapeHtml(text) {
  return String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/* ---------------------------------------------------------------- yaml */

// Enough highlighting to read a policy: keys, comments, nothing else. A
// syntax highlighter would be a dependency for four colours.
function highlightYaml(text) {
  return escapeHtml(text)
    .split("\n")
    .map((line) => {
      if (/^\s*#/.test(line)) return `<span class="c">${line}</span>`;
      return line.replace(/^(\s*-?\s*)([A-Za-z0-9_.-]+)(:)/,
        (_, indent, key, colon) => `${indent}<span class="k">${key}</span>${colon}`);
    })
    .join("\n");
}

function yamlOf(node) {
  // The node's own filter, printed the way a policy writes it. Two levels
  // is enough: deeper trees are rendered as their children instead.
  const raw = node.raw;
  if (raw === null || raw === undefined) return "";
  if (typeof raw !== "object") return String(raw);
  const lines = [];
  for (const [key, value] of Object.entries(raw)) {
    if (Array.isArray(value)) {
      lines.push(`${key}:`);
      for (const item of value) {
        if (item && typeof item === "object") {
          lines.push("  - ...");
        } else {
          lines.push(`  - ${item}`);
        }
      }
    } else if (value && typeof value === "object") {
      lines.push(`${key}: ...`);
    } else {
      lines.push(`${key}: ${value}`);
    }
  }
  return lines.join("\n");
}

function describe(node) {
  const raw = node.raw;
  if (!raw || typeof raw !== "object") return node.kind;
  if (raw.key !== undefined) {
    const op = raw.op || "is";
    const value = raw.value === "absent" ? "never came back" : JSON.stringify(raw.value);
    return raw.value === "absent"
      ? `<code>${escapeHtml(raw.key)}</code> never came back`
      : `<code>${escapeHtml(raw.key)}</code> ${escapeHtml(op)} ${escapeHtml(value)}`;
  }
  return escapeHtml(raw.type || node.kind);
}

/* ------------------------------------------------------------ playground */

function policiesWithExamples() {
  return DATA.catalog.policies.filter((p) => p.has_examples);
}

function renderPolicyPicker() {
  const list = policiesWithExamples();
  $("policy-select").innerHTML = list
    .map((p) => `<option value="${p.name}"${p.name === state.policy ? " selected" : ""}>${p.name}</option>`)
    .join("");
}

function renderPlayground() {
  const policy = DATA.catalog.policies.find((p) => p.name === state.policy);
  if (!policy) return;
  const examples = (DATA.results[policy.name] || {}).examples || [];
  if (state.example >= examples.length) state.example = 0;
  const example = examples[state.example];

  $("yaml-file").textContent = policy.file;
  $("yaml").innerHTML = highlightYaml(policy.yaml || "(this policy's block could not be located in the file)");

  $("example-tabs").innerHTML = examples
    .map((e, i) => `<button type="button" data-i="${i}" aria-pressed="${i === state.example}">${escapeHtml(e.label)}</button>`)
    .join("");

  if (!example) {
    $("resource-json").textContent = "";
    $("verdict-head").innerHTML = "";
    $("nodes").innerHTML = "";
    return;
  }

  $("resource-json").innerHTML = highlightYaml(JSON.stringify(example.resource, null, 2));

  const head = $("verdict-head");
  head.className = `verdict-head ${CLASS[example.root]}`;
  head.innerHTML =
    `<span class="big">${example.root === "match" ? "Reported" : example.root === "no_match" ? "Not reported" : "No answer offline"}</span>` +
    `<p>${verdictNote(example)}</p>`;

  // Only the leaves carry an explanation a reader can act on; the operator
  // nodes are shown as the indentation around them.
  $("nodes").innerHTML = example.nodes
    .map((node) => {
      const depth = node.path.split(".").length - 1;
      const isOperator = ["or", "and", "not"].includes(node.kind);
      const text = isOperator ? `<span class="op">${node.kind}</span>` : describe(node);
      return `<li class="node ${CLASS[node.result]}" style="padding-left:${16 + depth * 18}px">
        <span class="tag">${LABEL[node.result]}</span>
        <span class="txt">${text}</span>
      </li>`;
    })
    .join("");
}

function verdictNote(example) {
  const leaves = example.nodes.filter((n) => !["or", "and", "not"].includes(n.kind));
  const fired = leaves.filter((n) => n.result === "match");
  if (example.root === "unknown") {
    return "A filter here needs an AWS call, so offline there is no answer. It is never reported as a pass.";
  }
  if (example.root === "no_match") {
    return "Every condition was evaluated and none matched.";
  }
  if (fired.length === 1 && leaves.length > 1) {
    return "One condition matched. Delete it and this resource disappears from the report.";
  }
  return "The policy matched this resource.";
}

/* -------------------------------------------------------------- controls */

const FRAMEWORK_LABEL = {
  fsbp: "AWS FSBP",
  "pci-4.0": "PCI DSS 4.0",
  "cis-aws": "CIS AWS Foundations",
};

function renderCoverage() {
  const counts = DATA.catalog.counts.frameworks;
  $("coverage").innerHTML = Object.entries(counts)
    .map(([key, value]) => {
      const bar = value.complete
        ? `<div class="seg" role="img" aria-label="${value.covered} of ${value.total} covered">
             <i class="on" style="flex:${value.covered}"></i>
             <i class="off" style="flex:${Math.max(value.total - value.covered, 0)}"></i>
           </div>`
        : `<div class="seg partial"></div>`;
      const numbers = value.complete
        ? `<b>${value.covered}</b> / ${value.total} controls`
        : `<b>${value.covered}</b> controls cited`;
      return `<div class="board-row">
        <span class="name">${FRAMEWORK_LABEL[key] || key}</span>
        ${bar}
        <span class="val">${numbers}</span>
        <span class="state ${value.complete ? "complete" : "partial"}">${value.complete ? "complete" : "partial"}</span>
      </div>`;
    })
    .join("");
}

function renderControls() {
  const query = state.query.toLowerCase().trim();
  const rows = DATA.catalog.controls.filter((c) => {
    if (c.framework !== state.framework) return false;
    if (!query) return true;
    return (c.id + " " + c.policies.join(" ")).toLowerCase().includes(query);
  });

  $("ctl-count").textContent =
    `${rows.length} of ${DATA.catalog.controls.filter((c) => c.framework === state.framework).length} shown`;

  $("ctl-rows").innerHTML = rows
    .slice(0, 300)
    .map((c) => {
      const policies = c.covered
        ? c.policies.map((p) => `<button class="pol" type="button" data-policy="${escapeHtml(p)}">${escapeHtml(p)}</button>`).join("")
        : `<span class="none-yet">no policy cites it</span>`;
      const severity = c.severity
        ? `<span class="sev ${c.severity}">${c.severity}</span>`
        : `<span class="sev none">not covered</span>`;
      return `<div class="row ${c.covered ? "covered" : "uncovered"}">
        <span class="id">${escapeHtml(c.id)}</span>
        <span class="pols">${policies}</span>
        ${severity}
      </div>`;
    })
    .join("");
}

/* ------------------------------------------------------------------ tabs */

function showTab(button) {
  document.querySelectorAll(".masthead nav button").forEach((tab) => {
    const on = tab === button;
    tab.setAttribute("aria-selected", on ? "true" : "false");
    $(tab.getAttribute("aria-controls")).hidden = !on;
  });
}

function openPolicy(name) {
  const policy = DATA.catalog.policies.find((p) => p.name === name);
  if (!policy) return;
  if (!policy.has_examples) {
    // Better than a panel with nothing in it: say why it is empty.
    state.policy = name;
    state.example = 0;
    showTab($("tab-run"));
    renderPolicyPicker();
    $("yaml-file").textContent = policy.file;
    $("yaml").innerHTML = highlightYaml(policy.yaml || "");
    $("example-tabs").innerHTML = "";
    $("resource-json").textContent = "";
    $("verdict-head").className = "verdict-head is-unknown";
    $("verdict-head").innerHTML =
      `<span class="big">No example yet</span><p>The tests that cover this policy build their resources with helpers rather than plain dictionaries, so the build could not read one to run here.</p>`;
    $("nodes").innerHTML = "";
    return;
  }
  state.policy = name;
  state.example = 0;
  showTab($("tab-run"));
  renderPolicyPicker();
  renderPlayground();
}

/* ------------------------------------------------------------------ boot */

async function boot() {
  const [catalog, results] = await Promise.all([
    fetch("data/catalog.json").then((r) => r.json()),
    fetch("data/results.json").then((r) => r.json()),
  ]);
  DATA.catalog = catalog;
  DATA.results = results;

  // The one policy that teaches the whole point in five seconds, when the
  // build produced it; otherwise whatever has examples.
  const preferred = "rds-storage-unencrypted";
  state.policy = catalog.policies.some((p) => p.name === preferred && p.has_examples)
    ? preferred
    : (policiesWithExamples()[0] || {}).name;

  $("stat-policies").textContent = catalog.counts.policies;
  $("stat-files").textContent = `policies, ${catalog.counts.files} services`;
  const fsbp = catalog.counts.frameworks.fsbp;
  $("stat-fsbp").innerHTML = `${fsbp.covered}<span class="muted">/${fsbp.total}</span>`;
  $("stat-examples").textContent = Object.values(results)
    .reduce((total, entry) => total + entry.examples.length, 0);
  $("footer-commit").textContent = catalog.commit;
  $("footer-commit-2").textContent = catalog.commit;
  $("footer-built").textContent = new Date(catalog.generated_at).toISOString().slice(0, 16).replace("T", " ") + " UTC";

  renderPolicyPicker();
  renderPlayground();
  renderCoverage();
  renderControls();
  indexBuilderData();
  renderBuilder();

  // The example the site opens on: the absent-key one when it exists,
  // because it is the case the catalogue exists for.
  const examples = (results[state.policy] || {}).examples || [];
  const absent = examples.findIndex((e) => /absent|missing/i.test(e.label));
  if (absent >= 0) {
    state.example = absent;
    renderPlayground();
  }
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".masthead nav button").forEach((tab) => {
    tab.addEventListener("click", () => showTab(tab));
  });

  $("policy-select").addEventListener("change", (e) => {
    state.policy = e.target.value;
    state.example = 0;
    renderPlayground();
    if (state.source === "paste") renderPasted();
  });

  $("example-tabs").addEventListener("click", (e) => {
    const button = e.target.closest("button");
    if (!button) return;
    state.example = Number(button.dataset.i);
    renderPlayground();
  });

  $("ctl-rows").addEventListener("click", (e) => {
    const button = e.target.closest("button.pol");
    if (!button) return;
    openPolicy(button.dataset.policy);
  });

  document.querySelectorAll("#fw-chips button").forEach((chip) => {
    chip.addEventListener("click", () => {
      document.querySelectorAll("#fw-chips button").forEach((c) => {
        c.setAttribute("aria-pressed", c === chip ? "true" : "false");
      });
      state.framework = chip.dataset.fw;
      renderControls();
    });
  });

  $("ctl-search").addEventListener("input", (e) => {
    state.query = e.target.value;
    renderControls();
  });

  boot().catch((error) => {
    document.querySelector(".wrap").insertAdjacentHTML(
      "afterbegin",
      `<p class="load-error">The catalogue did not load: ${escapeHtml(error.message)}. ` +
      `This page is built from the repository, so an empty page means the build did not run, ` +
      `not that there is nothing to show.</p>`
    );
  });
});

/* ------------------------------------------------------- paste your own */

// The one answer on this page c7n did not compute. It runs the port in
// value_filter.js, which is a subset: anything it does not implement exactly
// comes back unknown, and CI fails the build if it ever contradicts c7n over
// the whole catalogue.
function renderPasted() {
  const policy = DATA.catalog.policies.find((p) => p.name === state.policy);
  const raw = $("paste-input").value.trim();
  const error = $("paste-error");

  if (!policy) return;
  if (!raw) {
    error.hidden = true;
    $("verdict-head").className = "verdict-head";
    $("verdict-head").innerHTML =
      `<span class="big">Waiting</span><p>Paste one resource as JSON, the way a describe call returns it.</p>`;
    $("nodes").innerHTML = "";
    return;
  }

  let resource;
  try {
    resource = JSON.parse(raw);
  } catch (e) {
    error.hidden = false;
    error.textContent = `That is not valid JSON: ${e.message}`;
    return;
  }
  if (Array.isArray(resource)) resource = resource[0];
  error.hidden = true;

  const evaluated = C7N.evaluate(policy.filters, resource);

  const head = $("verdict-head");
  head.className = `verdict-head ${CLASS[evaluated.root]}`;
  head.innerHTML =
    `<span class="big">${evaluated.root === "match" ? "Reported" : evaluated.root === "no_match" ? "Not reported" : "No answer here"}</span>` +
    `<p>${evaluated.root === "unknown"
      ? "Part of this policy needs an AWS call, or uses something this browser port does not implement. Run it locally with c7n-kit for the real answer."
      : "Evaluated in your browser, by the subset of c7n that CI checks against the catalogue."}</p>`;

  $("nodes").innerHTML = evaluated.nodes
    .map((node) => {
      const depth = node.path.split(".").length - 1;
      const isOperator = ["or", "and", "not"].includes(node.kind);
      const text = isOperator ? `<span class="op">${node.kind}</span>` : describe(node);
      return `<li class="node ${CLASS[node.result]}" style="padding-left:${16 + depth * 18}px">
        <span class="tag">${LABEL[node.result]}</span><span class="txt">${text}</span></li>`;
    })
    .join("");
}

function setSource(mode) {
  state.source = mode;
  $("src-examples").setAttribute("aria-pressed", String(mode === "examples"));
  $("src-paste").setAttribute("aria-pressed", String(mode === "paste"));
  $("examples-pane").hidden = mode !== "examples";
  $("paste-pane").hidden = mode !== "paste";
  if (mode === "paste") {
    const policy = DATA.catalog.policies.find((p) => p.name === state.policy);
    const examples = (DATA.results[policy.name] || {}).examples || [];
    if (!$("paste-input").value && examples.length) {
      // Start from a real one, so the first edit is a change and not a blank page.
      $("paste-input").value = JSON.stringify(examples[state.example].resource, null, 2);
    }
    renderPasted();
  } else {
    renderPlayground();
  }
}

/* ---------------------------------------------------------------- builder */

const BUILDER = { keysByResource: new Map(), controls: [] };

function indexBuilderData() {
  for (const policy of DATA.catalog.policies) {
    const keys = BUILDER.keysByResource.get(policy.resource) || new Set();
    const walk = (filter) => {
      if (!filter || typeof filter !== "object") return;
      for (const operator of ["or", "and", "not"]) {
        if (Array.isArray(filter[operator])) { filter[operator].forEach(walk); return; }
      }
      if (typeof filter.key === "string" && /^[A-Za-z_][\w.]*$/.test(filter.key)) keys.add(filter.key);
    };
    (policy.filters || []).forEach(walk);
    if (keys.size) BUILDER.keysByResource.set(policy.resource, keys);
  }
  BUILDER.controls = DATA.catalog.controls.map((c) => `${c.framework.toUpperCase()} ${c.id}`);
}

function renderBuilderInputs() {
  const resources = [...BUILDER.keysByResource.keys()].sort();
  if (!$("b-resource").options.length) {
    $("b-resource").innerHTML = resources.map((r) => `<option${r === "aws.rds" ? " selected" : ""}>${r}</option>`).join("");
    $("b-framework").innerHTML = BUILDER.controls.slice(0, 400).map((c) => `<option>${c}</option>`).join("");
  }
  const keys = [...(BUILDER.keysByResource.get($("b-resource").value) || [])].sort();
  // Open on the key this whole catalogue is an argument about, when the
  // chosen resource type has it.
  const current = $("b-key").value
    || (keys.includes("StorageEncrypted") ? "StorageEncrypted" : keys[0]);
  $("b-key").innerHTML = keys.map((k) => `<option${k === current ? " selected" : ""}>${k}</option>`).join("");
  $("b-resource-hint").textContent = `${resources.length} resource types appear in this catalogue`;
  $("b-key-hint").textContent = `${keys.length} keys are used on ${$("b-resource").value} by the policies here`;
}

function builderFilters() {
  const key = $("b-key").value;
  const op = $("b-op").value;
  const rawValue = $("b-value").value.trim();
  const value = rawValue === "true" ? true : rawValue === "false" ? false
    : /^-?\d+$/.test(rawValue) ? Number(rawValue) : rawValue;

  const main = op === "absent"
    ? { type: "value", key, value: "absent" }
    : op === "eq"
      ? { type: "value", key, value }
      : { type: "value", key, op, value };

  if (op === "absent" || !$("b-absent").checked) return [main];
  return [{ or: [main, { type: "value", key, value: "absent" }] }];
}

function toYaml(filters) {
  const lines = [
    `- name: ${$("b-name").value.trim() || "unnamed-policy"}`,
    `  resource: ${$("b-resource").value}`,
    "  metadata:",
    `    severity: ${$("b-severity").value}`,
    "    frameworks:",
    `    - ${$("b-framework").value}`,
    "  filters:",
  ];

  // The repository writes one key per line in this order, and the site has
  // to emit the same shape or a pasted policy would not look like its
  // neighbours in the file.
  const valueFilter = (filter, indent) => {
    lines.push(`${indent}- type: value`);
    lines.push(`${indent}  key: ${filter.key}`);
    if (filter.op) lines.push(`${indent}  op: ${filter.op}`);
    lines.push(`${indent}  value: ${filter.value}`);
  };

  if (filters[0].or) {
    lines.push("  - or:");
    filters[0].or.forEach((filter) => valueFilter(filter, "    "));
  } else {
    valueFilter(filters[0], "  ");
  }
  return lines.join("\n");
}

function renderBuilder() {
  renderBuilderInputs();
  const filters = builderFilters();
  $("b-value-field").hidden = $("b-op").value === "absent";
  $("b-absent").disabled = $("b-op").value === "absent";

  $("b-preview").innerHTML = highlightYaml(toYaml(filters));

  const key = $("b-key").value;
  const rawValue = $("b-value").value.trim() || "true";
  const other = rawValue === "true" ? "false" : rawValue === "false" ? "true" : "0";
  const samples = [
    { label: `"${key}": ${rawValue}`, resource: { [key]: JSON.parse(safeJson(rawValue)) } },
    { label: `"${key}": ${other}`, resource: { [key]: JSON.parse(safeJson(other)) } },
    { label: `no "${key}" in the payload`, resource: {} },
  ];

  $("b-catch").innerHTML = samples
    .map((sample) => {
      const result = C7N.evaluate(filters, sample.resource).root;
      return `<li class="${CLASS[result]}"><span class="tag">${LABEL[result]}</span>
        <span class="res">${escapeHtml(sample.label)}</span></li>`;
    })
    .join("");

  const missing = C7N.evaluate(filters, {}).root;
  $("b-foot").innerHTML = missing === "match"
    ? `The <code>absent</code> branch is what catches the third one. It is the branch most policies in the wild do not have.`
    : `Without an <code>absent</code> branch, a resource whose <code>${escapeHtml(key)}</code> never came back is reported as compliant without anyone looking at it.`;
}

function safeJson(text) {
  if (text === "true" || text === "false" || /^-?\d+$/.test(text)) return text;
  return JSON.stringify(text);
}

document.addEventListener("DOMContentLoaded", () => {
  $("src-examples").addEventListener("click", () => setSource("examples"));
  $("src-paste").addEventListener("click", () => setSource("paste"));
  $("paste-input").addEventListener("input", renderPasted);

  ["b-name", "b-resource", "b-key", "b-op", "b-value", "b-severity", "b-framework"].forEach((id) => {
    $(id).addEventListener("input", renderBuilder);
    $(id).addEventListener("change", renderBuilder);
  });
  $("b-absent").addEventListener("change", renderBuilder);

  $("b-copy").addEventListener("click", () => {
    const done = () => {
      $("b-copy").textContent = "Copied";
      setTimeout(() => { $("b-copy").textContent = "Copy"; }, 1500);
    };
    if (navigator.clipboard) navigator.clipboard.writeText($("b-preview").textContent).then(done, done);
    else done();
  });
});
