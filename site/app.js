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

const state = { policy: null, example: 0, framework: "fsbp", query: "" };

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
