/* Fails the build if the browser evaluator disagrees with c7n.
 *
 * site/value_filter.js answers questions about a resource the visitor pasted,
 * which by definition was not evaluated at build time. That makes it the only
 * thing on the site that can contradict c7n, so it is held against the whole
 * corpus: every example in results.json was answered by c7n's own engine
 * through c7n-kit, and this replays each of them in JavaScript.
 *
 * The asymmetry is deliberate. The port is allowed to say "unknown" where c7n
 * had an answer: it is a subset, and admitting that is honest. It is not
 * allowed to say match where c7n said no_match, or the reverse. One of those
 * and the deploy stops.
 *
 * Usage, after ci/build_catalog.py:
 *
 *     node ci/check_evaluator.js
 */
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const C7N = require(path.join(ROOT, "site", "value_filter.js"));

const catalog = JSON.parse(fs.readFileSync(path.join(ROOT, "site/data/catalog.json"), "utf8"));
const results = JSON.parse(fs.readFileSync(path.join(ROOT, "site/data/results.json"), "utf8"));

const filtersByPolicy = new Map(catalog.policies.map((p) => [p.name, p.filters]));

let nodesCompared = 0;
let nodesUnknownHere = 0;
let rootsCompared = 0;
let rootsUnknownHere = 0;
const disagreements = [];

for (const [policyName, entry] of Object.entries(results)) {
  const filters = filtersByPolicy.get(policyName);
  if (!filters) continue;

  for (const example of entry.examples) {
    const mine = C7N.evaluate(filters, example.resource);
    const byPath = new Map(mine.nodes.map((n) => [n.path, n.result]));

    for (const node of example.nodes) {
      const here = byPath.get(node.path);
      if (here === undefined) continue;
      nodesCompared += 1;
      if (here === "unknown") {
        nodesUnknownHere += 1;
        continue; // a subset is allowed to know less
      }
      if (node.result === "unknown") continue; // c7n could not answer either
      if (here !== node.result) {
        disagreements.push(
          `${policyName} / ${example.label} / node ${node.path}: ` +
          `c7n says ${node.result}, the browser says ${here} ` +
          `(${JSON.stringify(node.raw)})`
        );
      }
    }

    rootsCompared += 1;
    if (mine.root === "unknown") {
      rootsUnknownHere += 1;
    } else if (example.root !== "unknown" && mine.root !== example.root) {
      disagreements.push(
        `${policyName} / ${example.label} / whole policy: ` +
        `c7n says ${example.root}, the browser says ${mine.root}`
      );
    }
  }
}

const answered = nodesCompared - nodesUnknownHere;
const coverage = nodesCompared ? Math.round((answered / nodesCompared) * 100) : 0;

console.log(`nodes compared:  ${nodesCompared}`);
console.log(`answered here:   ${answered} (${coverage}%), the rest are unknown by design`);
console.log(`policies:        ${rootsCompared} examples, ${rootsCompared - rootsUnknownHere} with a verdict`);

if (disagreements.length) {
  console.log(`\n${disagreements.length} disagreement(s) with c7n:`);
  for (const line of disagreements.slice(0, 20)) console.log(`  - ${line}`);
  if (disagreements.length > 20) console.log(`  ... and ${disagreements.length - 20} more`);
  console.log("\nThe browser evaluator must never contradict c7n. Narrow it to " +
              "unknown for the case it got wrong, or fix the semantics.");
  process.exit(1);
}

console.log("\nno disagreement with c7n");
