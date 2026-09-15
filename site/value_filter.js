/* A deliberately small port of c7n's ValueFilter, for resources you paste.
 *
 * Everything else on this site is precomputed by c7n itself. This file is the
 * one exception, because a resource the visitor types cannot have been
 * evaluated at build time. That makes it the one place where the site could
 * disagree with c7n, so two rules hold it in place:
 *
 *   1. It answers "unknown" for anything it does not implement exactly. A
 *      filter type it does not know, a key it cannot resolve, an operator or
 *      a value_type outside the list below: unknown, never no_match. Being
 *      less capable than c7n is fine. Contradicting it is not.
 *   2. ci/check_evaluator.js runs it over every example in the built
 *      catalogue and compares it node by node against what c7n answered. One
 *      disagreement fails the build.
 *
 * The semantics that matter, from c7n/filters/core.py:
 *   - a key that is not in the resource is None
 *   - None == False is False, so `value: false` does not match a missing key
 *   - None != value is True, so `op: not-equal` DOES match a missing key
 *   - an ordering comparison against None raises, and c7n catches it and
 *     returns False
 *   - `value: absent` is the only branch that sees a missing key on purpose
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.C7N = factory();
  }
})(typeof self !== "undefined" ? self : this, function () {
  const MATCH = "match";
  const NO_MATCH = "no_match";
  const UNKNOWN = "unknown";

  // Operators this port implements with c7n's exact behaviour. Anything not
  // here makes the node unknown.
  const OPS = new Set([
    "eq", "equal", "ne", "not-equal", "gt", "greater-than", "ge", "gte",
    "lt", "less-than", "le", "lte", "in", "not-in", "contains",
  ]);

  // value_type coercions this port implements. The date ones (age,
  // expiration) depend on "now" and would drift between the browser clock
  // and the build, so they stay unknown on purpose.
  const VALUE_TYPES = new Set(["integer", "size", "normalize", "swap"]);

  function isPlainObject(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
  }

  // Python truthiness, which is not JavaScript's: [] and {} are falsy there.
  function pythonTruthy(value) {
    if (value === null || value === undefined) return false;
    if (typeof value === "boolean") return value;
    if (typeof value === "number") return value !== 0;
    if (typeof value === "string") return value.length > 0;
    if (Array.isArray(value)) return value.length > 0;
    if (isPlainObject(value)) return Object.keys(value).length > 0;
    return true;
  }

  // Python equality for the types that reach a policy: numbers and booleans
  // compare across (True == 1), strings never equal numbers, and lists and
  // dicts compare by value.
  function pythonEqual(a, b) {
    if (a === null || a === undefined) return b === null || b === undefined;
    if (b === null || b === undefined) return false;
    const na = typeof a === "boolean" ? Number(a) : a;
    const nb = typeof b === "boolean" ? Number(b) : b;
    if (typeof na === "number" && typeof nb === "number") return na === nb;
    if (typeof a === "string" && typeof b === "string") return a === b;
    if (Array.isArray(a) && Array.isArray(b)) {
      return a.length === b.length && a.every((item, i) => pythonEqual(item, b[i]));
    }
    if (isPlainObject(a) && isPlainObject(b)) {
      const ka = Object.keys(a);
      const kb = Object.keys(b);
      return ka.length === kb.length && ka.every((k) => pythonEqual(a[k], b[k]));
    }
    return false;
  }

  function comparable(a, b) {
    return (typeof a === "number" && typeof b === "number")
      || (typeof a === "string" && typeof b === "string");
  }

  // Only plain dotted paths. A real jmespath expression (a projection, a
  // function, a filter) goes to the resolver c7n uses, which is not here, so
  // it is unknown rather than approximated.
  const SIMPLE_KEY = /^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$/;

  function resolveKey(resource, key) {
    if (!SIMPLE_KEY.test(key)) return { ok: false };
    let current = resource;
    for (const part of key.split(".")) {
      if (current === null || current === undefined) return { ok: true, value: null };
      if (!isPlainObject(current)) return { ok: true, value: null };
      current = Object.prototype.hasOwnProperty.call(current, part) ? current[part] : null;
    }
    return { ok: true, value: current === undefined ? null : current };
  }

  function coerce(value, valueType) {
    switch (valueType) {
      case "integer": {
        const n = parseInt(value, 10);
        return Number.isNaN(n) ? 0 : n;
      }
      case "size":
        if (value === null) return 0;
        if (Array.isArray(value) || typeof value === "string") return value.length;
        if (isPlainObject(value)) return Object.keys(value).length;
        return 0;
      case "normalize":
        return typeof value === "string" ? value.toLowerCase().trim() : value;
      case "swap":
        return value;
      default:
        return value;
    }
  }

  function evaluateValue(filter, resource) {
    const key = filter.key;
    if (typeof key !== "string") return UNKNOWN;

    const resolved = resolveKey(resource, key);
    if (!resolved.ok) return UNKNOWN;

    let actual = resolved.value;
    let expected = filter.value;

    const valueType = filter.value_type;
    if (valueType !== undefined) {
      if (!VALUE_TYPES.has(valueType)) return UNKNOWN;
      if (valueType === "swap") {
        const swapped = actual;
        actual = expected;
        expected = swapped;
      } else {
        actual = coerce(actual, valueType);
      }
    }

    // The special values, which are the reason this site exists.
    if (expected === "absent") return actual === null ? MATCH : NO_MATCH;
    if (expected === "present") return actual !== null ? MATCH : NO_MATCH;
    if (expected === "not-null") return pythonTruthy(actual) ? MATCH : NO_MATCH;
    if (expected === "empty") return !pythonTruthy(actual) ? MATCH : NO_MATCH;

    const op = filter.op || "eq";
    if (!OPS.has(op)) return UNKNOWN;

    switch (op) {
      case "eq":
      case "equal":
        return pythonEqual(actual, expected) ? MATCH : NO_MATCH;
      case "ne":
      case "not-equal":
        // None != anything is True in Python: a missing key MATCHES here.
        return !pythonEqual(actual, expected) ? MATCH : NO_MATCH;
      case "gt":
      case "greater-than":
        return comparable(actual, expected) && actual > expected ? MATCH : NO_MATCH;
      case "ge":
      case "gte":
        return comparable(actual, expected) && actual >= expected ? MATCH : NO_MATCH;
      case "lt":
      case "less-than":
        return comparable(actual, expected) && actual < expected ? MATCH : NO_MATCH;
      case "le":
      case "lte":
        return comparable(actual, expected) && actual <= expected ? MATCH : NO_MATCH;
      case "in":
        if (!Array.isArray(expected)) return UNKNOWN;
        return expected.some((item) => pythonEqual(actual, item)) ? MATCH : NO_MATCH;
      case "not-in":
        if (!Array.isArray(expected)) return UNKNOWN;
        return expected.some((item) => pythonEqual(actual, item)) ? NO_MATCH : MATCH;
      case "contains":
        if (actual === null) return NO_MATCH;
        if (Array.isArray(actual)) {
          return actual.some((item) => pythonEqual(item, expected)) ? MATCH : NO_MATCH;
        }
        if (typeof actual === "string" && typeof expected === "string") {
          return actual.includes(expected) ? MATCH : NO_MATCH;
        }
        return UNKNOWN;
      default:
        return UNKNOWN;
    }
  }

  function combine(operator, results) {
    if (operator === "and") {
      if (results.includes(NO_MATCH)) return NO_MATCH;
      return results.includes(UNKNOWN) ? UNKNOWN : MATCH;
    }
    if (operator === "or") {
      if (results.includes(MATCH)) return MATCH;
      return results.includes(UNKNOWN) ? UNKNOWN : NO_MATCH;
    }
    const inner = combine("and", results);
    if (inner === UNKNOWN) return UNKNOWN;
    return inner === MATCH ? NO_MATCH : MATCH;
  }

  function operatorOf(filter) {
    if (!isPlainObject(filter)) return null;
    for (const name of ["or", "and", "not"]) {
      if (Array.isArray(filter[name])) return name;
    }
    return null;
  }

  // Returns the same shape as c7n-kit's trace: a flat list of nodes with
  // their path, so the page renders a pasted resource exactly like a
  // precomputed one.
  function evaluate(filters, resource) {
    const nodes = [];

    function walk(filter, path) {
      const operator = operatorOf(filter);
      if (operator) {
        const children = filter[operator].map((child, i) => walk(child, `${path}.${i}`));
        const result = combine(operator, children.map((c) => c.result));
        nodes.push({ path, kind: operator, result, raw: filter });
        return { result };
      }

      let result;
      if (!isPlainObject(filter)) {
        result = UNKNOWN;
      } else if (filter.type !== undefined && filter.type !== "value") {
        // Every other filter type reads state from AWS. Offline it has no
        // answer, and this is the whole point: unknown, never a pass.
        result = UNKNOWN;
      } else {
        result = evaluateValue(filter, resource);
      }
      nodes.push({ path, kind: (filter && filter.type) || "value", result, raw: filter });
      return { result };
    }

    const roots = (filters || []).map((filter, i) => walk(filter, String(i)));
    const root = combine("and", roots.map((r) => r.result));
    nodes.sort((a, b) => a.path.localeCompare(b.path, undefined, { numeric: true }));
    return { root, nodes };
  }

  return { evaluate, MATCH, NO_MATCH, UNKNOWN };
});
