"""Loads the built site in a real browser and asserts what it renders.

A page built from generated JSON fails in a way unit tests do not see: the
data is right, the fetch path is wrong, and the page renders empty. Worse
for this particular site, an empty page is indistinguishable from a
catalogue with nothing in it, which is the failure mode the whole
repository argues against. So the check is: serve the directory, open it,
and assert the three panels actually carry the answers the build computed.

Usage, from the repository root, after ci/build_catalog.py:

    python ci/check_site.py [--browser /path/to/chromium]

Exits non-zero with the reason if anything is missing.
"""
from __future__ import annotations

import argparse
import contextlib
import functools
import http.server
import json
import pathlib
import socketserver
import threading

ROOT = pathlib.Path(__file__).resolve().parent.parent
SITE = ROOT / "site"


@contextlib.contextmanager
def serve(directory: pathlib.Path):
    """A throwaway HTTP server on a free port. fetch() needs http, not file."""
    handler = functools.partial(http.server.SimpleHTTPRequestHandler,
                                directory=str(directory))
    with socketserver.TCPServer(("127.0.0.1", 0), handler) as httpd:
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{httpd.server_address[1]}/"
        finally:
            httpd.shutdown()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--browser", default=None,
                        help="chromium executable, for a machine without "
                             "playwright's own download")
    args = parser.parse_args()

    from playwright.sync_api import sync_playwright

    catalog = json.loads((SITE / "data" / "catalog.json").read_text())
    expected_policies = str(catalog["counts"]["policies"])

    problems: list[str] = []

    with serve(SITE) as url, sync_playwright() as p:
        launch = {"executable_path": args.browser} if args.browser else {}
        browser = p.chromium.launch(**launch)
        page = browser.new_page(viewport={"width": 1280, "height": 1000})

        console: list[str] = []
        page.on("console", lambda m: console.append(f"{m.type}: {m.text}")
                if m.type in ("error", "warning") else None)
        page.goto(url, wait_until="networkidle")

        # 1. the numbers came from the build, not from the markup
        if page.inner_text("#stat-policies").strip() != expected_policies:
            problems.append(
                f"the policy count reads {page.inner_text('#stat-policies')!r}, "
                f"the catalogue says {expected_policies}")

        # 2. the three panels have content
        for selector, what in (("#yaml", "the policy YAML"),
                               ("#resource-json", "the resource"),
                               ("#nodes li", "the per-node answers")):
            if page.locator(selector).count() == 0 or not page.inner_text(selector).strip():
                problems.append(f"{what} did not render ({selector} is empty)")

        # 3. the case the site exists to show: one condition fired and
        # another did not, for the same resource
        tags = [t.strip().lower() for t in
                page.locator("#nodes li .tag").all_inner_texts()]
        if not ("fires" in tags and "no match" in tags):
            problems.append(
                f"the opening example does not show a fired and an unfired "
                f"condition together, it shows {tags}")

        # 4. the controls screen lists controls, covered and not
        page.click("#tab-controls")
        page.wait_for_selector("#ctl-rows .row")
        rows = page.locator("#ctl-rows .row").count()
        if rows < 10:
            problems.append(f"the controls registry rendered {rows} rows")
        if page.locator("#ctl-rows .row.uncovered").count() == 0:
            problems.append("no uncovered control is listed, which is how a "
                            "coverage page starts lying")

        errors = [c for c in console if c.startswith("error")]
        if errors:
            problems.append(f"console errors: {errors}")

        page.screenshot(path=str(ROOT / "site-check-controls.png"))
        page.click("#tab-run")
        page.wait_for_selector("#nodes li")
        page.screenshot(path=str(ROOT / "site-check.png"))
        browser.close()

    if problems:
        print("site check failed:")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    print(f"site check ok: {expected_policies} policies, "
          f"{len(catalog['controls'])} controls, three panels rendered")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
