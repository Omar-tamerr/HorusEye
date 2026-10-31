#!/usr/bin/env python3
"""
Rebuild the website's live demo (docs/demo.html) from examples/acme-lab.

The demo is a normal HorusEye explorer report with the website-only extras
switched on: a top bar back to the site, a "synthetic data" label, link-preview
meta tags, and the Attack Paths view as the landing page.

    python scripts/build_demo.py
    SOURCE_DATE_EPOCH=1761900000 python scripts/build_demo.py   # fixed date
"""
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from horuseye import api                                   # noqa: E402
from horuseye.core.graph import AttackGraph                # noqa: E402
from horuseye.reports.explorer import build_explorer       # noqa: E402

SITE = "https://omar-tamerr.github.io/HorusEye/"
DEMO = {
    "home_url": "./",
    "install_url": "./#install",
    "repo_url": "https://github.com/Omar-tamerr/HorusEye",
    "page_url": SITE + "demo.html",
    "og_image": SITE + "assets/og-image.png",
    "default_view": "paths",
}
OWNED = ["JDOE@ACME.LAB"]


def main() -> None:
    data = api.parse_sources(bloodhound=str(ROOT / "examples" / "acme-lab"),
                             domain="ACME.LAB", dc="10.10.0.5")
    findings = api.detect(data)
    graph = AttackGraph(data)
    paths = [graph.describe(p) for p in graph.shortest_paths(owned=OWNED, max_paths=5)]
    impact = graph.remediation_impact(owned=OWNED, max_paths=5)
    plans = graph.remediation_plans(owned=OWNED)

    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    when = (datetime.fromtimestamp(int(epoch), tz=timezone.utc) if epoch
            else datetime.now(timezone.utc))
    page = build_explorer(findings, paths, impact, data, when.strftime("%Y-%m-%d"), demo=DEMO,
                          plans=plans)

    out = ROOT / "docs" / "demo.html"
    out.write_text(page, encoding="utf-8")
    chokes = sum(1 for h in impact if h["breaks_path"])
    print(f"wrote {out.relative_to(ROOT)} ({len(page):,} bytes): "
          f"{len(findings)} findings, {len(paths)} routes, {chokes} choke point(s), "
          f"{len(plans)} remediation option(s)")


if __name__ == "__main__":
    main()
