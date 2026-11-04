#!/usr/bin/env python3
"""
Rebuild the website's live demos from the bundled examples:

  docs/demo.html           examples/acme-lab    — two routes, the one fix (Attack Paths view)
  docs/exposure-demo.html  examples/karnak-lab  — domain exposure, live what-if (Overview)

Each demo is a normal HorusEye explorer report with the website-only extras
switched on: a top bar back to the site, a "synthetic data" label, link-preview
meta tags, and its landing view.

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
BASE = {
    "home_url": "./",
    "install_url": "./#install",
    "repo_url": "https://github.com/Omar-tamerr/HorusEye",
    "og_image": SITE + "assets/og-image.png",
}
DEMOS = [
    {"out": "demo.html", "lab": "acme-lab", "domain": "ACME.LAB", "dc": "10.10.0.5",
     "certipy": None, "owned": ["JDOE@ACME.LAB"],
     "demo": dict(BASE, page_url=SITE + "demo.html", default_view="paths")},
    {"out": "exposure-demo.html", "lab": "karnak-lab", "domain": "KARNAK.LAB", "dc": "10.20.0.10",
     "certipy": "adcs/karnak_Certipy.json", "owned": ["K.EID@KARNAK.LAB"],
     "demo": dict(BASE, page_url=SITE + "exposure-demo.html", default_view="overview",
                  source="karnak-lab",
                  note="Synthetic KARNAK.LAB data (1,245 users) — no real systems",
                  title="HorusEye Live Demo — domain exposure in KARNAK.LAB",
                  description=("Every user in a synthetic 1,200-user domain can reach Domain "
                               "Admin. Apply four fixes and watch exposure drop to zero, live, "
                               "in an offline HorusEye report."))},
]


def build(spec, when: str) -> str:
    lab = ROOT / "examples" / spec["lab"]
    data = api.parse_sources(bloodhound=str(lab), domain=spec["domain"], dc=spec["dc"],
                             certipy=str(lab / spec["certipy"]) if spec["certipy"] else None)
    findings = api.detect(data)
    graph = AttackGraph(data)
    owned = spec["owned"]
    paths = [graph.describe(p) for p in graph.shortest_paths(owned=owned, max_paths=5)]
    impact = graph.remediation_impact(owned=owned, max_paths=5)
    plans = graph.remediation_plans(owned=owned)
    exposure = AttackGraph(data).exposure()
    page = build_explorer(findings, paths, impact, data, when, demo=spec["demo"],
                          plans=plans, exposure=exposure)
    out = ROOT / "docs" / spec["out"]
    out.write_text(page, encoding="utf-8")
    print(f"wrote {out.relative_to(ROOT)} ({len(page):,} bytes): {len(findings)} findings, "
          f"{len(paths)} routes, {len(plans)} remediation option(s), exposure "
          f"{exposure['users_exposed']:,}/{exposure['users_total']:,} users")
    return page


def main() -> None:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    when = (datetime.fromtimestamp(int(epoch), tz=timezone.utc) if epoch
            else datetime.now(timezone.utc)).strftime("%Y-%m-%d")
    for spec in DEMOS:
        build(spec, when)


if __name__ == "__main__":
    main()
