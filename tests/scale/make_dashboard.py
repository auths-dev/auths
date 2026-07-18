#!/usr/bin/env python3
"""Generate dashboard.html from runs/*.json.

Six use-case tiers (agent fleets and employee onboarding, small/medium/large),
comparing per-identity anchoring (main) against batch anchoring (the KL-9 bulk
branch). Where a main-branch run is infeasible (quadratic write path), the cell
is a fitted projection and is labeled as such.

Regenerate any time:  python3 make_dashboard.py
"""

import json
import math
import datetime
from pathlib import Path

HERE = Path(__file__).parent
RUNS = HERE / "runs"
OUT = HERE / "dashboard.html"


def load(name):
    p = RUNS / f"{name}.json"
    return json.loads(p.read_text()) if p.exists() else None


def cell_from_run(name):
    d = load(name)
    if d is None:
        return None
    t, i = d["timings"], d["invariants"]
    return {
        "projected": False,
        "onboard_s": t["provision_wall_s"],
        "rate": t["provision_agents_per_sec"],
        "kel": i["root_kel_events_final"],
        "commits": i["registry_git_commits"],
        "du_mb": (i["registry_du_kb"] or 0) / 1024.0,
        "replay_ms": t["cold_root_kel_replay_ms"],
        "revoke_ms": t["revoke_individual"]["p50_ms"] if t["revoke_individual"] else None,
        "run": name,
    }


def main_fit():
    """Per-append cost a + b*i (ms) fitted from the main-1k decile means."""
    t = load("main-1k")["timings"]
    y1, y2 = t["provision_first_decile_mean_ms"], t["provision_last_decile_mean_ms"]
    b = (y2 - y1) / 900.0  # decile centers ~i=50 and ~i=950
    a = y1 - b * 50.0
    return a, b


def du_exponent():
    lo, hi = load("main-smoke"), load("main-1k")
    lo_mb = lo["invariants"]["registry_du_kb"] / 1024.0
    hi_mb = hi["invariants"]["registry_du_kb"] / 1024.0
    return math.log(hi_mb / lo_mb) / math.log(10.0), hi_mb


def project_main(n):
    a, b = main_fit()
    onboard_s = (a * n + b * n * n / 2.0) / 1000.0
    exp, mb_1k = du_exponent()
    d1k = load("main-1k")
    replay_per_event = d1k["timings"]["cold_root_kel_replay_ms"] / d1k["invariants"]["root_kel_events_final"]
    kel = 3 * n + 1
    return {
        "projected": True,
        "onboard_s": onboard_s,
        "rate": n / onboard_s,
        "kel": kel,
        "commits": round(4.05 * n),
        "du_mb": mb_1k * (n / 1000.0) ** exp,
        "replay_ms": replay_per_event * kel,
        "revoke_ms": None,
        "run": "fit from main @60/100/1000",
    }


PERSONAS = [
    {
        "id": "agents",
        "title": "Agent fleets",
        "sub": "CI runners, deploy bots, autonomous agents — delegated identities under one org root. Batch size 100.",
        "tiers": [
            ("Small", 100, cell_from_run("main-smoke"), cell_from_run("bulk-fleet-small")),
            ("Medium", 1_000, cell_from_run("main-1k"), cell_from_run("bulk-1k")),
            ("Large", 10_000, project_main(10_000), cell_from_run("bulk-10k")),
        ],
    },
    {
        "id": "employees",
        "title": "Employee onboarding",
        "sub": "Org-side membership cost per employee (each person's own identity is created on their device, in parallel — it never touches the org writer). Cohort batches of 25.",
        "tiers": [
            ("Small company", 50, cell_from_run("main-emp-small"), cell_from_run("bulk-emp-small")),
            ("Medium company", 500, cell_from_run("main-emp-medium"), cell_from_run("bulk-emp-medium")),
            ("Large company", 5_000, project_main(5_000), cell_from_run("bulk-emp-large")),
        ],
    },
]


def fmt_dur(s):
    if s is None:
        return "—"
    if s < 1:
        return f"{s*1000:.0f} ms"
    if s < 90:
        return f"{s:.1f} s"
    if s < 5400:
        return f"{s/60:.1f} min"
    return f"{s/3600:.1f} h"


def fmt_ms(ms):
    if ms is None:
        return "—"
    return fmt_dur(ms / 1000.0)


def fmt_int(v):
    return "—" if v is None else f"{v:,.0f}"


def fmt_mb(v):
    if v is None:
        return "—"
    return f"{v/1024:.1f} GB" if v >= 1024 else f"{v:.0f} MB"


def fmt_rate(v):
    return "—" if v is None else (f"{v:,.0f}/s" if v >= 10 else f"{v:.2f}/s")


def esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def bar_chart(persona):
    """Time-to-onboard, grouped pairs per tier. Pure HTML bars, linear from zero."""
    vmax = max(c["onboard_s"] for _, _, m, b in persona["tiers"] for c in (m, b) if c)
    rows = []
    for tier, n, m, b in persona["tiers"]:
        rows.append(f'<div class="tier-label">{esc(tier)} · {n:,} identities</div>')
        for series, cell, cls in (("Per-identity", m, "s1"), ("Batch", b, "s2")):
            if cell is None:
                continue
            w = max(cell["onboard_s"] / vmax * 100.0, 0.35)
            proj = ' <span class="proj">projected</span>' if cell["projected"] else ""
            op = ' style="opacity:.45"' if cell["projected"] else ""
            tip = (f"{esc(series)} anchoring · {n:,} identities&#10;"
                   f"time {fmt_dur(cell['onboard_s'])} · {fmt_rate(cell['rate'])}&#10;"
                   f"org KEL {fmt_int(cell['kel'])} events · {fmt_int(cell['commits'])} commits&#10;"
                   f"storage {fmt_mb(cell['du_mb'])} · replay {fmt_ms(cell['replay_ms'])}")
            rows.append(
                f'<div class="bar-row" data-tip="{tip}">'
                f'<span class="series-name"><i class="chip {cls}"></i>{series}</span>'
                f'<span class="track"><i class="bar {cls}"{op} data-w="{w:.2f}"></i></span>'
                f'<span class="val">{fmt_dur(cell["onboard_s"])}{proj}</span></div>'
            )
    legend = ('<div class="legend"><span><i class="chip s1"></i>Per-identity anchoring (main)</span>'
              '<span><i class="chip s2"></i>Batch anchoring (bulk)</span></div>')
    return legend + '<div class="chart">' + "".join(rows) + "</div>"


def table(persona):
    head = ("<tr><th>Tier</th><th>Anchoring</th><th>Time</th><th>Rate</th>"
            "<th>Org-KEL events</th><th>Commits</th><th>Storage</th>"
            "<th>Cold replay</th><th>Revoke one (p50)</th></tr>")
    body = []
    for tier, n, m, b in persona["tiers"]:
        for series, cell in (("Per-identity", m), ("Batch", b)):
            if cell is None:
                continue
            proj = ' <span class="proj">proj.</span>' if cell["projected"] else ""
            body.append(
                f"<tr><td>{esc(tier)} · {n:,}</td><td>{series}{proj}</td>"
                f"<td>{fmt_dur(cell['onboard_s'])}</td><td>{fmt_rate(cell['rate'])}</td>"
                f"<td>{fmt_int(cell['kel'])}</td><td>{fmt_int(cell['commits'])}</td>"
                f"<td>{fmt_mb(cell['du_mb'])}</td><td>{fmt_ms(cell['replay_ms'])}</td>"
                f"<td>{fmt_ms(cell['revoke_ms'])}</td></tr>"
            )
    return f'<div class="tablewrap"><table>{head}{"".join(body)}</table></div>'


def hero():
    m1k, b1k = cell_from_run("main-1k"), cell_from_run("bulk-1k")
    b10k = cell_from_run("bulk-10k")
    speedup = m1k["onboard_s"] / b1k["onboard_s"]
    tiles = [
        (f"{speedup:.0f}×", "faster onboarding with batch anchoring", "measured head-to-head at 1,000 identities"),
        (fmt_dur(b10k["onboard_s"]), "to onboard 10,000 agents", "batch anchoring, all verification checks passing"),
        (f"{b10k['kel']:,} vs {project_main(10_000)['kel']:,}", "org-log events at 10,000 identities", "batch vs per-identity — every verifier replays this log"),
    ]
    cells = "".join(
        f'<div class="tile"><div class="tile-v">{esc(v)}</div>'
        f'<div class="tile-t">{esc(t)}</div><div class="tile-s">{esc(s)}</div></div>'
        for v, t, s in tiles
    )
    return f'<div class="tiles">{cells}</div>'


def explainer():
    return """
<section>
<h2>What&rsquo;s being compared</h2>
<p class="sub">Every identity an organization creates &mdash; an employee, a device,
an AI agent &mdash; is vouched for by an entry in the organization&rsquo;s shared,
tamper-evident log. Anyone verifying an identity replays that log. The two
implementations differ only in how those entries are written.</p>
<div class="explain">
  <div>
    <h4><i class="chip s1"></i>Per-identity anchoring <span class="muted">&middot; today</span></h4>
    <p>Each new identity gets its own log entries &mdash; three of them &mdash; and each
    is saved to disk separately. Think of a notary who writes, stamps, and files a
    fresh page for every single hire. It&rsquo;s simple, but the book grows three pages
    per identity, and adding each new page gets slower as the book gets thicker.</p>
  </div>
  <div>
    <h4><i class="chip s2"></i>Batch anchoring <span class="muted">&middot; proposed</span></h4>
    <p>New identities are gathered into a group, and the notary stamps <em>one</em>
    page listing the whole cohort, filed once. The book stays short no matter how
    many identities join &mdash; so writing stays fast and reading stays fast. Each
    individual is still verified exactly as before, against that one shared page.</p>
  </div>
</div>
<p class="sub" style="margin-top:14px">Same cryptography, same verification, same
revocation &mdash; only the bookkeeping differs. Every run below passes identical
verification checks on both implementations.</p>
</section>"""


def build():
    meta_bulk = load("bulk-10k")["meta"]
    today = datetime.date.today().isoformat()
    sections = []
    for p in PERSONAS:
        sections.append(
            f'<section><h2>{esc(p["title"])}</h2><p class="sub">{esc(p["sub"])}</p>'
            f'<h3>Time to onboard</h3>{bar_chart(p)}{table(p)}</section>'
        )
    a, b = main_fit()

    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Auths at scale</title>
<style>
:root {{
  --page:#f9f9f7; --surface:#fcfcfb; --ink:#0b0b0b; --ink2:#52514e; --muted:#898781;
  --grid:#e1e0d9; --baseline:#c3c2b7; --ring:rgba(11,11,11,.10);
  --s1:#2a78d6; --s2:#1baf7a;
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --page:#0d0d0d; --surface:#1a1a19; --ink:#ffffff; --ink2:#c3c2b7; --muted:#898781;
    --grid:#2c2c2a; --baseline:#383835; --ring:rgba(255,255,255,.10);
    --s1:#3987e5; --s2:#199e70;
  }}
}}
* {{ box-sizing:border-box; margin:0; }}
body {{ background:var(--page); color:var(--ink);
  font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;
  -webkit-font-smoothing:antialiased; padding:56px 24px 80px; }}
main {{ max-width:920px; margin:0 auto; }}
h1 {{ font-size:34px; font-weight:700; letter-spacing:-.02em; }}
.tagline {{ color:var(--ink2); margin-top:6px; max-width:620px; }}
h2 {{ font-size:22px; font-weight:650; letter-spacing:-.01em; margin-bottom:4px; }}
h3 {{ font-size:13px; font-weight:600; color:var(--muted); text-transform:uppercase;
  letter-spacing:.06em; margin:22px 0 10px; }}
section {{ background:var(--surface); border:1px solid var(--ring); border-radius:16px;
  padding:28px; margin-top:28px; }}
.sub {{ color:var(--ink2); font-size:14px; max-width:640px; }}
.tiles {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
  gap:16px; margin-top:28px; }}
.tile {{ background:var(--surface); border:1px solid var(--ring); border-radius:16px;
  padding:22px; }}
.tile-v {{ font-size:32px; font-weight:700; letter-spacing:-.02em; }}
.tile-t {{ margin-top:4px; font-weight:600; }}
.tile-s {{ color:var(--muted); font-size:13px; margin-top:2px; }}
.legend {{ display:flex; gap:18px; color:var(--ink2); font-size:13px; margin-bottom:14px; }}
.legend span {{ display:inline-flex; align-items:center; gap:7px; }}
.chip {{ width:10px; height:10px; border-radius:3px; display:inline-block; }}
.chip.s1,.bar.s1 {{ background:var(--s1); }}
.chip.s2,.bar.s2 {{ background:var(--s2); }}
.chart {{ display:flex; flex-direction:column; gap:6px; }}
.tier-label {{ color:var(--ink2); font-size:13px; font-weight:600; margin:12px 0 2px; }}
.tier-label:first-child {{ margin-top:0; }}
.bar-row {{ display:grid; grid-template-columns:110px 1fr 130px; align-items:center;
  gap:12px; padding:2px 0; border-radius:6px; }}
.series-name {{ color:var(--ink2); font-size:13px; display:inline-flex;
  align-items:center; gap:7px; }}
.track {{ position:relative; height:14px; border-left:2px solid var(--baseline); }}
.bar {{ position:absolute; left:0; top:1px; height:12px; width:0;
  border-radius:0 4px 4px 0; transition:width .6s cubic-bezier(.2,.7,.2,1); }}
.val {{ font-size:13px; color:var(--ink); font-variant-numeric:tabular-nums; }}
.proj {{ color:var(--muted); font-size:11px; font-style:italic; }}
.explain {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr));
  gap:24px; margin-top:18px; }}
.explain h4 {{ font-size:14px; font-weight:650; display:flex; align-items:center;
  gap:8px; margin-bottom:6px; }}
.explain p {{ color:var(--ink2); font-size:14px; }}
.muted {{ color:var(--muted); font-weight:500; }}
.tablewrap {{ overflow-x:auto; margin-top:18px; }}
table {{ border-collapse:collapse; width:100%; font-size:13.5px; white-space:nowrap; }}
th {{ text-align:left; color:var(--muted); font-weight:600; font-size:12px;
  padding:8px 14px 8px 0; border-bottom:1px solid var(--grid); }}
td {{ padding:8px 14px 8px 0; border-bottom:1px solid var(--grid);
  font-variant-numeric:tabular-nums; }}
tr:last-child td {{ border-bottom:none; }}
.note {{ color:var(--muted); font-size:12.5px; margin-top:32px; line-height:1.7; }}
.note b {{ color:var(--ink2); }}
#tip {{ position:fixed; pointer-events:none; background:var(--ink); color:var(--page);
  padding:10px 12px; border-radius:10px; font-size:12.5px; line-height:1.5;
  white-space:pre-line; opacity:0; transition:opacity .12s; max-width:300px;
  z-index:10; font-variant-numeric:tabular-nums; }}
</style></head><body><main>
<h1>Auths at scale</h1>
<p class="tagline">Onboarding cost on the shared org log: today&rsquo;s per-identity
anchoring vs batch anchoring (one anchor event per batch). Same cryptography, same
verification &mdash; every run passes the full verification, signing, and revocation
checks on both implementations.</p>
{hero()}
{explainer()}
{"".join(sections)}
<p class="note">
<b>Method.</b> tests/scale harness, release build, Apple M1 Max &middot; 64 GB.
Per-identity anchoring measured at 50&ndash;1,000 identities; large-tier
per-identity cells are projections from the fitted per-append cost
({a:.0f}&#8201;ms + {b:.2f}&#8201;ms per identity already in the log; storage by power-law fit) because a direct run
is {fmt_dur(project_main(10_000)["onboard_s"])} of wall clock &mdash; which is the finding.
Batch anchoring measured directly at every tier, including 10,000.
Binaries: main @ d5d42c1c, bulk branch @ 0610292f.
Key-derivation cost excluded identically on both sides (test parameters).
Employee tiers count org-side membership work only. Raw data: runs/*.json &middot; {today}.
</p>
</main>
<div id="tip"></div>
<script>
const tip = document.getElementById('tip');
document.querySelectorAll('.bar-row').forEach(r => {{
  r.addEventListener('mousemove', e => {{
    tip.textContent = r.dataset.tip;
    tip.style.opacity = 1;
    const pad = 14, w = tip.offsetWidth, h = tip.offsetHeight;
    let x = e.clientX + pad, y = e.clientY + pad;
    if (x + w > innerWidth - 8) x = e.clientX - w - pad;
    if (y + h > innerHeight - 8) y = e.clientY - h - pad;
    tip.style.left = x + 'px'; tip.style.top = y + 'px';
  }});
  r.addEventListener('mouseleave', () => tip.style.opacity = 0);
}});
requestAnimationFrame(() => requestAnimationFrame(() =>
  document.querySelectorAll('.bar').forEach(b => b.style.width = b.dataset.w + '%')));
</script>
</body></html>"""
    OUT.write_text(html)
    print(f"wrote {OUT}")


if __name__ == "__main__":
    build()
