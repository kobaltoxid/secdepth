#!/usr/bin/env python3
"""Normalize a security report and render a self-contained HTML review."""
import argparse
import html
import json
import pathlib
from urllib.parse import urlparse

UNKNOWN = {None, "unknown", "undetermined"}
GROUPS = ("No deployable fix", "Fix available", "No confirmed local exposure / assessment incomplete")

def score(f):
    try:
        return float((f.get("cvss") or {}).get("score"))
    except (TypeError, ValueError):
        return -1.0

def applicability(f):
    # Missing applicability is unknown; presence is a separate exploitability fact.
    return f.get("applicability")

def has_deployable_fix(f):
    u = f.get("update") or {}
    status = f.get("update_status", u.get("status"))
    target = f.get("recommended_target_version", u.get("recommended_target_version"))
    feasible = f.get("feasibility", u.get("feasibility"))
    missing_targets = {None, "", "unknown", "undetermined"}
    return applicability(f) == "affected" and status == "released" and target not in missing_targets and feasible == "feasible"

def group(f):
    if applicability(f) in UNKNOWN or applicability(f) == "not-affected":
        return GROUPS[2]
    return GROUPS[1] if has_deployable_fix(f) else GROUPS[0]

def sort_key(f):
    sla = (f.get("sla") or {}).get("priority_rank")
    severity = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
    label = str((f.get("cvss") or {}).get("severity") or "").lower()
    numeric = score(f)
    fallback = severity.get(label, -1)
    return (
        0 if sla is not None else 1,
        sla if sla is not None else 0,
        0 if numeric >= 0 else 1,
        -numeric if numeric >= 0 else -fallback,
        str(f.get("id", "")),
    )

def normalize(data):
    findings = list(data.get("vulnerabilities") or [])
    order = {name: i for i, name in enumerate(GROUPS)}
    findings.sort(key=lambda f: (order[group(f)], sort_key(f)))
    data["vulnerabilities"] = findings
    report = data.setdefault("report", {})
    report["ordering_policy"] = (
        "No deployable fix first; then fix available; then no confirmed local exposure. "
        "Within each group: SLA rank ascending, CVSS score descending when present, "
        "severity label fallback (critical, high, medium, low, none), then CVE ID ascending."
    )
    report["finding_groups"] = {name: sum(group(f) == name for f in findings) for name in GROUPS}
    return data

def safe_url(value):
    p = urlparse(str(value or ""))
    return str(value) if p.scheme in {"http", "https"} and p.netloc else None

def plain(value):
    if value is None:
        return "unknown"
    if isinstance(value, list):
        return "<ul>" + "".join("<li>" + html.escape(str(x)) + "</li>" for x in value) + "</ul>"
    if isinstance(value, dict):
        return "<dl>" + "".join("<dt>" + html.escape(str(k)) + "</dt><dd>" + plain(v) + "</dd>" for k, v in value.items()) + "</dl>"
    return html.escape(str(value))

def path_html(path, components):
    if not path:
        return "<p>Dependency path unavailable.</p>"
    labels = []
    for cid in path:
        c = components.get(cid)
        if c:
            label = c.get("name", cid) + " @ " + str(c.get("version") or "unknown")
        else:
            label = str(cid) + " (missing component)"
        labels.append(html.escape(label))
    return "<p class=path>" + " &rarr; ".join(labels) + "</p>"

def sources_html(f, source_map):
    ids = list(f.get("sources") or [])
    ids.extend((f.get("patch_eta") or {}).get("source_ids") or [])
    sla_source = (f.get("sla") or {}).get("source_id")
    if sla_source:
        ids.append(sla_source)
    claims = f.get("claims") or []
    for claim in claims:
        ids.extend(claim.get("source_ids") or [])
    items = []
    for sid in dict.fromkeys(ids):
        s = source_map.get(sid)
        if not s:
            items.append("<li>" + html.escape(str(sid)) + " (missing source record)</li>")
            continue
        url = safe_url(s.get("url"))
        label = "%s [%s]" % (s.get("publisher", sid), sid)
        if url:
            anchor = '<a href="%s" rel="noreferrer noopener">%s</a>' % (
                html.escape(url, quote=True), html.escape(label)
            )
        else:
            anchor = html.escape(label + " (invalid URL)")
        support = ": " + html.escape(s.get("supports")) if s.get("supports") else ""
        items.append("<li>" + anchor + support + "</li>")
    claim_items = []
    for claim in claims:
        claim_label = html.escape(str(claim.get("claim", "Claim")))
        claim_sources = sources_html({"sources": claim.get("source_ids", [])}, source_map)
        claim_items.append("<li><strong>" + claim_label + "</strong>: " + claim_sources + "</li>")
    result = "<ul>" + "".join(items or ["<li>unknown</li>"]) + "</ul>"
    if claim_items:
        result += "<h4>Claims</h4><ul>" + "".join(claim_items) + "</ul>"
    return result

def render(data):
    components = {c.get("id"): c for c in data.get("components", [])}
    source_map = {s.get("id"): s for s in data.get("sources", [])}
    report = data.get("report") or {}
    root_id = report.get("root_component_id")
    root = components.get(root_id)
    root_label = "%s @ %s" % (root.get("name", root_id), root.get("version") or "unknown") if root else "unknown root component"
    sections = {name: [] for name in GROUPS}
    for f in data.get("vulnerabilities", []):
        affected_parts = []
        for component_id in f.get("affected_component_ids", []):
            component = components.get(component_id, {})
            name = component.get("name", component_id)
            version = component.get("version") or "unknown"
            affected_parts.append("%s @ %s" % (name, version))
        affected = ", ".join(affected_parts) or "unknown"
        paths = "".join(
            path_html(path, components) for path in (f.get("dependency_paths") or [])
        ) or "<p>Dependency path unavailable.</p>"
        update_fields = {
            key: f.get(key)
            for key in (
                "update_status", "recommended_target_version", "feasibility",
                "patch_eta", "blockers", "recommendation", "temporary_mitigations",
            )
            if key in f
        }
        body = (
            "<dl><dt>Description</dt><dd>%s</dd><dt>Applicability</dt><dd>%s</dd>"
            "<dt>Affected components</dt><dd>%s</dd><dt>CVSS</dt><dd>%s</dd>"
            "<dt>SLA</dt><dd>%s</dd><dt>Exploitability</dt><dd>%s</dd>"
            "<dt>Update status and recommendation</dt><dd>%s</dd>"
            "<dt>Dependency paths from %s</dt><dd>%s</dd>"
            "<dt>Sources and claim references</dt><dd>%s</dd></dl>"
        ) % (
            plain(f.get("description", f.get("summary"))), plain(applicability(f)),
            html.escape(affected), plain(f.get("cvss")), plain(f.get("sla")),
            plain(f.get("exploitability")), plain(update_fields or f.get("update")),
            html.escape(root_label), paths, sources_html(f, source_map),
        )
        encoded = html.escape(json.dumps(f, ensure_ascii=False), quote=True)
        item = '<details class="finding" data-search="%s"><summary><strong>%s</strong> <span>%s</span> <em>%s</em></summary>%s</details>' % (encoded, html.escape(str(f.get("id", "unknown"))), html.escape(group(f)), html.escape(affected), body)
        sections[group(f)].append(item)
    title = html.escape(str(report.get("title", "Security findings")))
    generated = html.escape(str(report.get("generated_at", "unknown")))
    css = (
        "body{font:15px system-ui;margin:2rem;max-width:1100px;color:#222}"
        "input{padding:.6rem;width:min(100%%,45rem)}details{border:1px solid #ccc;"
        "border-radius:6px;margin:1rem 0;padding:.7rem}summary{cursor:pointer}"
        "em{color:#8a1c1c;font-style:normal}.path{font-family:monospace;"
        "background:#f5f5f5;padding:.5rem}dt{font-weight:700;margin-top:.5rem}"
        "a{color:#0645ad}.hidden{display:none}.meta{white-space:pre-wrap;"
        "background:#f5f5f5;padding:1rem}"
    )
    page = (
        '<!doctype html><meta charset="utf-8"><title>%s</title><style>%s</style>'
        '<h1>%s</h1><p>Generated: %s<br>Root: %s</p>'
        '<input id="q" placeholder="Filter CVE, package, text…" oninput="filter()">'
        '<p id="count"></p><section><h2>%s</h2>%s</section>'
        '<section><h2>%s</h2>%s</section><section><h2>%s</h2>%s</section>'
        '<h2>Raw JSON</h2><details><summary>Show canonical report</summary>'
        '<pre class="meta">%s</pre></details>'
        '<script>function filter(){let q=document.getElementById("q").value.toLowerCase(),n=0;'
        'document.querySelectorAll(".finding").forEach(x=>{let h=x.dataset.search.toLowerCase().includes(q);'
        'x.classList.toggle("hidden",!h);if(h)n++});document.getElementById("count").textContent='
        'n+" finding(s) shown"}filter()</script>'
    )
    return page % (
        title, css, title, generated, html.escape(root_label),
        GROUPS[0], "".join(sections[GROUPS[0]]), GROUPS[1],
        "".join(sections[GROUPS[1]]), GROUPS[2],
        "".join(sections[GROUPS[2]]), html.escape(json.dumps(data, indent=2, ensure_ascii=False)),
    )

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=pathlib.Path)
    parser.add_argument("--output-dir", type=pathlib.Path, default=pathlib.Path.cwd() / "security-findings")
    args = parser.parse_args()
    data = normalize(json.loads(args.report.read_text(encoding="utf-8")))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "report.json").write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (args.output_dir / "report.html").write_text(render(data), encoding="utf-8")
    print(args.output_dir / "report.json")
    print(args.output_dir / "report.html")

if __name__ == "__main__": main()
