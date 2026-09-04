#!/usr/bin/env python3
"""SBOM helpers for the CI `sbom` stage. Python 3 standard library only.

  sbom_tool.py mix-normalize RAW.cdx.json OUT.cdx.json
  sbom_tool.py rebar3 DEFAULT.xml [PROFILE.xml ...] OUT.cdx.json
  sbom_tool.py enrich SBOM.cdx.json OUT.cdx.json
      env: REGISTRY_URL (dependably base URL), REGISTRY_KEY (read-only token)

mix-normalize: `mix sbom.cyclonedx` writes the private registry's repo name into
every Hex purl (`pkg:hex/dependably/jose@1.11.6?checksum=...`) and into the
component `group`. Advisory databases key Hex packages by the bare
`pkg:hex/jose@1.11.6`, so this rewrites each Hex purl to that form and drops
the group. Everything else, including `scope` (required/excluded for dev- and
test-only deps), is kept.

rebar3: rebar3_sbom writes CycloneDX 1.4 XML only, one profile at a time, and
the dependably SBOM endpoint accepts JSON only. This reads the default-profile
document plus any profile documents (`rebar3 as dev sbom`, `rebar3 as test
sbom`), unions their components, and marks anything absent from the default
profile as `scope: excluded`, the same signal a Mix SBOM carries.

enrich: sbom-reach's analyze mode reads vulnerabilities embedded in the SBOM
and does not look any up itself, and the CI runner cannot reach public advisory
hosts. This asks the dependably registry's own vulnerability report
(`GET /api/v1/vuln-report?ecosystem=hex&name=...`, readable with the same
token CI already uses to pull packages) for every Hex component and writes the
matches as CycloneDX `vulnerabilities[]`. The registry only knows versions it
has served, which for a project that pulls everything through it is all of
them.
"""
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

HEX_PURL = re.compile(r"^pkg:hex/(?:[^/@?]+/)?([^/@?]+)@([^?#]+)")


def bare(purl):
    m = HEX_PURL.match(purl or "")
    return f"pkg:hex/{m.group(1)}@{m.group(2)}" if m else None


def split(purl):
    m = HEX_PURL.match(purl or "")
    return (m.group(1), m.group(2)) if m else (None, None)


def load(path):
    with open(path) as f:
        return json.load(f)


def save(doc, path):
    with open(path, "w") as f:
        json.dump(doc, f, indent=2)


def mix_normalize(src, dst):
    doc = load(src)
    n = 0
    for c in doc.get("components", []):
        p = bare(c.get("purl"))
        if p:
            c["purl"] = p
            c.pop("group", None)
            n += 1
    save(doc, dst)
    print(f"normalized {n} hex purls -> {dst}")


def read_xml(path):
    root = ET.parse(path).getroot()
    ns = root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""
    comps = {}
    for c in root.iter(f"{ns}component"):
        text = lambda tag: (c.findtext(f"{ns}{tag}") or "").strip()
        purl = bare(text("purl")) or text("purl")
        comp = {
            "type": c.get("type", "library"),
            "bom-ref": purl,
            "name": text("name"),
            "version": text("version"),
            "purl": purl,
        }
        if text("description"):
            comp["description"] = text("description")
        hashes = [{"alg": h.get("alg"), "content": (h.text or "").strip()} for h in c.iter(f"{ns}hash")]
        if hashes:
            comp["hashes"] = hashes
        licenses = [{"license": {"id": (l.text or "").strip()}} for l in c.iter(f"{ns}id") if l.text]
        if licenses:
            comp["licenses"] = licenses
        comps[purl] = comp
    return comps


def rebar3(default_xml, profile_xmls, dst):
    default = read_xml(default_xml)
    merged = dict(default)
    for p in profile_xmls:
        for purl, comp in read_xml(p).items():
            merged.setdefault(purl, comp)
    for purl, comp in merged.items():
        comp["scope"] = "required" if purl in default else "excluded"
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"tools": {"components": [{"type": "application", "name": "rebar3_sbom"}]}},
        "components": sorted(merged.values(), key=lambda c: c["purl"]),
    }
    save(doc, dst)
    excluded = sum(1 for c in merged.values() if c["scope"] == "excluded")
    print(f"wrote {len(merged)} components ({excluded} profile-only, scope excluded) -> {dst}")


def vuln_report(base, token, name):
    url = f"{base}/api/v1/vuln-report?ecosystem=hex&limit=200&name={urllib.parse.quote(name)}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp).get("items", [])


def enrich(src, dst):
    base = os.environ.get("REGISTRY_URL", "").rstrip("/")
    token = os.environ.get("REGISTRY_KEY", "")
    if not base or not token:
        sys.exit("enrich: REGISTRY_URL and REGISTRY_KEY must be set")
    doc = load(src)
    refs = {}
    for c in doc.get("components", []):
        name, version = split(c.get("purl"))
        if name:
            refs.setdefault(name, {})[version] = c.get("bom-ref") or c["purl"]
    vulns = {}
    for name in sorted(refs):
        try:
            items = vuln_report(base, token, name)
        except urllib.error.HTTPError as e:
            sys.exit(f"enrich: {name}: HTTP {e.code} from {base}")
        for it in items:
            ref = refs[name].get(it.get("version"))
            if not ref or it.get("revokedAt"):
                continue
            v = vulns.setdefault(it["osvId"], {
                "id": it["osvId"],
                "source": {"name": "dependably", "url": f"{base}/api/v1/vulnerabilities/{it['osvId']}"},
                "description": it.get("summary") or "",
                "published": it.get("publishedAt"),
                "ratings": [{
                    "severity": (it.get("severity") or "unknown").lower(),
                    "score": it.get("cvssScore"),
                    "method": "other",
                    "source": {"name": "dependably"},
                }],
                "affects": [],
            })
            if not any(a["ref"] == ref for a in v["affects"]):
                v["affects"].append({"ref": ref})
    doc["vulnerabilities"] = sorted(vulns.values(), key=lambda v: v["id"])
    save(doc, dst)
    affected = {a["ref"] for v in vulns.values() for a in v["affects"]}
    print(f"enriched: {len(refs)} packages checked, {len(vulns)} advisories on {len(affected)} components -> {dst}")


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["mix-normalize"] and len(a) == 3:
        mix_normalize(a[1], a[2])
    elif a[:1] == ["rebar3"] and len(a) >= 3:
        rebar3(a[1], a[2:-1], a[-1])
    elif a[:1] == ["enrich"] and len(a) == 3:
        enrich(a[1], a[2])
    else:
        sys.exit(__doc__)
