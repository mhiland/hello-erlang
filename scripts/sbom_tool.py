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
hosts. The dependably registry embeds security advisories in the signed Hex
registry record it serves for every package (`GET /hex/packages/NAME`, the
same gzip + protobuf document `mix deps.get` and `rebar3` fetch with the same
token, and what `mix hex.audit` reads), so this decodes those records and
writes the advisories touching each SBOM component's version as CycloneDX
`vulnerabilities[]`. The management API's vulnerability report would be
simpler, but the CI token's role cannot read it (403).
"""
import gzip
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


# --- minimal protobuf reader for the Hex registry `Signed`/`Package` messages ---
# Field numbers follow hexpm's registry proto (and dependably's HexRegistryCodec):
#   Signed   { 1 payload }
#   Package  { 1 releases (Release), 2 name, 3 repository, 4 advisories (SecurityAdvisory) }
#   Release  { 1 version, ..., 6 advisory_indexes (uint32, repeated, into Package.advisories) }
#   SecurityAdvisory { 1 id, 2 summary, 3 html_url, 4 severity (0 none..4 critical),
#                      5 cvss_score (float), 6 api_url, 7 aliases (repeated string) }

SEVERITIES = {0: "none", 1: "low", 2: "medium", 3: "high", 4: "critical"}


def _varint(b, i):
    shift = value = 0
    while True:
        c = b[i]
        i += 1
        value |= (c & 0x7F) << shift
        if not c & 0x80:
            return value, i
        shift += 7


def fields(b):
    """Yield (field_number, wire_type, value) for one protobuf message."""
    import struct
    i = 0
    while i < len(b):
        tag, i = _varint(b, i)
        num, wire = tag >> 3, tag & 7
        if wire == 0:
            v, i = _varint(b, i)
        elif wire == 1:
            v, i = struct.unpack_from("<d", b, i)[0], i + 8
        elif wire == 2:
            n, i = _varint(b, i)
            v, i = b[i:i + n], i + n
        elif wire == 5:
            v, i = struct.unpack_from("<f", b, i)[0], i + 4
        else:
            raise ValueError(f"unsupported wire type {wire}")
        yield num, wire, v


def packed_or_single(wire, v):
    if wire == 2:
        out, i = [], 0
        while i < len(v):
            x, i = _varint(v, i)
            out.append(x)
        return out
    return [v]


def decode_advisory(b):
    adv = {"aliases": []}
    for num, wire, v in fields(b):
        if num == 1: adv["id"] = v.decode()
        elif num == 2: adv["summary"] = v.decode()
        elif num == 3: adv["html_url"] = v.decode()
        elif num == 4: adv["severity"] = SEVERITIES.get(v, "unknown")
        elif num == 5: adv["score"] = round(v, 1)
        elif num == 6: adv["api_url"] = v.decode()
        elif num == 7: adv["aliases"].append(v.decode())
    return adv


def decode_package(signed_gz):
    raw = gzip.decompress(signed_gz) if signed_gz[:2] == b"\x1f\x8b" else signed_gz
    payload = next(v for num, wire, v in fields(raw) if num == 1 and wire == 2)
    advisories, releases = [], {}
    for num, wire, v in fields(payload):
        if num == 4 and wire == 2:
            advisories.append(decode_advisory(v))
        elif num == 1 and wire == 2:
            version, idx = None, []
            for n2, w2, v2 in fields(v):
                if n2 == 1 and w2 == 2: version = v2.decode()
                elif n2 == 6: idx.extend(packed_or_single(w2, v2))
            releases[version] = idx
    return advisories, releases


def registry_record(base, token, name):
    url = f"{base}/hex/packages/{urllib.parse.quote(name)}"
    req = urllib.request.Request(url, headers={"Authorization": token, "Accept": "application/octet-stream"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


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
            advisories, releases = decode_package(registry_record(base, token, name))
        except urllib.error.HTTPError as e:
            sys.exit(f"enrich: {name}: HTTP {e.code} from {base}/hex/packages/{name}")
        for version, ref in refs[name].items():
            for i in releases.get(version, []):
                if i >= len(advisories) or "id" not in advisories[i]:
                    continue
                a = advisories[i]
                v = vulns.setdefault(a["id"], {
                    "id": a["id"],
                    "source": {"name": "dependably", "url": a.get("html_url") or f"{base}/hex/packages/{name}"},
                    "references": [{"id": alias, "source": {"name": "aliases"}} for alias in a["aliases"]],
                    "description": a.get("summary", ""),
                    "ratings": [{
                        "severity": a.get("severity", "unknown"),
                        "score": a.get("score"),
                        "method": "other",
                        "source": {"name": "dependably"},
                    }],
                    "affects": [],
                })
                if not any(x["ref"] == ref for x in v["affects"]):
                    v["affects"].append({"ref": ref})
    for v in vulns.values():
        if not v["references"]:
            del v["references"]
        if v["ratings"][0]["score"] is None:
            del v["ratings"][0]["score"]
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
