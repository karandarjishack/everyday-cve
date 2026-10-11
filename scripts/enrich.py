#!/usr/bin/env python3
"""
Everyday CVE — weekly enrichment (runs in GitHub Actions).
Fresh CVEs often publish with no CPE vendor/product data and no tagged
patch links; NVD adds them over the following days. This job re-checks
recent entries that are missing vendor/product/patch and fills them in,
preferring NVD's CPE data, then the CNA's own affected-product record
(CVE Program API), so cards stop showing "Pending NVD analysis".
"""
import html
import json, os, re, time
from datetime import datetime, timedelta
from urllib.request import Request, urlopen

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_API = "https://cveawg.mitre.org/api/cve"  # CVE Program API (public, no key needed)
UA = {"User-Agent": "EverydayCVE-enrich/1.0"}
MAX_CALLS = 600  # ~60 min at 6s spacing


def clean(s):
    s = html.unescape(s or "")
    return re.sub(r"\s+", " ", s).strip()


def fetch_cve(cid):
    time.sleep(6)
    req = Request(f"{NVD}?cveId={cid}", headers=UA)
    with urlopen(req, timeout=60) as r:
        d = json.load(r)
    v = d.get("vulnerabilities", [])
    return v[0]["cve"] if v else None


def extract(cve):
    vendors, prods, vers = [], [], []
    seen = set()
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                p = m.get("criteria", "").split(":")
                if len(p) < 5 or p[2] not in ("a", "o"):
                    continue
                key = (p[3], p[4])
                if key in seen or "*" in key:
                    continue
                seen.add(key)
                vendors.append(p[3].replace("_", " ").strip().title())
                prods.append(p[4].replace("_", " ").strip().title())
                rng = []
                if m.get("versionStartIncluding"): rng.append(">=" + m["versionStartIncluding"])
                if m.get("versionEndExcluding"): rng.append("<" + m["versionEndExcluding"])
                if m.get("versionStartExcluding"): rng.append(">" + m["versionStartExcluding"])
                if m.get("versionEndIncluding"): rng.append("<=" + m["versionEndIncluding"])
                if rng:
                    vers.append(f"{p[4].replace('_', ' ')} {' '.join(rng)}")
    patch = ""
    for r in cve.get("references", []):
        tags = [t.lower() for t in r.get("tags", [])]
        if any("patch" in t or "vendor advisory" in t or "mitigation" in t for t in tags):
            patch = r["url"]
            break
    return vendors, prods, vers, patch


def fetch_cna(cid):
    """CNA fallback for CVEs NVD still hasn't analyzed.

    Returns (vendor, product, versions) from the CNA's own affected-product
    record via the CVE Program API. Authoritative — preferred over any
    description-regex guess stored earlier.
    """
    try:
        time.sleep(2)
        with urlopen(Request(f"{CVE_API}/{cid}", headers=UA), timeout=30) as r:
            d = json.load(r)
    except Exception:
        return "", "", ""
    cna = d.get("containers", {}).get("cna", {})
    for a in cna.get("affected", []) or []:
        product = clean(a.get("product", ""))
        if not product or product.lower() in ("n/a", "unknown"):
            continue
        vendor = clean(a.get("vendor", ""))
        if vendor.lower() in ("n/a", "unknown"):
            vendor = ""
        vers = []
        for v in a.get("versions", []) or []:
            if v.get("status") != "affected":
                continue
            if v.get("lessThanOrEqual"):
                vers.append(f"<= {v['lessThanOrEqual']}")
            elif v.get("lessThan"):
                vers.append(f"< {v['lessThan']}")
            elif v.get("version") and v["version"].lower() not in ("n/a", "*"):
                vers.append(v["version"].rstrip("."))
        return vendor, product, "; ".join(vers[:2])
    return "", "", ""


def main():
    cutoff = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")
    days_path = os.path.join(DATA, "days.json")
    days = json.load(open(days_path)) if os.path.exists(days_path) else []
    targets = [d for d in days if d >= cutoff]
    calls, filled = 0, 0
    for day in sorted(targets):
        path = os.path.join(DATA, f"{day}.json")
        if not os.path.exists(path):
            continue
        entries = json.load(open(path))
        changed = False
        for e in entries:
            if calls >= MAX_CALLS:
                break
            if (e.get("vendor") or e.get("product")) and e.get("patch"):
                continue
            try:
                cve = fetch_cve(e["id"])
            except Exception as ex:
                print(f"skip {e['id']}: {ex}")
                continue
            calls += 1
            if not cve:
                continue
            vendors, prods, vers, patch = extract(cve)
            if not (vendors or prods):
                # NVD still hasn't analyzed this CVE (no CPE data): the CNA's
                # own record is authoritative, so it replaces any
                # description-regex guess stored earlier.
                cv, cp, cvers = fetch_cna(e["id"])
                if cp:
                    e["vendor"] = cv
                    e["product"] = cp
                    e["versions"] = cvers
                    changed = True
            else:
                if not e.get("vendor") and vendors:
                    e["vendor"] = vendors[0]
                    changed = True
                if not e.get("product") and prods:
                    e["product"] = ", ".join(prods[:3])
                    changed = True
                if not e.get("versions") and vers:
                    e["versions"] = "; ".join(vers[:2])
                    changed = True
            if not e.get("patch") and patch:
                e["patch"] = patch
                changed = True
            if changed:
                filled += 1
        if changed:
            json.dump(entries, open(path, "w"))
            print(f"{day}: updated")
    print(f"done: {calls} NVD calls, {filled} entries enriched")


if __name__ == "__main__":
    main()
