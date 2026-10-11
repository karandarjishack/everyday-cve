#!/usr/bin/env python3
"""
Everyday CVE — daily gather job (runs in GitHub Actions).
Pulls the last 24h of new CVEs from NVD, cross-checks CISA KEV,
and writes data/YYYY-MM-DD.json + updates data/days.json.
Each entry carries PROBLEM (what it is / how attacked) and
SOLUTION (how to fix it + patch link).
"""
import csv, io, json, os, re, time, html
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
UA = {"User-Agent": "EverydayCVE/1.0"}
MIN_CVSS = 7.0

CWE_FIX = {
    "CWE-89":  ("SQL injection", "Use parameterized queries / prepared statements; never concatenate user input into SQL. Update to the patched version."),
    "CWE-79":  ("Cross-site scripting (XSS)", "Encode all user-controlled output, enforce a strict Content-Security-Policy, and update to the patched version."),
    "CWE-287": ("Authentication bypass", "Enforce authentication on every affected endpoint/server-side; do not rely on client checks. Update to the patched version."),
    "CWE-306": ("Missing authentication", "Require authentication on all affected endpoints. Update to the patched version."),
    "CWE-798": ("Hard-coded credentials", "Rotate the exposed credentials immediately and move secrets out of code. Update to the patched version."),
    "CWE-284": ("Improper access control", "Add server-side authorization checks for every object and action. Update to the patched version."),
    "CWE-862": ("Missing authorization", "Add server-side authorization checks for every object and action. Update to the patched version."),
    "CWE-863": ("Incorrect authorization", "Correct server-side authorization logic and re-test object-level access. Update to the patched version."),
    "CWE-639": ("Authorization bypass (IDOR)", "Enforce per-user ownership checks on every direct object reference. Update to the patched version."),
    "CWE-200": ("Information disclosure", "Strip debug/verbose data and stack traces from responses; restrict sensitive endpoints. Update to the patched version."),
    "CWE-538": ("Information disclosure", "Strip debug/verbose data and stack traces from responses; restrict sensitive endpoints. Update to the patched version."),
    "CWE-78":  ("OS command injection", "Never pass user input to shell commands; use allowlisted APIs instead. Update to the patched version."),
    "CWE-77":  ("Command injection", "Never pass user input to shell commands; use allowlisted APIs instead. Update to the patched version."),
    "CWE-22":  ("Path traversal", "Canonicalize paths and restrict to an allowlisted directory. Update to the patched version."),
    "CWE-918": ("SSRF", "Allowlist outbound destination URLs and block internal/metadata IP ranges. Update to the patched version."),
    "CWE-434": ("Unrestricted file upload", "Validate file type AND content server-side; store uploads outside the web root. Update to the patched version."),
    "CWE-502": ("Insecure deserialization", "Never deserialize untrusted data; require signed/integrity-checked payloads. Update to the patched version."),
    "CWE-787": ("Out-of-bounds write / RCE", "Update to the patched version immediately; no safe workaround exists for memory-corruption RCE."),
    "CWE-119": ("Memory corruption", "Update to the patched version immediately; no safe workaround exists for memory-corruption flaws."),
    "CWE-120": ("Buffer overflow", "Update to the patched version immediately; no safe workaround exists for buffer overflows."),
    "CWE-20":  ("Improper input validation", "Allowlist and validate all input server-side before use. Update to the patched version."),
    "CWE-352": ("CSRF", "Add anti-CSRF tokens to state-changing requests and check Origin/Referer. Update to the patched version."),
    "CWE-611": ("XXE", "Disable external entity resolution in XML parsers. Update to the patched version."),
    "CWE-601": ("Open redirect", "Validate redirect targets against an allowlist. Update to the patched version."),
}

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}


def http_json(url):
    time.sleep(6)
    with urlopen(Request(url, headers=UA), timeout=60) as r:
        return json.load(r)


def fetch_nvd():
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=24)
    fmt = lambda d: d.strftime("%Y-%m-%dT%H:%M:%S.000")
    base = f"{NVD}?pubStartDate={fmt(start)}&pubEndDate={fmt(end)}&resultsPerPage=2000"
    vulns, idx = [], 0
    while True:
        d = http_json(f"{base}&startIndex={idx}")
        vulns.extend(d.get("vulnerabilities", []))
        idx += d.get("resultsPerPage", 0)
        if idx >= d.get("totalResults", 0):
            break
    return vulns, end


def fetch_kev():
    with urlopen(Request(KEV_URL, headers=UA), timeout=60) as r:
        text = r.read().decode("utf-8", errors="replace")
    kev = {}
    for row in csv.DictReader(io.StringIO(text)):
        kev[row["cveID"].strip().upper()] = row.get("dateAdded", "")
    return kev


def cvss(cve):
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        for m in cve.get("metrics", {}).get(key, []):
            return m["cvssData"]["baseScore"], m["cvssData"].get("vectorString", "")
    return None, ""


def cwes(cve):
    out = set()
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("value", "").startswith("CWE-"):
                out.add(d["value"])
    return sorted(out)


NAME_CH = r"[\w\-\.\'&–—:(),/+ ]"
DESC_PATTERNS = [
    # "The X plugin for WordPress ... up to, and including, 1.2.3"
    (re.compile(r"The (.+?) plugin for WordPress", re.I),
     lambda m, t: (f"{m.group(1).strip()} (WordPress plugin)",
                   version_from(t), m.group(1).strip())),
    # "Deserialization ... vulnerability in ThemeREX Group Booklovers booklovers allows"
    (re.compile(r"vulnerability in ((?:[A-Z][\w&'\-–—]+)(?:\s+[A-Z][\w&'\-–—]+){0,1}) ([A-Z][\w\-–—]{1,40}) ([a-z][\w\-]{1,40}) allows"),
     lambda m, t: (f"{m.group(2).strip()} ({m.group(1).strip()})",
                   version_affects(t), m.group(1).strip())),
    # "in SiteVault – Backup, Restore, Migration & Cloning <= 1.5.19"
    (re.compile(r"\bin ([A-Z]" + NAME_CH + r"{1,60}?)\s*(<=|<|through|\bbefore\b|\bprior to\b)\s+([\d][\d.\-a-z]*)", re.I),
     lambda m, t: (m.group(1).strip().rstrip(" –—-"),
                   f"{'< ' if m.group(2) in ('before', 'prior to') else m.group(2) + ' '}{m.group(3).rstrip('.')}", "")),
    # "This issue affects Veto: from n/a through 1.0.0"
    (re.compile(r"This issue affects ([\w .&'\-–—]{2,50}?): from ([\w\d.\-/]+) through ([\d.\-]+)", re.I),
     lambda m, t: (m.group(1).strip().title(),
                   f"{m.group(2)} through {m.group(3).rstrip('.')}", "")),
]


def version_from(t):
    v = re.search(r"(?:up to, and including,|before|<=|<|through)\s+([\d][\d\.\-a-z]*)", t or "")
    return f"<= {v.group(1).rstrip('.')}" if v else ""


def version_affects(t):
    v = re.search(r"This issue affects [\w .&'\-–—]{2,50}?: from ([\w\d.\-/]+) through ([\d.\-]+)", t or "", re.I)
    return f"{v.group(1)} through {v.group(2).rstrip('.')}" if v else ""


def guess_product(desc):
    """Fallback: pull vendor/product/version from the description text,
    since fresh CVEs often have no CPE data yet."""
    t = desc or ""
    for rx, build in DESC_PATTERNS:
        m = rx.search(t)
        if m:
            product, vers, vendor = build(m, t)
            return product, vers, vendor
    return "", "", ""


def products(cve, desc=""):
    prods, vers, seen = [], [], set()
    vendors = []
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                p = m.get("criteria", "").split(":")
                if len(p) < 5 or p[2] not in ("a", "o"):
                    continue
                key = (p[3], p[4])
                if key not in seen and "*" not in key:
                    seen.add(key)
                    vendor = p[3].replace("_", " ").strip().title()
                    product = p[4].replace("_", " ").strip().title()
                    vendors.append(vendor)
                    prods.append(product)
                rng = []
                if m.get("versionStartIncluding"): rng.append(">=" + m["versionStartIncluding"])
                if m.get("versionEndExcluding"): rng.append("<" + m["versionEndExcluding"])
                if m.get("versionStartExcluding"): rng.append(">" + m["versionStartExcluding"])
                if m.get("versionEndIncluding"): rng.append("<=" + m["versionEndIncluding"])
                if rng:
                    vers.append(f"{p[4].replace('_',' ')} {' '.join(rng)}")
    vendor = vendors[0] if vendors else ""
    if not prods:
        g, gv, gvend = guess_product(desc)
        if g:
            vendor = gvend or vendor
            prods.append(g)
            if gv:
                vers.append(gv)
    if not vendor and prods and "(" not in prods[0]:
        first = prods[0].split(" ")[0]
        if re.fullmatch(r"[A-Za-z]{3,}", first or ""):
            vendor = first
    return vendor, prods[:3], vers[:2]


VECTOR_LABELS = {
    "AV:N": "Remote (network)", "AV:A": "Adjacent network", "AV:L": "Local access", "AV:P": "Physical",
    "AC:L": "Low complexity", "AC:H": "High complexity",
    "PR:N": "No privileges needed", "PR:L": "Low privileges needed", "PR:H": "High privileges needed",
    "UI:N": "No user interaction", "UI:R": "User interaction needed", "UI:A": "Active user interaction",
    "S:C": "Scope changed", "S:U": "Scope unchanged",
    "C:H": "High confidentiality impact", "I:H": "High integrity impact", "A:H": "High availability impact",
}


def attack_profile(vector):
    chips = []
    for part in (vector or "").split("/"):
        if part in VECTOR_LABELS:
            chips.append((part.split(":")[0], VECTOR_LABELS[part]))
    order = {"AV": 0, "PR": 1, "UI": 2, "AC": 3, "S": 4, "C": 5, "I": 6, "A": 7}
    chips.sort(key=lambda c: order.get(c[0], 99))
    return [c[1] for c in chips[:6]]


def refs(cve):
    patch, exploit = [], []
    for r in cve.get("references", []):
        tags = [t.lower() for t in r.get("tags", [])]
        if any("patch" in t or "vendor advisory" in t or "mitigation" in t for t in tags):
            patch.append(r["url"])
        elif any("exploit" in t for t in tags):
            exploit.append(r["url"])
    return patch, exploit


def one_line(t, n=1500):
    t = html.unescape(re.sub(r"\s+", " ", t or "").strip())
    t = re.sub(r"\s+([.,;:)])", r"\1", t)          # no space before punctuation
    t = re.sub(r"\bsQL\b", "SQL", t)               # NVD casing glitch
    if t and not t.endswith((".", "!", "?", "…")):
        t += "."
    return t if len(t) <= n else t[: n - 1].rstrip() + "…"


def main():
    os.makedirs(DATA, exist_ok=True)
    vulns, end = fetch_nvd()
    kev = fetch_kev()
    day = end.strftime("%Y-%m-%d")
    day_path = os.path.join(DATA, f"{day}.json")
    done = set()
    if os.path.exists(day_path):
        with open(day_path) as f:
            done = {e["id"] for e in json.load(f)}

    entries = []
    for v in vulns:
        cve = v.get("cve", {})
        cid = cve.get("id", "")
        if not cid or cid in done:
            continue
        score, vector = cvss(cve)
        in_kev = cid.upper() in kev
        cw = cwes(cve)
        labels = [CWE_FIX[c][0] for c in cw if c in CWE_FIX]
        if not (in_kev or (score is not None and score >= MIN_CVSS) or labels):
            continue
        patch, exploit = refs(cve)
        desc = cve.get("descriptions", [{}])[0].get("value", "")
        vendor, prods, vers = products(cve, desc)
        av = re.search(r"AV:([NALP])", vector or "")
        scope = {"N": "Exploitable remotely over the network.",
                 "A": "Exploitable from the adjacent network.",
                 "L": "Requires local access to exploit.",
                 "P": "Requires physical access to exploit."}.get(av.group(1) if av else "")
        problem = one_line(desc, 1500) + (f" {scope}" if scope else "")
        solution = next((CWE_FIX[c][1] for c in cw if c in CWE_FIX),
                        "Apply the vendor patch at the earliest maintenance window and confirm the asset is not internet-exposed.")
        fixm = re.search(r"(?:fixed in|update to|patched in)\s+(?:version\s+)?([\d][\d\.\-a-z]*)", desc, re.I)
        fixed_in = fixm.group(1).rstrip(".") if fixm else ""
        if fixed_in:
            solution = f"Fixed in version {fixed_in} — update immediately. " + solution
        sev = "CRITICAL" if score and score >= 9.0 else "HIGH" if score and score >= 7.0 else "MEDIUM"
        entries.append({
            "id": cid, "date": cve.get("published", "")[:10],
            "severity": sev, "score": score if score is not None else "n/a",
            "exploited": in_kev, "exploit_public": bool(exploit),
            "bug_class": ", ".join(labels[:2]),
            "vendor": vendor,
            "product": ", ".join(prods), "versions": "; ".join(vers),
            "fixed_in": fixed_in,
            "attack": attack_profile(vector),
            "problem": problem, "solution": solution,
            "patch": patch[0] if patch else "",
            "nvd": f"https://nvd.nist.gov/vuln/detail/{cid}",
        })
    entries.sort(key=lambda e: (0 if e["exploited"] else 1,
                                SEV_ORDER.get(e["severity"], 3),
                                -(e["score"] if isinstance(e["score"], (int, float)) else 0)))

    if os.path.exists(day_path):
        with open(day_path) as f:
            entries = json.load(f) + entries
    with open(day_path, "w") as f:
        json.dump(entries, f)

    days_path = os.path.join(DATA, "days.json")
    days = []
    if os.path.exists(days_path):
        with open(days_path) as f:
            days = json.load(f)
    if day not in days:
        days.append(day)
    days.sort(reverse=True)
    with open(days_path, "w") as f:
        json.dump(days, f)
    print(f"{day}: {len(entries)} entries")


if __name__ == "__main__":
    main()
