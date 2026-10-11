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
CVE_API = "https://cveawg.mitre.org/api/cve"  # CVE Program API (public, no key needed)
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

NAME_CH = r"[\w\-\.\'&–—:(),/+ |\u200c\u200d]"
GENERIC_FIRST = {"web", "the", "a", "an", "wp", "wordpress", "woocommerce", "backup",
                 "file", "advanced", "ultimate", "free", "pro", "lite", "easy", "simple",
                 "new", "best", "top", "super", "my", "our", "plugin", "theme", "premium"}
ORG_SUFFIX = {"inc", "ltd", "llc", "gmbh", "group", "labs", "lab", "technologies",
              "technology", "tech", "software", "systems", "system", "security", "sas",
              "ab", "oy", "srl", "pty", "co", "corp", "studio", "studios", "team"}


def clean(s):
    s = html.unescape(s or "")
    s = re.sub(r"\s+", " ", s).strip().rstrip(" –—-|")
    s = re.sub(r"\s+([.,;:])", r"\1", s)
    return s.strip()


def split_vendor_product(name):
    """'Vendor – Product' / 'A | B' / 'VendorWord rest...' -> (vendor, product)."""
    name = clean(name)
    for sep in (" – ", " — ", " - "):
        if sep in name:
            v, p = (clean(x) for x in name.split(sep, 1))
            return v, p
    if "|" in name:
        a, b = (clean(x) for x in name.split("|", 1))
        prod = b if len(b) > len(a) else a
        first = a.split(" ")[0] if a else ""
        return first, prod or name
    # drop a duplicated trailing "in X" fragment if the regex overshot
    if " in " in name:
        name = name.rsplit(" in ", 1)[1]
    name = re.sub(r"^(the|a|an)\s+", "", name, flags=re.I)
    first = name.split(" ")[0] if name else ""
    if first and first.lower() not in GENERIC_FIRST \
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9&.'\-]*", first):
        return first, name
    # generic first word (e.g. "Web Plura ...") -> first two words as vendor
    words = name.split(" ")
    if len(words) > 1 and words[0].lower() in GENERIC_FIRST:
        return " ".join(words[:2]), name
    return "", name


def split_org(name):
    """'ThemeREX Group Let's Play' / 'rtCamp Inc. rtMedia for WordPress'
    -> (vendor, product) using org-suffix detection."""
    words = clean(name).split(" ")
    for i, w in enumerate(words):
        if w.rstrip(".").lower() in ORG_SUFFIX:
            return " ".join(words[:i + 1]), " ".join(words[i + 1:])
    if len(words) > 1:
        return words[0], " ".join(words[1:])
    return words[0] if words else "", ""


def version_from(t):
    t = t or ""
    m = re.search(r"up to, and including,?\s+([\d][\d.\-a-z]*)", t, re.I)
    if m:
        return f"<= {m.group(1).rstrip('.')}"
    m = re.search(r"\bthrough\s+([\d][\d.\-a-z]*)", t, re.I)
    if m:
        return f"<= {m.group(1).rstrip('.')}"
    m = re.search(r"\bbefore\s+([\d][\d.\-a-z]*)", t, re.I)
    if m:
        return f"< {m.group(1).rstrip('.')}"
    m = re.search(r"(<=|<)\s*([\d][\d.\-a-z]*)", t)
    if m:
        return f"{m.group(1)} {m.group(2).rstrip('.')}"
    return ""


def version_affects(t):
    v = re.search(r"This issue affects [\w .,&+'\-–—]{2,60}?: from ([\w\d.\-/]+) (?:through|before) ([\d.\-]+)", t or "", re.I)
    return f"{v.group(1)} through {v.group(2).rstrip('.')}" if v else ""


def wp_plugin(m, t):
    name = clean(m.group(1))
    name = name.split("|")[0].strip()      # "Avada | Website Builder ..." -> "Avada"
    name = name.split(":")[0].strip()      # "Listdom: AI-powered ..." -> "Listdom"
    name = re.split(r"\s+[–—-]\s+", name)[0].strip()  # "User Frontend – Membership, ..." -> "User Frontend"
    vend, prod = split_vendor_product(name)
    kind = "theme" if "theme" in m.group(0).lower() else "plugin"
    return f"{prod} (WordPress {kind})", version_from(t), vend


def vuln_in_allows(m, t):
    region = m.group(1)
    # "vulnerability in the login handler that allows ..." -> prose, not a product
    if re.match(r"^(the|a|an)\s+", region, re.I):
        return "", "", ""
    vend, prod = split_org(region)
    prod = re.sub(r"\s+[a-z][\w\-]*$", "", prod)          # trailing slug word
    prod = re.split(r",\s*(?=[A-Z][a-z]*(?:Press|Commerce))", prod)[0]  # platform list
    prod = clean(prod)
    # guard: must look like a product name, not "X that allows ..." prose
    low = prod.lower()
    if (not prod or low in ("that", "this", "these", "those", "it")
            or re.match(r"^(and|or|the|a|an|that|this|these|those|it)\b", low)
            or (not re.search(r"[A-Z]", prod) and len(prod) < 12)):
        return "", "", ""
    return prod, version_affects(t), vend


def in_versioned(m, t):
    vend, prod = split_vendor_product(m.group(1))
    op = m.group(2)
    op = "< " if op in ("before", "prior to") else op + " "
    return prod, f"{op}{m.group(3).rstrip('.')}", vend


def affects_from_through(m, t):
    vend, prod = split_vendor_product(m.group(1))
    return prod, f"{m.group(2)} through {m.group(3).rstrip('.')}", vend


def starts_through(m, t):
    prod = clean(m.group(1))
    # guard: reject prose overshoot like "Foo 1.0 is bad, fixed in 2.0 through 3.0"
    if "fixed in" in prod.lower() or len(re.findall(r"\d+\.\d+", prod)) > 1:
        return "", "", ""
    if " in " in prod:
        prod = prod.rsplit(" in ", 1)[1]
    prod = clean(prod)
    if len(prod) > 80 or not prod:
        return "", "", ""
    base = clean(prod.split("(")[0])
    vend, _ = split_vendor_product(base)
    return prod, f"{m.group(2)} through {m.group(4).rstrip('.')}", vend or base


def name_through(m, t):
    prod = clean(m.group(1))
    vend = clean(prod.split("(")[0]) if "(" in prod else prod
    return prod, f"<= {m.group(2).rstrip('.')}", vend


def name_before(m, t):
    prod = clean(m.group(1))
    return prod, f"< {m.group(2).rstrip('.')}", prod


def name_contains(m, t):
    prod = clean(m.group(1))
    vend = clean(prod.split("(")[0]) if "(" in prod else prod
    return prod, m.group(2).rstrip("."), vend


def deserialization_of(m, t):
    return clean(m.group(2)), version_affects(t), clean(m.group(1))


def by_vendor(m, t):
    prod = clean(m.group(1))
    vend = clean(m.group(2))
    vm = re.search(r"([\d][\d.\-a-z]*)\s+by\s+" + re.escape(vend), t or "")
    return prod, vm.group(1).rstrip(".") if vm else "", vend


DESC_PATTERNS = [
    # "The LTL Freight Quotes WordPress plugin before 4.2.19" / "The Graphene theme for WordPress ..."
    (re.compile(r"The (.+?)\s+(?:(plugin|theme) for WordPress|WordPress (plugin|theme))\b", re.I), wp_plugin),
    # "Deserialization ... vulnerability in ThemeREX Group Let's Play playhockey allows ..."
    (re.compile(r"vulnerability in (.+?)\s+(allows|allow|lets|let)(?![\w'])", re.I), vuln_in_allows),
    # "This issue affects Veto: from n/a through 1.0.0"
    (re.compile(r"This issue affects ([\w .&'\-–—]{2,60}?): from ([\w\d.\-/]+) through ([\d.\-]+)", re.I),
     affects_from_through),
    # "Unauthenticated RCE in SiteVault – Backup, Restore, Migration & Cloning <= 1.5.19"
    (re.compile(r"\bin (" + r"[A-Z]" + NAME_CH + r"{1,160}?)\s*(<=|<|through|\bbefore\b|\bprior to\b)\s+([\d][\d.\-a-z]*)", re.I),
     in_versioned),
    # "Floci 1.1.0 before 2.2.0 contains ..." / "1MCP Agent (@1mcp/agent) 0.20.0 through 0.39.0 ..."
    (re.compile(r"^(.+?)\s+([\d][\d.\-a-z]*)\s+(before|through)\s+v?([\d][\d.\-a-z]*)"), starts_through),
    # "openapi-typescript-codegen through 0.31.0 contains ..." / "Open Source Social Network (OSSN) through 10.1 ..."
    # "argocd-mcp (Argo CD MCP Server) through 0.9.0 ..." / "Helicone through v2025.08.21-1 ..."
    (re.compile(r"^([A-Za-z][\w.\-() ]+?)\s+through\s+v?([\d][\d.\-a-z]*)"), name_through),
    (re.compile(r"^([\w][\w.\-]*)\s+through\s+v?([\d][\d.\-a-z]*)"), name_through),
    (re.compile(r"^([\w][\w.\-]*)\s+before\s+v?([\d][\d.\-a-z]*)"), name_before),
    # "OpenLIT 2.1.0 contains an authorization bypass ..."
    (re.compile(r"^([\w][\w.\-]*)\s+([\d][\d.\-a-z]*)\s+contains\b"), name_contains),
    # "... deserialization of Apache DataSketches C++ ..."
    (re.compile(r"\bdeserialization of ([A-Z][\w&.'\-–—]*)\s+([A-Z][\w+&.'\-–—]*(?:\s+[A-Z0-9+][\w+&.'\-–—]*)*)", re.I), deserialization_of),
    # "ExifTool for photo and video 5.0.1-gms by CellHubs constructs ..."
    (re.compile(r"^([A-Z][\w.\-]*)\b.*?\bby\s+([A-Z][\w&.'\-–—]+(?:\s+[A-Z][\w&.'\-–—]+){0,2})"), by_vendor),
]


def guess_product(desc):
    """Fallback: pull vendor/product/version from the description text,
    since fresh CVEs often have no CPE data yet."""
    t = clean(desc)
    for rx, build in DESC_PATTERNS:
        m = rx.search(t)
        if m:
            product, vers, vendor = build(m, t)
            product, vendor = clean(product), clean(vendor)
            if product:
                return product, vers, vendor
    return "", "", ""


def fetch_cna(cid):
    """CNA fallback for CVEs NVD hasn't analyzed yet.

    Fresh CVEs often publish with no CPE configuration data, which used to
    render as "Pending NVD analysis" for days. The CVE Program's own API
    carries the CNA's affected vendor/product from day one, so use that
    instead of waiting for NVD enrichment.
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
        # NVD hasn't analyzed this CVE yet (no CPE data): use the CNA's own
        # affected-product record from the CVE Program API before falling back
        # to description regexes. Authoritative beats heuristic.
        cid = cve.get("id", "")
        if cid:
            cv, cp, cvers = fetch_cna(cid)
            if cp:
                vendor = cv or vendor
                prods.append(cp)
                if cvers:
                    vers.append(cvers)
    if not prods:
        g, gv, gvend = guess_product(desc)
        if g:
            vendor = gvend or vendor
            prods.append(g)
            if gv:
                vers.append(gv)
    if not vendor and prods:
        v, _ = split_vendor_product(prods[0].split(" (")[0])
        if v and v.lower() != prods[0].lower():
            vendor = v
        elif v:
            vendor = v  # single-token project name: project is the vendor
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
