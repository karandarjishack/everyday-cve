# Everyday CVE

**Every new CVE, explained — the problem and the solution. Updated daily.**

Live site: https://karandarjishack.github.io/everyday-cve/

## What it does

Every morning (~7:30 AM US Eastern), a scheduled job:

1. Pulls the last 24 hours of newly published CVEs from the [NVD API](https://nvd.nist.gov/developers) (NIST)
2. Cross-checks them against [CISA's Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
3. Keeps high/critical severity CVEs, anything exploited in the wild, and common web bug classes
4. Writes each entry with:
   - **The problem** — what it is, what it hits, how the attack works
   - **The solution** — how to fix it, with the vendor patch link and NVD link
5. Commits the day's data as `data/YYYY-MM-DD.json`; the site renders it automatically

## Site

Static site, no build step, no tracking:

- `index.html` / `styles.css` / `app.js` — the reader UI (day picker, search, severity filters, expandable cards)
- `data/days.json` — index of available days
- `data/YYYY-MM-DD.json` — one file per day

## Run the gather manually

From the Actions tab: **Daily CVE gather → Run workflow**.
