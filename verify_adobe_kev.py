"""
Put these in ONE folder:
  - every CVE-YYYY.json.xz you downloaded (leave them compressed; no need to extract)
  - the KEV file as known_exploited_vulnerabilities.csv

Run from that folder:
  python verify_adobe_kev.py

Output: printed tables + adobe_cves_checked.csv (one row per CVE, open it in Excel).
"""
import csv, glob, json, lzma, os, sys, collections

FOLDER = sys.argv[1] if len(sys.argv) > 1 else "."
START, END = "2018-01-01", "2023-12-31"   # compared as YYYY-MM-DD text, inclusive

# ---- KEV (CISA csv) ----
with open(os.path.join(FOLDER, "known_exploited_vulnerabilities.csv"), newline="", encoding="utf-8-sig") as f:
    kev = {r["cveID"].strip(): r for r in csv.DictReader(f)}
kev_adobe_all = sum(1 for r in kev.values() if r["vendorProject"].strip().lower() == "adobe")
print(f"KEV rows: {len(kev)} | Adobe rows (vendorProject = Adobe): {kev_adobe_all}")


def vuln_vendors(item):
    # CPE string: cpe:2.3:<part>:<vendor>:<product>:...  -> vendor is field 3, product field 4
    for c in item.get("configurations") or []:
        for n in c.get("nodes", []):
            for m in n.get("cpeMatch", []):
                if m.get("vulnerable"):
                    p = m["criteria"].split(":")
                    yield p[3], p[4]


def pick(item, family):
    ms = item.get("metrics", {}).get(family, [])
    if not ms:
        return None
    prim = [m for m in ms if m.get("type") == "Primary"]
    m = (prim or ms)[0]
    return m["cvssData"]["baseScore"], m.get("type")


def band(s):
    return "Low" if s < 4 else "Medium" if s < 7 else "High" if s < 9 else "Critical"


rows, in_window, rejected = {}, 0, 0
files = sorted(glob.glob(os.path.join(FOLDER, "CVE-*.json.xz")) + glob.glob(os.path.join(FOLDER, "CVE-*.json")))
if not files:
    sys.exit("No CVE-*.json.xz files found in the folder.")
print("NVD files:", ", ".join(os.path.basename(x) for x in files))
for fp in files:
    opener = lzma.open if fp.endswith(".xz") else open
    with opener(fp, "rt", encoding="utf-8") as fh:
        d = json.load(fh)
    for it in d["cve_items"]:
        pub = it["published"][:10]
        if not (START <= pub <= END):
            continue
        in_window += 1
        if it["vulnStatus"] == "Rejected":
            rejected += 1
            continue
        prods = sorted({p for v, p in vuln_vendors(it) if v == "adobe"})
        if not prods:
            continue
        v31, v30 = pick(it, "cvssMetricV31"), pick(it, "cvssMetricV30")
        use = v31 or v30
        rows[it["id"]] = dict(
            cve=it["id"], published=pub, products="|".join(prods),
            v31=v31[0] if v31 else "", v30=v30[0] if v30 else "",
            score_used=use[0] if use else "", band=band(use[0]) if use else "NoScore",
            in_kev=int(it["id"] in kev), kev_added=kev[it["id"]]["dateAdded"] if it["id"] in kev else "")
    del d  # free memory before next file

R = sorted(rows.values(), key=lambda r: (r["published"], r["cve"]))
print(f"\nNVD records published {START}..{END} (all vendors, in the files you gave): {in_window}")
print(f"  of which Rejected: {rejected}")
print(f"Adobe records (CPE vendor = adobe, vulnerable): {len(R)}")
print(f"  with no v3.x score: {sum(1 for r in R if r['band']=='NoScore')}")
print(f"  with v3.1: {sum(1 for r in R if r['v31']!='')} | v3.0 only: {sum(1 for r in R if r['v31']=='' and r['v30']!='')}")
print(f"  in KEV: {sum(r['in_kev'] for r in R)}")


def table(title, recs):
    print(f"\n{title}  (n={len(recs)})")
    print(f"{'band':9}{'n':>6}{'KEV':>5}{'%':>7}")
    for b in ["Low", "Medium", "High", "Critical"]:
        g = [r for r in recs if r["band"] == b]
        k = sum(r["in_kev"] for r in g)
        print(f"{b:9}{len(g):6}{k:5}{(100*k/len(g) if g else 0):7.2f}")
    k = sum(r["in_kev"] for r in recs)
    print(f"{'Total':9}{len(recs):6}{k:5}{(100*k/len(recs) if recs else 0):7.2f}")


table("MAIN: v3.1 score, else v3.0", [r for r in R if r["band"] != "NoScore"])
table("SENSITIVITY: v3.1 only", [r for r in R if r["v31"] != ""])

with open(os.path.join(FOLDER, "adobe_cves_checked.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(R[0].keys()))
    w.writeheader()
    w.writerows(R)
print("\nWrote adobe_cves_checked.csv")
