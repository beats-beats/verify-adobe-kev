Put these in ONE folder:
  - every CVE-YYYY.json.xz you downloaded (leave them compressed; no need to extract)
  - the KEV file as known_exploited_vulnerabilities.csv
 
Run from that folder:
  python verify_adobe_kev.py
 
Output: printed tables + adobe_cves_checked.csv (one row per CVE, open it in Excel).
