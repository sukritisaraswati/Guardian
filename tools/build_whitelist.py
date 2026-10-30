"""Build guardian/data/whitelist.csv.gz (domain,category) from database.csv."""
import csv, gzip, sys
src = sys.argv[1] if len(sys.argv) > 1 else "database.csv"
dst = sys.argv[2] if len(sys.argv) > 2 else "guardian/data/whitelist.csv.gz"
seen = set(); n = 0
with open(src, encoding="utf-8", newline="") as f, gzip.open(dst, "wt", encoding="utf-8", newline="") as g:
    w = csv.writer(g); w.writerow(["domain", "category"])
    for r in csv.DictReader(f):
        d = r["domain"].strip().lower().rstrip(".")
        if d.startswith("www."): d = d[4:]
        if not d or d in seen: continue
        seen.add(d); w.writerow([d, r["category"]]); n += 1
print(n, "domains ->", dst)
