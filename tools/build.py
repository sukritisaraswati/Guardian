import csv, json, sys, collections, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from classify2 import classify
P = "D:/Sukriti RRU/Projects/Guardian/"
S = os.path.dirname(os.path.abspath(__file__)) + "/"

old = list(csv.DictReader(open(P + "categorized_websites_old.csv", encoding="utf-8")))

corr = {}
for name in ("batch1", "fallback", "lowconf"):
    for r in csv.DictReader(open(P + f"corrected_categories_{name}.csv", encoding="utf-8")):
        corr[r["rank"]] = (r["category"], name)

pages = {}  # rank -> record with title/desc/err (later files override earlier only if they have text)
for fn in ("fallback_titles.jsonl", "low_titles.jsonl", "medium_titles.jsonl", "retry_titles.jsonl"):
    if not os.path.exists(S + fn):
        continue
    for l in open(S + fn, encoding="utf-8"):
        try:
            r = json.loads(l)
        except Exception:
            continue
        if r["rank"] not in pages or r["title"] or r["desc"]:
            pages[r["rank"]] = r

out = []
stat = collections.Counter()
for r in old:
    k = r["rank"]
    if k in corr:
        cat, name = corr[k]
        basis = {"batch1": "corrected_batch1_site_opened", "fallback": "corrected_fallback_site_read",
                 "lowconf": "corrected_lowconf_site_read"}[name]
    elif r["confidence"] == "high":
        cat, basis = r["category"], "original_high"
    else:
        p = pages.get(k)
        has_text = p and (p["title"] or p["desc"])
        x = classify(p) if has_text else None
        if x:
            cat = x[0]
            basis = "site_visited_confirmed" if cat == r["category"] else "site_visited_reclassified"
        elif has_text:
            cat, basis = r["category"], "site_visited_unclear_kept_old"
        else:
            cat, basis = r["category"], "unreachable_kept_old"
    stat[basis] += 1
    out.append((int(k), r["domain"], cat, basis))

out.sort()
with open(P + "database.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["rank", "domain", "category", "basis"])
    w.writerows(out)
print(len(out))
for b, n in stat.most_common():
    print(f"{b:34s}{n:8d}")
