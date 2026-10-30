import csv, sys, re, ssl, json, os, urllib.request
from concurrent.futures import ThreadPoolExecutor
src="D:/Sukriti RRU/Projects/Guardian/categorized_websites_old.csv"; out="medium_titles.jsonl"
ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
done=set()
if os.path.exists(out):
    for l in open(out,encoding="utf-8"):
        try: done.add(json.loads(l)["rank"])
        except: pass
rows=[r for r in csv.DictReader(open(src,encoding="utf-8")) if r["confidence"]=="medium" and r["rank"] not in done]
def get(r):
    d=r["domain"]; res={"rank":r["rank"],"domain":d,"title":"","desc":"","err":""}
    for u in ("https://"+d,"http://"+d):
        try:
            req=urllib.request.Request(u,headers={"User-Agent":"Mozilla/5.0"})
            b=urllib.request.urlopen(req,timeout=5,context=ctx).read(40000).decode("utf-8","ignore")
            t=re.search(r"<title[^>]*>(.*?)</title>",b,re.I|re.S)
            m=re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']',b,re.I|re.S)
            res["title"]=re.sub(r"\s+"," ",t.group(1)).strip()[:150] if t else ""
            res["desc"]=re.sub(r"\s+"," ",m.group(1)).strip()[:200] if m else ""
            res["err"]=""; break
        except Exception as e: res["err"]=type(e).__name__
    return res
print(len(rows),flush=True)
with ThreadPoolExecutor(1000) as ex, open(out,"a",encoding="utf-8") as f:
    for i,r in enumerate(ex.map(get,rows)):
        f.write(json.dumps(r,ensure_ascii=False)+"\n")
        if i%1000==0: print(i,flush=True); f.flush()
