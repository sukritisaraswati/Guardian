import re, html
S = {  # strong patterns (score 3 in title, 2 in desc)
 "Adult": r"\bporn|\bxxx\b|hentai|\bescorts?\b|\bnsfw|onlyfans|rule ?34|\bjav\b|doujin|sex (videos?|cams?|chat|stories)|nude|erotic|порно|секс[- ]|成人|色情|ポルノ|アダルト|엄마|av ?女優|เซ็กส์",
 "Gaming & Gambling": r"casino|\bslots?\b|togel|\btoto ?\d*\b|\bbetting|sportsbook|satta|matka|\bpoker|\bbandar|\bjudi\b|nhà cái|\bgacor\b|bet365|1xbet|казино|букмекер|赌场|博彩|カジノ|\blottery|online games?|free games?|\bgames?\b.*play|\bgaming\b|\bmmorpg|roblox|minecraft|game(s)? (server|guide|wiki|portal)|\bgame ?(zone|hub|site)",
 "Cybersecurity": r"\bvpn\b|antivirus|anti-?malware|threat intelligence|penetration test|endpoint (security|protection)|cyber ?security|firewall|siem\b|password manager|ddos protection",
 "Advertising, Analytics & Tracking": r"\badtech\b|ad (network|exchange|server)|programmatic|affiliate network|web analytics|retargeting|real-time bidding|demand[- ]side platform|publicité contextuelle|ad ?platform|advertising platform",
 "Finance & Payments": r"\bbank(ing)?\b|credit union|\bloans?\b|insurance|mortgage|payment (gateway|processing|solutions)|\bforex\b|stock broker|\bipo\b|trading platform|investments?\b|wealth management|crypto(currency)? (exchange|wallet)|银行|保险|証券|банк|страхов",
 "Health & Medical": r"hospital|clinic\b|medical|pharmacy|prescription|health ?care|dentist|dental|doctors?\b|physician|cancer|patients?\b|医院|診療|病院|больниц|аптек|داروخانه|سلامت",
 "Education & Research": r"university|universidad|universität|université|университет|\bcollege\b|\bschools?\b|e-?learning|online courses?|scholarship|research (institute|center|centre)|\bK-?12\b|大学|学校|学院|школ|institute of technology",
 "Government & Non-profit": r"government|ministry|municipal|city of |county\b|official (site|website|portal) of|non-?profit|charity|ministerio|gobierno|правительств|政府|市役所|\bchurch\b|jehovah|\bun\b.*organization|world .* organization|\bNGO\b",
 "News & Media": r"\bnews\b|newspaper|breaking news|noticias|actualités|nachrichten|новости|новини|ニュース|新闻|新聞|\bberita\b|haber(ler)?\b|journal\b|daily\b|\btimes\b|\bpost\b|\bmagazine\b",
 "Entertainment & Streaming": r"watch (movies?|anime|tv|online|free)|stream(ing)? (movies?|tv|anime)|free movies|\banime\b|\bmanga\b|\bmanhwa|webtoon|\bcomics?\b|podcast|\bmusic\b|\bmp3\b|lyrics|tv series|subtitles|episodes?\b|漫画|фильмы|смотреть|\bvideos?\b|\bfilm",
 "Social Media & Communication": r"social (network|media|platform)|messenger|chat (app|room|rooms)|dating|\bforums?\b|community forum|video call|webmail|email service|вконтакте|论坛|社交|掲示板",
 "E-commerce & Shopping": r"online (shop|store|shopping)|add to cart|free (shipping|delivery)|fashion|\bshop\b|marketplace|coupons?|\bdeals\b|discount|boutique|jewel|furniture|tienda|интернет-магазин|商城|网店|通販|ショップ|toko online|loja\b|\bbuy\b|\bsale\b|купить",
 "Travel, Lifestyle & Automotive": r"\bhotels?\b|flights?\b|\btravel|tourism|vacation|\bresorts?\b|\bcars?\b|automotive|dealership|auto parts|real estate|recipes?|restaurant|fitness|beauty|wedding|\bweather\b|meteo|автомобил|машин|недвижимость|旅游|酒店|旅行|不動産|inmobiliaria|imóveis|\btrain|\btimetable",
 "Technology & Software": r"software|\bsaas\b|open source|developers?\b|\bapi\b|\bapk\b|\bdownloader\b|programming|github|devops|it solutions|artificial intelligence|\bai\b|软件|программн|ソフトウェア|\berp\b|\bcrm\b|\bapps?\b",
 "Cloud, CDN & Infrastructure": r"\bcdn\b|content delivery|dedicated servers?|\bvps\b|cloud hosting|web hosting|data ?cent(er|re)|dns (service|hosting)|dynamic dns|colocation|domain (registration|registrar)|internet service provider|\bisp\b|broadband|宽带",
}
STRONG_ONLY = {"Adult","Cybersecurity","Advertising, Analytics & Tracking"}
C = {k:re.compile(v,re.I) for k,v in S.items()}
PARK = re.compile(r"domain information|domain (is )?for sale|parked|coming soon|under construction|default (web )?page|index of /|403 forbidden|404|not found|just a moment|attention required|access denied|apache|nginx|^welcome to|it works|^home$|suspended|expired|^&nbsp;$|^$", re.I)
def clean(s): return html.unescape(html.unescape(s or "")).replace("\xa0"," ").strip()
def classify(r):
    t=clean(r["title"]); d=clean(r["desc"])
    if len(t)+len(d)<8 or (PARK.search(t) and not d): return None
    sc={}
    for k,p in C.items():
        s=3*len(set(m.lower() for m in map(str,p.findall(t)))) if p.search(t) else 0
        if p.search(d): s+=2
        if s: sc[k]=s
    if not sc: return None
    top=sorted(sc.items(),key=lambda x:-x[1])
    if top[0][1]<3: return None
    if len(top)>1 and top[0][1]-top[1][1]<2: return None
    return top[0][0], top[0][1]
