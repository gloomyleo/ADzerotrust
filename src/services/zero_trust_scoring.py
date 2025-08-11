PILLARS=['Identity','Devices','Network','Apps','Data']
def score_results(results: list[dict]) -> dict:
    scores = {p:[] for p in PILLARS}
    for r in results:
        p=r.get('pillar','Identity'); scores.setdefault(p,[]).append(1.0 if 'error' not in r else 0.0)
    out={}
    for p,arr in scores.items():
        out[p]=round(sum(arr)/len(arr)*100,1) if arr else 50.0
    out['overall']=round(sum(out.values())/len(out),1); return out
