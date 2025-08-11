import os, json, yaml, pandas as pd
from .ps_runner import PSRunner
from .zero_trust_scoring import score_results
class ZeroTrustEngine:
    def __init__(self, config: dict):
        ps=config.get('ps',{})
        self.runner = PSRunner(shell=ps.get('shell','pwsh'),
                               execution_policy=ps.get('execution_policy','AllSigned'),
                               timeout_sec=ps.get('timeout_sec',180),
                               transcript_dir=ps.get('transcript_dir','logs/transcripts'),
                               configuration_name=ps.get('configuration_name','') or None)
        self.out_dir = config.get('app',{}).get('out_dir','out'); os.makedirs(self.out_dir, exist_ok=True)
    def run_checks(self, manifest_path='checks/manifest.yaml', signed_only=True):
        with open(manifest_path,'r',encoding='utf-8') as f: manifest=yaml.safe_load(f)
        results=[]
        for chk in manifest.get('checks',[]):
            script=os.path.join('checks','scripts',chk['script'])
            try:
                data=self.runner.run_script(script, chk.get('args'), signed_only=signed_only)
                results.append({**{k:v for k,v in chk.items() if k!='script'}, "data":data})
            except Exception as e:
                results.append({**{k:v for k,v in chk.items() if k!='script'}, "error":str(e)})
        with open(os.path.join(self.out_dir,'results.json'),'w',encoding='utf-8') as f: json.dump(results,f,indent=2)
        rows=[]
        for r in results:
            flat={k:v for k,v in r.items() if k!='data'}
            for dk,dv in (r.get('data') or {}).items():
                if dk!="_meta": flat[f"data.{dk}"]=dv
            rows.append(flat)
        pd.DataFrame(rows).to_csv(os.path.join(self.out_dir,'results.csv'), index=False)
        scores=score_results(results)
        with open(os.path.join(self.out_dir,'scores.json'),'w',encoding='utf-8') as f: json.dump(scores,f,indent=2)
        return {"results":"out/results.json","scores":"out/scores.json"}
