from __future__ import annotations
import json, math, os, time
from pathlib import Path
import pandas as pd
from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import httpx
from .config import EVENT_CACHE, EVAL_PATH, DATA_DIR, RAW_DIR, VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, GROQ_API_KEY, GROQ_MODEL, AGENT_INTERVAL_SECONDS, DISABLE_AGENT_AUTORUN
from .ml import detector
from .agent import start_background, state, run_once, ask, summary_tool, priority_tool, event_tool, related_tool, distribution_tool

app=FastAPI(title='NetworkPulse AI — Autonomous SOC',version='5.0.0')
app.add_middleware(CORSMiddleware,allow_origins=['*'],allow_credentials=False,allow_methods=['*'],allow_headers=['*'])
FRONTEND=Path(__file__).resolve().parents[2]/'frontend'


def load_events():
    if not EVENT_CACHE.exists(): raise HTTPException(503,'Real-data evidence cache not found. Run setup_windows.bat.')
    return pd.read_csv(EVENT_CACHE,low_memory=False,encoding_errors='replace')

def risk_series(df, bins=48):
    if df.empty:return []
    n=min(bins,len(df)); chunk=max(1,math.ceil(len(df)/n)); out=[]
    for i in range(0,len(df),chunk):
        g=df.iloc[i:i+chunk]
        out.append({'bucket':i//chunk,'risk':round(float(g.risk.mean()),2),'peak':round(float(g.risk.max()),2),'attacks':int((g.label.astype(str).str.upper()!='BENIGN').sum())})
    return out[-bins:]

def safe_label(v): return str(v) if v is not None else 'UNKNOWN'

def dashboard_payload():
    df=load_events(); labels=df.label.astype(str)
    dist=labels.value_counts().head(18).to_dict()
    manifest_path=DATA_DIR/'dataset_manifest.json'
    manifest=json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    return {
        'summary': {**summary_tool(), 'provider':'groq' if GROQ_API_KEY else 'local', 'llm_configured':bool(GROQ_API_KEY), 'corpus':'CICIDS2017', 'corpus_rows':manifest.get('total_rows',len(df)), 'corpus_files':manifest.get('total_files',8), 'feature_count':70},
        'events': priority_tool(18),
        'attack_distribution':dist,
        'risk_series':risk_series(df),
        'agent':state(),
        'evaluation': json.loads(EVAL_PATH.read_text()) if EVAL_PATH.exists() else {'available':False,'models':[]}
    }

@app.on_event('startup')
def startup():
    if EVENT_CACHE.exists() and detector.ready and not DISABLE_AGENT_AUTORUN:
        start_background(AGENT_INTERVAL_SECONDS)

@app.get('/api/ping')
def ping(): return {'ok':True}

@app.get('/api/health')
def health():
    return {'status':'online','model_ready':detector.ready,'agent':'autonomous','llm_configured':bool(GROQ_API_KEY),'llm_model':GROQ_MODEL,'corpus':'CICIDS2017'}

@app.get('/api/dashboard')
def dashboard(): return dashboard_payload()

@app.get('/api/summary')
def summary(): return summary_tool()

@app.get('/api/events')
def events(limit:int=250,severity:str|None=None,label:str|None=None,q:str|None=None):
    return {'events':priority_tool(max(1,min(limit,1000)),severity,label,q)}

@app.get('/api/events/{event_id}')
def event(event_id:str):
    r=event_tool(event_id)
    if r is None: raise HTTPException(404,'Event not found')
    row=pd.DataFrame([r])
    evidence=detector.explain(row)
    raw={k:v for k,v in r.items() if k not in {'risk','severity','anomaly_score','ensemble_probability','xgb_probability','lgbm_probability','catboost_probability','model_agreement','confidence','reconstruction_error','isolation_score','anomaly','event_id','row_id','label'}}
    return {'event_id':event_id,'ground_truth':safe_label(r.get('label')),'evidence':evidence,'raw':raw,'related':related_tool(event_id,10)}

@app.get('/api/evaluation')
def evaluation(): return json.loads(EVAL_PATH.read_text()) if EVAL_PATH.exists() else {'available':False,'models':[]}

@app.get('/api/models/{model}/importance')
def importance(model:str):
    model=model.lower();
    if model not in {'xgboost','lightgbm','catboost'}: raise HTTPException(400,'Unknown model')
    return {'model':model,'features':detector.model_importance(model)}

@app.get('/api/agent')
def agent_status(): return state()

@app.post('/api/agent/run')
def agent_run(): return run_once()

class ChatRequest(BaseModel):
    message:str
    event_id:str|None=None
    history:list[dict]|None=None

@app.post('/api/agent/chat')
def agent_chat(req:ChatRequest):
    if not req.message.strip(): raise HTTPException(400,'Message required')
    answer,provider=ask(req.message,req.event_id,req.history)
    return {'answer':answer,'provider':provider,'agent':True}

@app.get('/api/hunt')
def hunt(q:str|None=None,label:str|None=None,min_risk:float=0,limit:int=20):
    rows=priority_tool(limit,label=label,query=q)
    rows=[r for r in rows if float(r.get('risk',0))>=min_risk]
    return {'query':{'q':q,'label':label,'min_risk':min_risk},'hits':rows}

@app.post('/api/analyze/upload')
async def analyze_upload(file:UploadFile=File(...)):
    if not file.filename.lower().endswith('.csv'): raise HTTPException(400,'CSV required')
    target=DATA_DIR/'uploaded_analysis.csv'; target.write_bytes(await file.read())
    try: df=pd.read_csv(target,low_memory=False,encoding_errors='replace')
    except Exception as exc: raise HTTPException(400,f'Could not parse CSV: {exc}')
    pred=detector.predict(df)
    labels=df.get('Label',pd.Series(['UNLABELED']*len(df))).astype(str).str.strip()
    return {'ok':True,'flows':len(df),'high_risk':int((pred.risk>=65).sum()),'critical':int((pred.risk>=85).sum()),'attack_like':int((pred.ensemble_probability>=detector.threshold).sum()),'top_risk':float(pred.risk.max()) if len(pred) else 0.0,'label_distribution':labels.value_counts().head(10).to_dict()}

async def _vt_ip(ip):
    if not VIRUSTOTAL_API_KEY: return {'available':False,'reason':'VirusTotal API key not configured.'}
    url=f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    async with httpx.AsyncClient(timeout=20) as client:
        r=await client.get(url,headers={'x-apikey':VIRUSTOTAL_API_KEY}); r.raise_for_status(); d=r.json().get('data',{}).get('attributes',{})
    stats=d.get('last_analysis_stats',{}) or {}
    return {'available':True,'ip':ip,'asn':d.get('asn'),'as_owner':d.get('as_owner'),'country':d.get('country'),'continent':d.get('continent'),'last_analysis_stats':stats}

async def _abuse_ip(ip):
    if not ABUSEIPDB_API_KEY: return {'available':False,'reason':'AbuseIPDB API key not configured.'}
    async with httpx.AsyncClient(timeout=20) as client:
        r=await client.get('https://api.abuseipdb.com/api/v2/check',params={'ipAddress':ip,'maxAgeInDays':90,'verbose':''},headers={'Key':ABUSEIPDB_API_KEY,'Accept':'application/json'}); r.raise_for_status(); d=r.json().get('data',{})
    return {'available':True,'ip':ip,'abuseConfidenceScore':d.get('abuseConfidenceScore'),'countryCode':d.get('countryCode'),'usageType':d.get('usageType'),'isp':d.get('isp'),'domain':d.get('domain'),'totalReports':d.get('totalReports'),'isWhitelisted':d.get('isWhitelisted')}

@app.get('/api/intel/ip/{ip}')
async def intel_ip(ip:str):
    out={'ip':ip,'virustotal':None,'abuseipdb':None}
    try: out['virustotal']=await _vt_ip(ip)
    except Exception as exc: out['virustotal']={'available':True,'error':str(exc)}
    try: out['abuseipdb']=await _abuse_ip(ip)
    except Exception as exc: out['abuseipdb']={'available':True,'error':str(exc)}
    return out

@app.get('/api/report/{event_id}',response_class=HTMLResponse)
def report(event_id:str):
    e=event(event_id)
    esc=lambda s: str(s).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
    h=e['evidence'];
    html=f'''<!doctype html><html><head><meta charset="utf-8"><title>NetworkPulse Investigation {esc(event_id)}</title><style>body{{margin:0;background:#040508;color:#eef5f7;font:14px Inter,Arial;line-height:1.6}}main{{max-width:1100px;margin:auto;padding:48px}}.hero,.card{{background:#0a0d12;border:1px solid #1d2731;border-radius:22px;padding:26px;margin:18px 0;box-shadow:0 18px 50px rgba(0,0,0,.35)}}h1{{font-size:44px;line-height:1.05;margin:0 0 12px;background:linear-gradient(90deg,#fff,#54f3da,#a78bfa);-webkit-background-clip:text;color:transparent}}h2{{color:#7eead9}}.pill{{display:inline-block;padding:7px 12px;border-radius:999px;background:#0f201e;color:#6ff1dd;border:1px solid #204c43}}pre{{white-space:pre-wrap;color:#b8c6d2}}.grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}}.metric{{padding:16px;background:#090c11;border:1px solid #1b252f;border-radius:16px}}.value{{font-size:28px;font-weight:800}}small{{color:#738392}}</style></head><body><main><section class="hero"><span class="pill">NETWORKPULSE AI · INVESTIGATION REPORT</span><h1>{esc(event_id)}</h1><p>Ground-truth label: <strong>{esc(e['ground_truth'])}</strong></p><div class="grid"><div class="metric"><small>Risk</small><div class="value">{h['risk']:.1f}/99</div></div><div class="metric"><small>Ensemble probability</small><div class="value">{h['ensemble_probability']*100:.1f}%</div></div><div class="metric"><small>Confidence</small><div class="value">{h['confidence']:.1f}%</div></div></div></section><section class="card"><h2>Model evidence</h2><pre>{esc(json.dumps(h,indent=2,default=str))}</pre></section><section class="card"><h2>Related activity</h2><pre>{esc(json.dumps(e['related'],indent=2,default=str))}</pre></section><section class="card"><h2>Telemetry</h2><pre>{esc(json.dumps(e['raw'],indent=2,default=str))}</pre></section></main></body></html>'''
    return HTMLResponse(html)

if FRONTEND.exists():
    app.mount('/app', StaticFiles(directory=FRONTEND), name='frontend-files')

@app.get('/')
def root():
    path=FRONTEND/'index.html'
    if not path.exists():
        return HTMLResponse('<h1>NetworkPulse frontend missing</h1>',status_code=500)
    # Version the script and stylesheet by file time so the browser never runs a stale cached copy.
    html=path.read_text(encoding='utf-8')
    for name in ('app.js','styles.css'):
        f=FRONTEND/name
        if f.exists():
            html=html.replace(f'/app/{name}"', f'/app/{name}?v={int(f.stat().st_mtime)}"')
    return HTMLResponse(html, headers={'Cache-Control':'no-store'})
