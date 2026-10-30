from __future__ import annotations
import json, threading, time
from datetime import datetime, timezone
from typing import Any
import pandas as pd
import httpx
from .config import EVENT_CACHE, AGENT_LOG, EVAL_PATH, GROQ_API_KEY, GROQ_MODEL
from .ml import detector

_lock = threading.Lock()
_state = {
    'running': False, 'last_run': None, 'summary': 'Ready for autonomous investigation.',
    'provider': 'groq' if GROQ_API_KEY else 'local', 'llm_ready': bool(GROQ_API_KEY),
    'priority': [], 'events': [], 'cycle': 0
}

SYSTEM = '''You are NetworkPulse Agent, an autonomous SOC investigation analyst. You work only from supplied evidence. Never invent network facts. Distinguish dataset ground-truth labels from model predictions. Explain risk using ensemble probability, model agreement, autoencoder reconstruction deviation and other telemetry. When asked for action, recommend analyst-reviewable next steps; never block, quarantine, delete, or change infrastructure automatically. Be concise but specific.''' 


def now(): return datetime.now(timezone.utc).isoformat()

def load_events() -> pd.DataFrame:
    if not EVENT_CACHE.exists(): return pd.DataFrame()
    return pd.read_csv(EVENT_CACHE, low_memory=False, encoding_errors='replace')

def _safe(v):
    try:
        import numpy as np
        if pd.isna(v): return None
        if hasattr(v, 'item'): return v.item()
    except Exception: pass
    return v

def log(step: str, detail: str, kind: str='info'):
    item={'time': now(), 'step': step, 'detail': detail, 'kind': kind}
    with _lock:
        _state['events']=(_state.get('events',[])+[item])[-160:]
        AGENT_LOG.write_text(json.dumps(_state, indent=2, default=str), encoding='utf-8')

def summary_tool():
    df=load_events()
    if df.empty: return {'status':'no telemetry'}
    labels=df['label'].astype(str).str.upper()
    dist=df['label'].astype(str).value_counts().head(15).to_dict()
    return {
        'flows':len(df),'attack_labelled':int((labels!='BENIGN').sum()),
        'critical':int((df.risk>=85).sum()),'high':int(((df.risk>=65)&(df.risk<85)).sum()),
        'medium':int(((df.risk>=40)&(df.risk<65)).sum()),'low':int((df.risk<40).sum()),
        'top_risk':round(float(df.risk.max()),2),'mean_risk':round(float(df.risk.mean()),2),
        'attack_distribution':dist,
        'champion':'Weighted ensemble: XGBoost + LightGBM + CatBoost; anomaly evidence from Autoencoder + Isolation Forest.'
    }

def priority_tool(limit=12, severity=None, label=None, query=None):
    df=load_events()
    if df.empty: return []
    if severity: df=df[df.severity.astype(str).str.lower()==str(severity).lower()]
    if label: df=df[df.label.astype(str).str.lower()==str(label).lower()]
    if query:
        q=str(query).lower(); df=df[df.astype(str).apply(lambda c:c.str.lower().str.contains(q, na=False)).any(axis=1)]
    cols=[c for c in ['event_id','label','destination_port','risk','severity','ensemble_probability','confidence','model_agreement','anomaly_score','reconstruction_error','xgb_probability','lgbm_probability','catboost_probability'] if c in df.columns]
    return df.sort_values('risk',ascending=False).head(max(1,min(int(limit),50)))[cols].round(5).to_dict('records')

def event_tool(event_id):
    df=load_events()
    if df.empty: return None
    m=df[df.event_id.astype(str)==str(event_id)]
    if m.empty: return None
    r=m.iloc[0]
    return {k:_safe(v) for k,v in r.to_dict().items()}

def related_tool(event_id,limit=10):
    df=load_events()
    if df.empty: return []
    m=df[df.event_id.astype(str)==str(event_id)]
    if m.empty:return []
    r=m.iloc[0]
    same=df[(df.label.astype(str)==str(r.label)) | (df.destination_port==r.destination_port)].copy()
    same['distance']=(same.risk-r.risk).abs()
    cols=[c for c in ['event_id','label','destination_port','risk','severity','ensemble_probability','confidence'] if c in same.columns]
    return same.sort_values(['distance','risk'],ascending=[True,False]).head(limit)[cols].round(4).to_dict('records')

def eval_tool():
    return json.loads(EVAL_PATH.read_text()) if EVAL_PATH.exists() else {'available':False}

def distribution_tool():
    df=load_events(); return df.label.astype(str).value_counts().head(20).to_dict() if not df.empty else {}

def importance_tool(model='xgboost'):
    return detector.model_importance(model)

TOOLS={
 'get_network_summary': lambda **_: summary_tool(),
 'get_priority_events': lambda limit=10,severity=None,label=None,query=None: priority_tool(limit,severity,label,query),
 'get_event': lambda event_id: event_tool(event_id),
 'search_related_events': lambda event_id,limit=10: related_tool(event_id,limit),
 'get_evaluation_metrics': lambda **_: eval_tool(),
 'get_attack_distribution': lambda **_: distribution_tool(),
 'get_feature_importance': lambda model='xgboost': importance_tool(model)
}
TOOL_SCHEMAS=[
 {'type':'function','function':{'name':'get_network_summary','description':'Return current network counts, risk tiers and attack distribution.','parameters':{'type':'object','properties':{}}}},
 {'type':'function','function':{'name':'get_priority_events','description':'Return highest-risk network flows with ensemble evidence.','parameters':{'type':'object','properties':{'limit':{'type':'integer','minimum':1,'maximum':20},'severity':{'type':'string'},'label':{'type':'string'},'query':{'type':'string'}},'required':[]}}},
 {'type':'function','function':{'name':'get_event','description':'Inspect one NetworkPulse event and return scored model evidence plus telemetry.','parameters':{'type':'object','properties':{'event_id':{'type':'string'}},'required':['event_id']}}},
 {'type':'function','function':{'name':'search_related_events','description':'Find related flows by attack label, destination port and risk proximity.','parameters':{'type':'object','properties':{'event_id':{'type':'string'},'limit':{'type':'integer','minimum':1,'maximum':12}},'required':['event_id']}}},
 {'type':'function','function':{'name':'get_evaluation_metrics','description':'Return held-out benchmark metrics and methodology.','parameters':{'type':'object','properties':{}}}},
 {'type':'function','function':{'name':'get_attack_distribution','description':'Return attack label distribution in current evidence cache.','parameters':{'type':'object','properties':{}}}},
 {'type':'function','function':{'name':'get_feature_importance','description':'Return global feature importance for a requested ensemble component.','parameters':{'type':'object','properties':{'model':{'type':'string','enum':['xgboost','lightgbm','catboost']}},'required':[]}}},
]

def groq_request(messages, tools=None):
    if not GROQ_API_KEY: return None
    body={'model':GROQ_MODEL,'messages':messages,'temperature':0.15,'max_tokens':1400}
    if tools is not None:
        body['tools']=tools; body['tool_choice']='auto'
    headers={'Authorization':f'Bearer {GROQ_API_KEY}','Content-Type':'application/json'}
    with httpx.Client(timeout=50) as client:
        resp=client.post('https://api.groq.com/openai/v1/chat/completions',headers=headers,json=body)
        resp.raise_for_status(); return resp.json()

def extract_message(data):
    if not data: return {}
    return data.get('choices',[{}])[0].get('message',{}) or {}

def ask(question, event_id=None, history=None):
    prefix = f'Focused event: {event_id}. ' if event_id else ''
    messages=[{'role':'system','content':SYSTEM}]
    if history: messages.extend(history[-8:])
    messages.append({'role':'user','content':prefix+question})
    if GROQ_API_KEY:
        try:
            for round_no in range(3):
                data=groq_request(messages,TOOL_SCHEMAS)
                msg=extract_message(data); tool_calls=msg.get('tool_calls') or []
                messages.append(msg)
                if not tool_calls:
                    content=msg.get('content') or ''
                    return str(content), 'groq'
                for call in tool_calls[:8]:
                    name=call.get('function',{}).get('name','')
                    try: args=json.loads(call.get('function',{}).get('arguments') or '{}')
                    except Exception: args={}
                    fn=TOOLS.get(name)
                    result=fn(**args) if fn else {'error':'Unknown tool'}
                    log('TOOL',f'{name}({json.dumps(args)})','success')
                    messages.append({'role':'tool','tool_call_id':call.get('id',''),'content':json.dumps(result,default=str)})
            # Hard stop: ask for synthesis with no tools so the UI always receives a final answer.
            messages.append({'role':'system','content':'Tool budget reached. Produce the final answer now using only the evidence already gathered. Do not call any tools.'})
            final=groq_request(messages,tools=None); fm=extract_message(final)
            if fm.get('content'): return str(fm['content']), 'groq'
        except Exception as exc:
            log('LLM ERROR',str(exc),'warning')
    # Evidence-grounded local fallback
    s=summary_tool(); top=priority_tool(1)
    if top:
        e=top[0]
        return (f"NetworkPulse prioritizes {e['event_id']} ({e['label']}) at risk {float(e['risk']):.1f}/99. "
                f"The ensemble probability is {float(e.get('ensemble_probability',0))*100:.1f}% with "
                f"{float(e.get('confidence',0)):.1f}% confidence. The current evidence cache contains "
                f"{s['flows']:,} flows, of which {s['attack_labelled']:,} are attack-labelled. "
                "Recommended next step: inspect the event dossier and correlate related flows before escalation."), 'local'
    return 'No telemetry is available. Load the bundled CICIDS2017 cache first.', 'local'

def run_once(limit=6):
    with _lock:
        if _state['running']: return state()
        _state['running']=True
    try:
        df=load_events()
        if df.empty: raise RuntimeError('No evidence cache found.')
        log('OBSERVE',f'Observed {len(df):,} real CICIDS2017 flows.')
        priority=df.sort_values('risk',ascending=False).head(limit)
        log('DETECT',f'Ranked {len(priority)} priority flows using ensemble risk.','success')
        top=priority.iloc[0]
        event=event_tool(top.event_id)
        log('INSPECT',f'Inspected {top.event_id}: risk {float(top.risk):.1f}/99; ensemble {float(top.ensemble_probability)*100:.1f}%.','success')
        related=related_tool(top.event_id,8)
        log('CORRELATE',f'Found {len(related)} related flows using label/port/risk proximity.','success')
        packet={'summary':summary_tool(),'priority':priority_tool(limit),'top_event':event,'related':related,'evaluation':eval_tool()}
        log('REASON','Sending bounded evidence packet to the Groq analyst.' if GROQ_API_KEY else 'Using local evidence synthesis.')
        q='''You are completing one autonomous SOC cycle. Using the evidence packet in the user message, produce a concise analyst briefing with: (1) what matters now, (2) why the top flow is risky, explicitly separating ground-truth label vs model evidence, (3) correlated activity, and (4) three analyst-reviewable next steps. Do not invent IPs, timestamps or facts not present.'''
        msgs=[{'role':'system','content':SYSTEM},{'role':'user','content':q+'\n\nEVIDENCE PACKET:\n'+json.dumps(packet,default=str)}]
        if GROQ_API_KEY:
            data=groq_request(msgs,tools=None); msg=extract_message(data); insight=str(msg.get('content') or '')
            provider='groq' if insight else 'local'
        else: insight,provider=ask(q)
        if not insight:
            insight,_=ask('Summarize the current top-risk finding from existing evidence without additional tool calls.',top.event_id)
            provider='groq' if GROQ_API_KEY else 'local'
        log('REASON',f'{provider.upper()} analyst produced the final synthesis.','success')
        recommendation='Review the top event dossier, compare model consensus with anomaly evidence, inspect related flows, then enrich external indicators if justified.'
        log('RECOMMEND',recommendation)
        with _lock:
            _state.update({'last_run':now(),'summary':insight,'priority':priority.to_dict('records'),'provider':provider,'llm_ready':bool(GROQ_API_KEY),'cycle':int(_state.get('cycle',0))+1,'running':False})
            AGENT_LOG.write_text(json.dumps(_state,indent=2,default=str),encoding='utf-8')
    except Exception as exc:
        log('ERROR',str(exc),'error')
        with _lock:_state['running']=False
    return state()

def start_background(interval=180):
    def loop():
        # one initial cycle, then periodic cycles
        time.sleep(2)
        while True:
            if not _state['running']:
                run_once()
            time.sleep(interval)
    threading.Thread(target=loop,daemon=True,name='networkpulse-agent').start()

def state():
    with _lock: return json.loads(json.dumps(_state,default=str))
