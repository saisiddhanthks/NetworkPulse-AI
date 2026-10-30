import os, sys
os.environ['DISABLE_AGENT_AUTORUN']='1'
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from fastapi.testclient import TestClient
from app.main import app

with TestClient(app) as c:
    checks=['/api/ping','/api/health','/api/dashboard','/api/events?limit=3','/api/evaluation','/api/agent','/api/models/xgboost/importance']
    for path in checks:
        r=c.get(path); assert r.status_code==200,(path,r.text[:400])
    ev=c.get('/api/events?limit=1').json()['events'][0]['event_id']
    assert c.get('/api/events/'+ev).status_code==200
    print('NETWORKPULSE SMOKE TEST: PASS')
    print('Top event:',ev)
