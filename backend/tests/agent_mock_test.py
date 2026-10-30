import os, sys
os.environ['DISABLE_AGENT_AUTORUN']='1'
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from app import agent

original=agent.groq_request
calls={'n':0}

def fake_request(messages, tools=None):
    calls['n']+=1
    if tools:
        return {'choices':[{'message':{'role':'assistant','content':'','tool_calls':[{'id':'t1','type':'function','function':{'name':'get_priority_events','arguments':'{"limit":1}'}}]}}]}
    return {'choices':[{'message':{'role':'assistant','content':'Mock Groq final synthesis: highest risk evidence reviewed.'}}]}

agent.groq_request=fake_request
try:
    answer, provider=agent.ask('Investigate the highest-risk flow.')
    assert provider=='groq'
    assert 'Mock Groq final synthesis' in answer
    assert calls['n']>=2
    print('AGENT MOCK TOOL-CALL TEST: PASS')
finally:
    agent.groq_request=original
