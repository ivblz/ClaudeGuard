#!/usr/bin/env python3
"""Opt-in integration of the installed Claude CLI and guard against a local API.

Requires the separate test upstream on localhost:18080 and a running ClaudeGuard.
Temporarily changes connection mode, whitelist and protection, restoring them in
finally. Do not edit settings during the run. Does not use account credentials.
Logs only synthetic request results; uses --bare with a local dummy API key.
"""
import json,os,time,subprocess,hashlib,threading,signal,sys,tempfile
from pathlib import Path
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
if '--run' not in sys.argv:
 raise SystemExit('Opt-in live test: python3 tests/live_cli_proxy_check.py --run (requires local HTTP/SOCKS proxy on port 18080)')
ROOT=Path(tempfile.mkdtemp(prefix='claudeguard-cli-check-'));CFG=Path.home()/'.config/claudeguard/config.json';STATE=CFG.parent/'state.json'
original=json.loads(CFG.read_text());keys=['connection_mode','protection_enabled','proxy_enabled','proxy_profile','allowed_ips']
class API(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_POST(self):
  body=json.loads(self.rfile.read(int(self.headers.get('Content-Length',0))))
  self.server.requests+=1
  if self.path.endswith('count_tokens'):
   data=json.dumps({'input_tokens':1}).encode();typ='application/json'
  else:
   msg={'id':'msg_cg_test','type':'message','role':'assistant','model':body.get('model','test'),'content':[{'type':'text','text':'CG_PROXY_OK'}],'stop_reason':'end_turn','stop_sequence':None,'usage':{'input_tokens':1,'output_tokens':3}}
   if body.get('stream'):
    initial=dict(msg,content=[],stop_reason=None,usage={'input_tokens':1,'output_tokens':0})
    events=[('message_start',{'type':'message_start','message':initial}),('content_block_start',{'type':'content_block_start','index':0,'content_block':{'type':'text','text':''}}),('content_block_delta',{'type':'content_block_delta','index':0,'delta':{'type':'text_delta','text':'CG_PROXY_OK'}}),('content_block_stop',{'type':'content_block_stop','index':0}),('message_delta',{'type':'message_delta','delta':{'stop_reason':'end_turn','stop_sequence':None},'usage':{'output_tokens':3}}),('message_stop',{'type':'message_stop'})]
    data=''.join('event: '+event+'\ndata: '+json.dumps(payload)+'\n\n' for event,payload in events).encode();typ='text/event-stream'
   else:data=json.dumps(msg).encode();typ='application/json'
  self.send_response(200);self.send_header('Content-Type',typ);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
def save(changes):
 d=json.loads(CFG.read_text());d.update(changes);tmp=CFG.with_suffix('.matrix.tmp');tmp.write_text(json.dumps(d,indent=2));tmp.chmod(0o600);tmp.replace(CFG)
def wait_state(want,timeout=85):
 until=time.monotonic()+timeout;consecutive=0
 while time.monotonic()<until:
  try:
   s=json.loads(STATE.read_text());c=json.loads(CFG.read_text())
   match=s.get('mode')==c['connection_mode'] and s.get('protection_enabled')==c['protection_enabled'] and time.time()-s.get('updated_at',0)<10 and s.get('state')==want and not s.get('enforcement_error')
   if c['connection_mode']=='proxy' and c['protection_enabled']:match=match and s.get('proxy_profile_id')==hashlib.sha256(json.dumps(c['proxy_profile'],sort_keys=True).encode()).hexdigest()
   consecutive=consecutive+1 if match else 0
   if consecutive>=3:return True
  except (OSError,ValueError):pass
  time.sleep(.5)
 print('STATE TIMEOUT expected',want,'last',s.get('state'),s.get('enforcement_error'),flush=True);return False
def proxy_count():
 return Path('/tmp/claudeguard-local-proxy/proxy.log').read_text().count('inbound connection to 127.0.0.1:18082')
def cli(name):
 env=dict(os.environ,ANTHROPIC_API_KEY='cg-local-test-key',ANTHROPIC_BASE_URL='http://127.0.0.1:18082')
 env.pop('ANTHROPIC_AUTH_TOKEN',None)
 before=proxy_count();requests=server.requests;start=time.monotonic()
 cmd=[str(Path.home()/'.local/bin/claude'),'-p','--bare','--tools','','--no-session-persistence','--max-turns','1','--output-format','json','Reply with exactly CG_PROXY_OK.']
 p=subprocess.Popen(cmd,cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
 try:out,err=p.communicate(timeout=50)
 except subprocess.TimeoutExpired:
  os.killpg(p.pid,signal.SIGTERM);out,err=p.communicate(timeout=5)
 (ROOT/(name+'.out')).write_text(out);(ROOT/(name+'.err')).write_text(err)
 row={'case':name,'exit':p.returncode,'seconds':round(time.monotonic()-start,1),'success':'CG_PROXY_OK' in out,'api_requests':server.requests-requests,'upstream_connections':proxy_count()-before,'stderr':err[-500:]}
 print(json.dumps(row),flush=True)
 with (ROOT/'local-matrix.jsonl').open('a') as f:f.write(json.dumps(row)+'\n')
 return row
server=ThreadingHTTPServer(('127.0.0.1',18082),API);server.requests=0
threading.Thread(target=server.serve_forever,daemon=True).start()
failures=[]
try:
 cases=[('http-local','allowed',{'connection_mode':'proxy','protection_enabled':True,'proxy_enabled':True,'proxy_profile':{'type':'http','server':'127.0.0.1','server_port':18080}}),('socks5-local','allowed',{'proxy_profile':{'type':'socks','version':'5','server':'127.0.0.1','server_port':18080}}),('disabled-local','disabled',{'protection_enabled':False}),('vpn-denied-local','blocked',{'connection_mode':'vpn','protection_enabled':True,'allowed_ips':[]}),('proxy-denied-local','blocked',{'connection_mode':'proxy','proxy_profile':{'type':'http','server':'127.0.0.1','server_port':18081}})]
 sys.path.insert(0,str(Path.home()/'.local/share/ClaudeGuard'))
 from src.ip_checker import fetch_public_ip
 current_ip,_ = fetch_public_ip(timeout=3)
 if current_ip:
  cases.insert(3,('vpn-allowed-local','allowed',{'protection_enabled':True,'connection_mode':'vpn','allowed_ips':[current_ip]}))
 cases.insert(2,('http-after-socks-local','allowed',{'proxy_profile':{'type':'http','server':'127.0.0.1','server_port':18080}}))
 for name,want,changes in cases:
  print('START',name,flush=True);save(changes)
  if not wait_state(want):
   failures.append(name);continue
  result=cli(name)
  allowed=want in ('allowed','disabled')
  if allowed:
   if result['exit']!=0 or not result['success'] or not result['api_requests']:failures.append(name)
   elif 'http' in name or 'socks' in name:
    if not result['upstream_connections']:failures.append(name)
  elif result['exit']==0 or result['api_requests']:
   failures.append(name)
finally:
 save({k:original[k] for k in keys if k in original});server.shutdown();server.server_close();print('Original settings restored',flush=True)

print('Report directory:',ROOT)
if failures:raise SystemExit('Failed cases: '+', '.join(failures))
