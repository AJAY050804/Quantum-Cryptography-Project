# server_ui.py
# pip install flask flask-socketio cryptography
# python server_ui.py
# Open http://localhost:8000  then click START

import socket, os, json, random, time, statistics, struct, threading
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, render_template_string
from flask_socketio import SocketIO

app = Flask(__name__)
app.config['SECRET_KEY'] = 'qs'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

CRYPTO_PORT = 5000
BB84_LEN    = 256
ROUNDS      = 20
state       = {"started": False, "conn": None, "aes": None, "done": False, "tb": 0, "tp": 0, "times": []}

def _send(sk, data):
    state["tb"] += 4 + len(data); state["tp"] += 1
    sk.sendall(struct.pack('!I', len(data)) + data)

def _recv(sk):
    def ra(n):
        d=b''
        while len(d)<n:
            c=sk.recv(n-len(d))
            if not c: return None
            d+=c
        return d
    r=ra(4)
    if not r: return None
    n=struct.unpack('!I',r)[0]
    d=ra(n)
    state["tb"]+=4+n; state["tp"]+=1
    return d

def lg(msg,kind="info"):
    socketio.emit('log',{'msg':msg,'kind':kind})

def run_server():
    sk=ed25519.Ed25519PrivateKey.generate()
    sk_pub=sk.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    srv=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    srv.bind(('0.0.0.0',CRYPTO_PORT))
    srv.listen(1)
    lg(f"Listening on port {CRYPTO_PORT}…","info")
    conn,addr=srv.accept()
    state["conn"]=conn
    lg(f"Alice connected from {addr[0]}","success")
    socketio.emit('peer_connected')

    bb84_key=shared=final=None
    for i in range(ROUNDS):
        t0=time.time()
        lg(f"Round {i+1}/{ROUNDS}  BB84 exchange…","info")
        d=json.loads(_recv(conn))
        ab,aB=d["bits"],d["bases"]
        bB=[random.randint(0,1) for _ in range(BB84_LEN)]
        br=[ab[j] if bB[j]==aB[j] else random.randint(0,1) for j in range(BB84_LEN)]
        _send(conn,json.dumps({"bob_bases":bB}).encode())
        idx=json.loads(_recv(conn))["indices"]
        sifted=[br[j] for j in idx]
        bb84_key=bytes(int(''.join(map(str,sifted[j:j+8])),2) for j in range(0,len(sifted),8))
        lg(f"  BB84 → {len(idx)} matching bits → {len(bb84_key)} byte key","detail")

        xp=x25519.X25519PrivateKey.generate()
        xb=xp.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        sig=sk.sign(xb)
        _send(conn,json.dumps({"sign_pub":sk_pub.hex(),"x_pub":xb.hex(),"signature":sig.hex()}).encode())
        cpub=bytes.fromhex(json.loads(_recv(conn))["x_pub"])
        shared=xp.exchange(x25519.X25519PublicKey.from_public_bytes(cpub))
        final=HKDF(hashes.SHA256(),32,None,b"hybrid").derive(shared+bb84_key)

        e=time.time()-t0; state["times"].append(e)
        socketio.emit('round',{'n':i+1,'total':ROUNDS,'ms':round(e*1000,1)})
        lg(f"  Round {i+1} done — {e*1000:.1f} ms","success")

    t=state["times"]
    socketio.emit('handshake_done',{
        'bb84':bb84_key.hex(),'x25519':shared.hex(),'hkdf':final.hex(),
        'avg':f"{statistics.mean(t)*1000:.1f}ms",'std':f"{statistics.stdev(t)*1000:.1f}ms",
        'mn':f"{min(t)*1000:.1f}ms",'mx':f"{max(t)*1000:.1f}ms",
        'bytes':state["tb"],'packets':state["tp"]
    })
    lg("Secure channel LIVE — AES-256-GCM ready","success")
    state["aes"]=AESGCM(final); state["done"]=True

    while True:
        try:
            data=_recv(conn)
            if not data: break
            pt=state["aes"].decrypt(data[:12],data[12:],None)
            socketio.emit('msg',{'who':'Alice','text':pt.decode(),'me':False})
        except Exception as ex:
            lg(f"Recv error: {ex}","error"); break

@socketio.on('start')
def on_start():
    if state["started"]: return
    state["started"]=True
    threading.Thread(target=run_server,daemon=True).start()

@socketio.on('chat')
def on_chat(data):
    if not state["done"]: return
    txt=data['text']
    nonce=os.urandom(12)
    ct=state["aes"].encrypt(nonce,txt.encode(),None)
    _send(state["conn"],nonce+ct)
    socketio.emit('msg',{'who':'Bob (you)','text':txt,'me':True})

HTML=r"""<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<title>QuantumLink – Server</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@600;700&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.5/socket.io.min.js"></script>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#06100a;--sur:#0b1810;--bdr:#163d22;
  --g:#1aff6e;--gd:#0aaa44;--gdk:#041508;
  --amb:#ffc040;--red:#ff3a4a;--cy:#00e5ff;
  --tx:#b8f5cb;--mu:#3a6b4a;
  --fn:'Share Tech Mono',monospace;--fh:'Rajdhani',sans-serif;
}
body{background:var(--bg);color:var(--tx);font-family:var(--fn);height:100vh;display:flex;flex-direction:column;overflow:hidden}

/* scanlines */
body::after{content:'';position:fixed;inset:0;pointer-events:none;
  background:repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(26,255,110,.008) 3px,rgba(26,255,110,.008) 4px);z-index:999}

#bar{display:flex;align-items:center;gap:12px;background:var(--sur);border-bottom:1px solid var(--bdr);padding:10px 20px;flex-shrink:0}
.brand{font-family:var(--fh);font-size:19px;font-weight:700;color:var(--g);letter-spacing:4px;text-shadow:0 0 18px var(--g)}
.role{font-family:var(--fh);font-size:10px;letter-spacing:3px;color:var(--amb);border:1px solid var(--amb);padding:2px 9px}
#dot{width:9px;height:9px;border-radius:50%;background:var(--red);box-shadow:0 0 8px var(--red);margin-left:auto;transition:.3s}
#dot.on{background:var(--g);box-shadow:0 0 14px var(--g);animation:bk 2s infinite}
@keyframes bk{0%,100%{opacity:1}50%{opacity:.4}}
#slbl{font-size:11px;color:var(--mu);letter-spacing:2px}

#pw{height:3px;background:var(--sur);flex-shrink:0}
#pr{height:100%;width:0;background:var(--g);box-shadow:0 0 8px var(--g);transition:width .3s}

#body{display:flex;flex:1;overflow:hidden}

#side{width:270px;flex-shrink:0;background:var(--sur);border-right:1px solid var(--bdr);padding:14px;overflow-y:auto;display:flex;flex-direction:column;gap:16px}
.st{font-family:var(--fh);font-size:9px;letter-spacing:3px;color:var(--mu);border-bottom:1px solid var(--bdr);padding-bottom:5px;margin-bottom:5px}
.kv .lb{font-size:9px;color:var(--mu);letter-spacing:1px;margin-bottom:3px}
.kv .vl{font-size:9px;color:var(--g);background:var(--gdk);border-left:2px solid var(--gd);padding:5px 7px;word-break:break-all;line-height:1.6;min-height:26px}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:7px}
.tile{background:var(--gdk);border:1px solid var(--bdr);padding:8px;text-align:center}
.tile .v{font-family:var(--fh);font-size:14px;color:var(--amb)}
.tile .l{font-size:9px;color:var(--mu);letter-spacing:1px;margin-top:2px}
#sbtn{font-family:var(--fh);font-size:13px;letter-spacing:3px;background:var(--gdk);border:1px solid var(--gd);color:var(--g);padding:10px;cursor:pointer;width:100%;transition:.2s}
#sbtn:hover{background:var(--gd);color:var(--bg)}
#sbtn:disabled{opacity:.35;cursor:not-allowed}

#main{flex:1;display:flex;flex-direction:column;overflow:hidden}
.tabs{display:flex;border-bottom:1px solid var(--bdr);flex-shrink:0}
.tab{padding:8px 18px;font-family:var(--fh);font-size:11px;letter-spacing:2px;color:var(--mu);cursor:pointer;border-bottom:2px solid transparent}
.tab.on{color:var(--g);border-bottom-color:var(--g)}

#lp{flex:1;overflow-y:auto;padding:12px 14px;display:flex;flex-direction:column;gap:2px}
.le{font-size:12px;line-height:1.6}
.le .ts{color:var(--bdr);margin-right:7px}
.le.info .bd{color:var(--mu)}
.le.success .bd{color:var(--g)}
.le.detail .bd{color:#3a88bb;padding-left:16px}
.le.error .bd{color:var(--red)}

#cp{flex:1;overflow-y:auto;padding:12px 14px;display:none;flex-direction:column;gap:5px}
#cp.on{display:flex}
.bub{max-width:72%;padding:8px 12px;font-size:13px;line-height:1.5}
.bub.them{background:#0b1e0e;border:1px solid #1a3d1a;border-radius:0 8px 8px 8px;align-self:flex-start}
.bub.me{background:#0a1f1a;border:1px solid #1a3d33;border-radius:8px 0 8px 8px;align-self:flex-end}
.bub .who{font-size:9px;letter-spacing:2px;margin-bottom:3px}
.bub.them .who{color:var(--cy)}
.bub.me .who{color:var(--amb)}
#lock{margin:auto;color:var(--mu);font-size:12px;text-align:center}

#inp{display:flex;align-items:center;gap:9px;background:var(--sur);border-top:1px solid var(--bdr);padding:9px 14px;flex-shrink:0}
.pfx{color:var(--g);font-size:14px}
#mi{flex:1;background:transparent;border:none;outline:none;color:var(--tx);font-family:var(--fn);font-size:14px;caret-color:var(--g)}
#mi::placeholder{color:var(--mu)}
#sb{font-family:var(--fh);font-size:11px;letter-spacing:2px;background:var(--gdk);border:1px solid var(--gd);color:var(--g);padding:7px 14px;cursor:pointer;transition:.2s}
#sb:hover{background:var(--gd);color:var(--bg)}
#sb:disabled{opacity:.3;cursor:not-allowed}
</style>
</head><body>

<div id="bar">
  <div class="brand">QUANTUMLINK</div>
  <div class="role">SERVER · BOB</div>
  <span id="slbl">IDLE</span>
  <div id="dot"></div>
</div>
<div id="pw"><div id="pr"></div></div>

<div id="body">
  <div id="side">
    <button id="sbtn" onclick="doStart()">▶ START SERVER</button>
    <div>
      <div class="st">CRYPTO KEYS</div>
      <div class="kv" style="margin-bottom:9px"><div class="lb">BB84 QUANTUM KEY</div><div class="vl" id="k1">—</div></div>
      <div class="kv" style="margin-bottom:9px"><div class="lb">X25519 SHARED SECRET</div><div class="vl" id="k2">—</div></div>
      <div class="kv"><div class="lb">HKDF FINAL KEY</div><div class="vl" id="k3">—</div></div>
    </div>
    <div>
      <div class="st">PERFORMANCE</div>
      <div class="g2">
        <div class="tile"><div class="v" id="p1">—</div><div class="l">AVG</div></div>
        <div class="tile"><div class="v" id="p2">—</div><div class="l">STD</div></div>
        <div class="tile"><div class="v" id="p3">—</div><div class="l">MIN</div></div>
        <div class="tile"><div class="v" id="p4">—</div><div class="l">MAX</div></div>
      </div>
      <div class="kv" style="margin-top:8px"><div class="lb">BYTES / PACKETS</div><div class="vl" id="p5">—</div></div>
    </div>
  </div>

  <div id="main">
    <div class="tabs">
      <div class="tab on" id="tl" onclick="sw('log')">LOG</div>
      <div class="tab"    id="tc" onclick="sw('chat')">CHAT</div>
    </div>
    <div id="lp"></div>
    <div id="cp"><div id="lock">🔒 Waiting for handshake…</div></div>
  </div>
</div>

<div id="inp">
  <span class="pfx">BOB ›</span>
  <input id="mi" type="text" placeholder="Type a message…" disabled>
  <button id="sb" disabled onclick="sendChat()">SEND</button>
</div>

<script>
const S=io();
const TOTAL=""" + str(ROUNDS) + """;

function ts(){return new Date().toTimeString().slice(0,8)}
function addLog(msg,kind){
  const p=document.getElementById('lp');
  const d=document.createElement('div');
  d.className='le '+kind;
  d.innerHTML='<span class="ts">['+ts()+']</span><span class="bd">'+msg+'</span>';
  p.appendChild(d); p.scrollTop=p.scrollHeight;
}

S.on('log',d=>addLog(d.msg,d.kind));
S.on('peer_connected',()=>{
  document.getElementById('dot').classList.add('on');
  document.getElementById('slbl').textContent='CONNECTED';
});
S.on('round',d=>{
  document.getElementById('pr').style.width=(d.n/d.total*100)+'%';
});
S.on('handshake_done',d=>{
  document.getElementById('k1').textContent=d.bb84;
  document.getElementById('k2').textContent=d.x25519;
  document.getElementById('k3').textContent=d.hkdf;
  document.getElementById('p1').textContent=d.avg;
  document.getElementById('p2').textContent=d.std;
  document.getElementById('p3').textContent=d.mn;
  document.getElementById('p4').textContent=d.mx;
  document.getElementById('p5').textContent=d.bytes+' B / '+d.packets+' pkts';
  document.getElementById('pr').style.width='100%';
  document.getElementById('slbl').textContent='SECURE';
  document.getElementById('lock').style.display='none';
  document.getElementById('mi').disabled=false;
  document.getElementById('sb').disabled=false;
});
S.on('msg',d=>{
  const p=document.getElementById('cp');
  const b=document.createElement('div');
  b.className='bub '+(d.me?'me':'them');
  b.innerHTML='<div class="who">'+d.who+'</div>'+d.text;
  p.appendChild(b); p.scrollTop=p.scrollHeight;
});

function doStart(){
  document.getElementById('sbtn').disabled=true;
  document.getElementById('sbtn').textContent='⏳ WAITING FOR ALICE…';
  document.getElementById('slbl').textContent='LISTENING';
  S.emit('start');
}
function sw(t){
  document.getElementById('lp').style.display=t==='log'?'flex':'none';
  document.getElementById('cp').classList.toggle('on',t==='chat');
  document.getElementById('tl').classList.toggle('on',t==='log');
  document.getElementById('tc').classList.toggle('on',t==='chat');
}
function sendChat(){
  const el=document.getElementById('mi');
  const txt=el.value.trim(); if(!txt) return;
  S.emit('chat',{text:txt}); el.value='';
}
document.getElementById('mi').addEventListener('keydown',e=>{if(e.key==='Enter')sendChat()});
</script>
</body></html>"""

@app.route('/')
def index(): return render_template_string(HTML)

if __name__=='__main__':
    print("Open http://localhost:8000  →  click START  →  then run client_ui.py on the other laptop")
    socketio.run(app, host='0.0.0.0', port=8000, debug=False)