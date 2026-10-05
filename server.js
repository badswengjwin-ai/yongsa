'use strict';
// 용사의 대륙 온라인 서버 — 외부 패키지 없이 `node server.js` 만으로 실행됩니다.
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto'),zlib=require('zlib');
const PORT=+process.env.PORT||3000;
const DATA=process.env.DATA_DIR||__dirname;
const MAXC=+process.env.MAX_PLAYERS||300;      // 동시 접속 상한
const PER_IP=+process.env.MAX_PER_IP||8;       // IP당 동시 접속 상한
const GUID='258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const MAXFRAME=64*1024, VIEW_R=1400, VIEW_MAX=40, TICK=125;
const FILE=path.join(DATA,'accounts.json');

// ── 계정 저장소 (JSON 파일) ──────────────────────────────
let ACC={};try{ACC=JSON.parse(fs.readFileSync(FILE,'utf8'))}catch(e){}
let dirty=false;
function flush(sync){if(!dirty)return;dirty=false;const s=JSON.stringify(ACC);try{if(sync){fs.writeFileSync(FILE,s)}else{fs.writeFile(FILE+'.tmp',s,e=>{if(!e)fs.rename(FILE+'.tmp',FILE,()=>{})})}}catch(e){console.error('save fail',e.message)}}
setInterval(()=>flush(false),5000);
for(const sg of['SIGTERM','SIGINT'])process.on(sg,()=>{flush(true);process.exit(0)});

// ── 정적 파일 (게임 HTML) ────────────────────────────────
let HTML=null,HTMLGZ=null;
function loadHtml(){try{HTML=fs.readFileSync(path.join(__dirname,'index.html'));HTMLGZ=zlib.gzipSync(HTML,{level:9})}catch(e){HTML=null}}
loadHtml();
const server=http.createServer((req,res)=>{
  const u=req.url.split('?')[0];
  if(u==='/healthz'){res.writeHead(200,{'Content-Type':'text/plain'});return res.end('ok '+clients.size)}
  if(u==='/'||u==='/index.html'){
    if(!HTML){res.writeHead(500);return res.end('index.html not found')}
    const gz=/\bgzip\b/.test(req.headers['accept-encoding']||'');
    res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-cache',...(gz?{'Content-Encoding':'gzip'}:{})});
    return res.end(gz?HTMLGZ:HTML);
  }
  res.writeHead(404);res.end('not found');
});

// ── WebSocket (RFC 6455 최소 구현) ───────────────────────
const clients=new Set(),rooms=new Map(),ipCount=new Map(),ipFail=new Map(),ipNew=new Map();
let nextId=1;
const ipOf=req=>((req.headers['x-forwarded-for']||'').split(',')[0].trim())||req.socket.remoteAddress||'?';
function frame(str){const p=Buffer.from(str),n=p.length;let h;
  if(n<126)h=Buffer.from([0x81,n]);else if(n<65536){h=Buffer.alloc(4);h[0]=0x81;h[1]=126;h.writeUInt16BE(n,2)}else{h=Buffer.alloc(10);h[0]=0x81;h[1]=127;h.writeUInt32BE(0,2);h.writeUInt32BE(n,6)}
  return Buffer.concat([h,p])}
function send(c,o){if(c.dead||c.sock.destroyed)return;try{c.sock.write(typeof o==='string'?frame(o):frame(JSON.stringify(o)))}catch(e){}}
function kill(c){if(c.dead)return;c.dead=true;clients.delete(c);const r=rooms.get(c.room);if(r){r.delete(c);if(!r.size)rooms.delete(c.room)}
  const n=ipCount.get(c.ip)||1;n<=1?ipCount.delete(c.ip):ipCount.set(c.ip,n-1);try{c.sock.destroy()}catch(e){}}

server.on('upgrade',(req,sock)=>{
  const url=new URL(req.url,'http://x');
  const key=req.headers['sec-websocket-key'];
  if(url.pathname!=='/ws'||!key||(req.headers.upgrade||'').toLowerCase()!=='websocket'){sock.end('HTTP/1.1 400 Bad Request\r\n\r\n');return}
  const ip=ipOf(req);
  if(clients.size>=MAXC||(ipCount.get(ip)||0)>=PER_IP){sock.end('HTTP/1.1 503 Service Unavailable\r\n\r\n');return}
  const accept=crypto.createHash('sha1').update(key+GUID).digest('base64');
  sock.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: '+accept+'\r\n\r\n');
  sock.setNoDelay(true);
  let rn=(url.searchParams.get('room')||'main').toLowerCase().replace(/[^a-z0-9_-]/g,'').slice(0,24)||'main';
  const c={sock,id:'p'+(nextId++).toString(36),ip,room:rn,d:null,buf:Buffer.alloc(0),frag:null,fop:0,fl:0,alive:true,tp:0,tc:0,ts:0,last:''};
  clients.add(c);ipCount.set(ip,(ipCount.get(ip)||0)+1);
  if(!rooms.has(rn))rooms.set(rn,new Set());rooms.get(rn).add(c);
  sock.on('data',b=>onData(c,b));sock.on('close',()=>kill(c));sock.on('error',()=>kill(c));
});
function onData(c,chunk){
  c.buf=Buffer.concat([c.buf,chunk]);if(c.buf.length>MAXFRAME*2)return kill(c);
  for(;;){const b=c.buf;if(b.length<2)return;
    const fin=b[0]&128,op=b[0]&15,masked=b[1]&128;let len=b[1]&127,off=2;
    if(len===126){if(b.length<4)return;len=b.readUInt16BE(2);off=4}
    else if(len===127){if(b.length<10)return;if(b.readUInt32BE(2))return kill(c);len=b.readUInt32BE(6);off=10}
    if(!masked||len>MAXFRAME)return kill(c);
    if(b.length<off+4+len)return;
    const mk=b.subarray(off,off+4),pl=Buffer.from(b.subarray(off+4,off+4+len));
    for(let i=0;i<len;i++)pl[i]^=mk[i&3];
    c.buf=b.subarray(off+4+len);
    if(op===8){try{c.sock.end(Buffer.from([0x88,0]))}catch(e){}return kill(c)}
    if(op===9){try{c.sock.write(Buffer.concat([Buffer.from([0x8A,pl.length]),pl.subarray(0,125)]))}catch(e){}continue}
    if(op===10){c.alive=true;continue}
    if(op===1||op===2){c.frag=[pl];c.fop=op;c.fl=pl.length}
    else if(op===0&&c.frag){c.frag.push(pl);c.fl+=pl.length;if(c.fl>MAXFRAME)return kill(c)}
    else continue;
    if(fin){const m=Buffer.concat(c.frag);c.frag=null;if(c.fop===1)onMsg(c,m.toString('utf8'))}
  }
}

// ── 메시지 처리 ──────────────────────────────────────────
const clean=(s,n)=>String(s==null?'':s).replace(/[\u0000-\u001f\u007f<>]/g,'').trim().slice(0,n);
const int=(v,lo,hi,d)=>{v=Math.round(+v);return Number.isFinite(v)?Math.min(hi,Math.max(lo,v)):d};
const safeEq=(a,b)=>{a=Buffer.from(String(a));b=Buffer.from(String(b));return a.length===b.length&&crypto.timingSafeEqual(a,b)};
function onMsg(c,txt){
  let m;try{m=JSON.parse(txt)}catch(e){return}
  if(!m||typeof m!=='object')return;
  const now=Date.now();
  if(m.t==='p'){
    if(now-c.tp<50)return;c.tp=now;const d=m.d||{};
    const n=clean(d.n,16);if(!n)return;
    c.d={n,x:int(d.x,0,20000,0),y:int(d.y,0,20000,0),sk:int(d.sk,0,40,0),f:d.f<0?-1:1,lv:int(d.lv,1,999,1),j:int(d.j,0,30,0),mv:d.mv?1:0,at:d.at?1:0};
  }else if(m.t==='c'){
    if(now-c.tc<1200)return;c.tc=now;
    const d=m.d||{},t=clean(d.t,40),n=clean(d.n,16);if(!t||!n)return;
    const r=rooms.get(c.room);if(!r)return;
    for(const o of r)send(o,{t:'c',id:c.id,d:{n,t},me:o===c?1:0});
  }else if(m.t==='get'||m.t==='set'){
    const rid=int(m.r,0,1e9,0),k=String(m.k||''),h=String(m.h||'');
    const bad=e=>send(c,{t:'r',r:rid,err:e});
    if(!/^u[0-9a-f]{2,200}$/.test(k)||!/^[0-9a-f]{64}$/.test(h))return bad('bad');
    const a=ACC[k];
    if(m.t==='get'){
      const f=ipFail.get(c.ip)||{n:0,t:now};if(now-f.t>6e5){f.n=0;f.t=now}
      if(f.n>=15)return bad('rate');
      if(!a)return send(c,{t:'r',r:rid,ex:false});
      if(!safeEq(a.h,h)){f.n++;ipFail.set(c.ip,f);return send(c,{t:'r',r:rid,ex:true,ok:false})}
      return send(c,{t:'r',r:rid,ex:true,ok:true,p:a.p,ts:a.t||0});
    }
    if(now-c.ts<1500)return bad('rate');c.ts=now;
    const p=typeof m.p==='string'?m.p:'';if(!p||p.length>200000)return bad('bad');
    try{JSON.parse(p)}catch(e){return bad('bad')}
    if(a&&!safeEq(a.h,h))return bad('auth');
    if(!a){const q=ipNew.get(c.ip)||{n:0,t:now};if(now-q.t>36e5){q.n=0;q.t=now}if(q.n>=10||Object.keys(ACC).length>=50000)return bad('rate');q.n++;ipNew.set(c.ip,q)}
    ACC[k]={h,p,t:int(m.ts,0,9e15,now)};dirty=true;
    return send(c,{t:'r',r:rid,ok:true});
  }
}

// ── 주변 플레이어 스냅샷 방송 ────────────────────────────
setInterval(()=>{
  for(const [,set] of rooms){
    const live=[];for(const c of set)if(c.d)live.push(c);
    for(const c of set){
      if(!c.d)continue;
      let l=[];
      for(const o of live){if(o===c)continue;const dx=o.d.x-c.d.x,dy=o.d.y-c.d.y,dd=dx*dx+dy*dy;if(dd<=VIEW_R*VIEW_R)l.push([dd,o])}
      if(l.length>VIEW_MAX){l.sort((a,b)=>a[0]-b[0]);l=l.slice(0,VIEW_MAX)}
      const s=JSON.stringify({t:'s',n:set.size,l:l.map(([,o])=>[o.id,o.d])});
      if(s!==c.last||c.lastT<Date.now()-2000){c.last=s;c.lastT=Date.now();send(c,s)}
    }
  }
},TICK);
// ── 연결 상태 확인 ───────────────────────────────────────
setInterval(()=>{for(const c of [...clients]){if(!c.alive){kill(c);continue}c.alive=false;try{c.sock.write(Buffer.from([0x89,0]))}catch(e){}}},30000);
setInterval(()=>{const n=Date.now();for(const [k,v] of ipFail)if(n-v.t>6e5)ipFail.delete(k);for(const [k,v] of ipNew)if(n-v.t>36e5)ipNew.delete(k)},60000);

server.listen(PORT,()=>console.log('용사의 대륙 서버 실행 중 — http://localhost:'+PORT));
