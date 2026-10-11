import http from 'http';
import { randomUUID, createHash, randomInt, timingSafeEqual } from 'crypto';
import express from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import { WebSocketServer } from 'ws';
import { MongoClient } from 'mongodb';

const { JWT_SECRET, ALLOWED_ORIGIN, MONGODB_URI, BREVO_API_KEY, MAIL_FROM } = process.env;
const MAIL_FROM_NAME = process.env.MAIL_FROM_NAME || 'SORO';

// ---- TEST MODE: free logins with a fixed code, no email sent. Turn OFF before real use. ----
const TEST_MODE = process.env.TEST_MODE === 'true';
const TEST_CODE = process.env.TEST_CODE || '';
const TEST_EMAILS = (process.env.TEST_EMAILS || process.env.TEST_NUMBERS || '').split(',').map(x => x.trim().toLowerCase()).filter(Boolean);
if (TEST_MODE && (!/^\d{6}$/.test(TEST_CODE) || !TEST_EMAILS.length)) { console.error('TEST_MODE needs a 6-digit TEST_CODE and TEST_EMAILS (comma-separated emails)'); process.exit(1); }
if (TEST_MODE) console.warn('TEST MODE ON: no emails are sent. Turn it off before real use.');
if (!TEST_MODE && (!BREVO_API_KEY || !MAIL_FROM)) { console.error('Set BREVO_API_KEY and MAIL_FROM (a sender verified in Brevo), or use TEST_MODE'); process.exit(1); }

// A user's identity is their email address (lowercase). Internally it is still called "phone" in messages.
const norm = e => String(e || '').trim().toLowerCase();
const idOk = p => typeof p === 'string' && p.length <= 254 && /^[a-z0-9._%+\-]+@[a-z0-9\-]+(\.[a-z0-9\-]+)+$/.test(p);

// ---- MongoDB (persistent storage) ----
const db = (await new MongoClient(MONGODB_URI).connect()).db('soro');
const Users = db.collection('users'), Queue = db.collection('queue'), Groups = db.collection('groups'), Otps = db.collection('otps');
await Queue.createIndex({ to: 1, createdAt: 1 });
await Queue.createIndex({ createdAt: 1 }, { expireAfterSeconds: 30 * 86400 }); // undelivered messages kept 30 days
await Groups.createIndex({ members: 1 });
await Otps.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// ---- Email codes (Brevo) ----
const hashCode = (email, code) => createHash('sha256').update(`${email}:${code}:${JWT_SECRET}`).digest('hex');
async function sendMail(to, code) {
  const r = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: { 'api-key': BREVO_API_KEY, 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({
      sender: { name: MAIL_FROM_NAME, email: MAIL_FROM }, to: [{ email: to }],
      subject: 'Your SORO sign-in code',
      htmlContent: `<div style="font-family:sans-serif"><p>Your SORO sign-in code is:</p><p style="font-size:28px;font-weight:700;letter-spacing:4px">${code}</p><p>It expires in 10 minutes. If you did not ask for it, ignore this email.</p></div>`
    })
  });
  if (!r.ok) throw new Error('Brevo ' + r.status + ' ' + (await r.text()).slice(0, 200));
}

// ---- HTTP: email login ----
const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(cors({ origin: ALLOWED_ORIGIN }));
const limiter = rateLimit({ windowMs: 10 * 60 * 1000, limit: TEST_MODE ? 10 : 8 });

app.post('/send-otp', limiter, async (req, res) => {
  const email = norm(req.body?.phone);
  if (!idOk(email)) return res.status(400).json({ ok: false, error: 'Enter a valid email address' });
  if (TEST_MODE) return res.json(TEST_EMAILS.includes(email) ? { ok: true } : { ok: false, error: 'This email is not on the test list' });
  try {
    const now = Date.now(), o = await Otps.findOne({ _id: email });
    if (o && now - o.lastSent < 30000) return res.status(429).json({ ok: false, error: 'Please wait 30 seconds before asking for another code' });
    const inWindow = o && now - o.windowStart < 3600000;
    if (inWindow && o.count >= 5) return res.status(429).json({ ok: false, error: 'Too many codes requested. Try again in an hour.' });
    const code = String(randomInt(100000, 1000000));
    await sendMail(email, code);
    await Otps.updateOne({ _id: email }, { $set: { hash: hashCode(email, code), tries: 0, lastSent: now, codeExpires: now + 10 * 60000,
      expiresAt: new Date(now + 3600000), windowStart: inWindow ? o.windowStart : now, count: inWindow ? o.count + 1 : 1 } }, { upsert: true });
    res.json({ ok: true });
  } catch (e) { console.error(e.message); res.status(500).json({ ok: false, error: 'Could not send the email' }); }
});

app.post('/verify-otp', limiter, async (req, res) => {
  const email = norm(req.body?.phone), code = String(req.body?.code || '').trim();
  if (!idOk(email) || !/^\d{6}$/.test(code)) return res.status(400).json({ ok: false, error: 'Invalid request' });
  try {
    let good = false;
    if (TEST_MODE) good = TEST_EMAILS.includes(email) && code === TEST_CODE;
    else {
      const o = await Otps.findOne({ _id: email });
      if (o && o.hash && o.codeExpires > Date.now() && o.tries < 5) {
        await Otps.updateOne({ _id: email }, { $inc: { tries: 1 } });
        const a = Buffer.from(o.hash), b = Buffer.from(hashCode(email, code));
        good = a.length === b.length && timingSafeEqual(a, b);
        if (good) await Otps.updateOne({ _id: email }, { $set: { hash: null } }); // one use only
      }
    }
    if (!good) return res.status(401).json({ ok: false, error: 'Wrong or expired code' });
    await Users.updateOne({ _id: email }, { $setOnInsert: { createdAt: new Date() } }, { upsert: true });
    res.json({ ok: true, token: jwt.sign({ phone: email }, JWT_SECRET, { expiresIn: '30d' }) });
  } catch (e) { console.error(e.message); res.status(500).json({ ok: false, error: 'Server error' }); }
});
app.get('/', (_, res) => res.send('SORO API running'));

// ---- WebSocket: messaging, groups, call signaling ----
const server = http.createServer(app);
const wss = new WebSocketServer({ server, maxPayload: 3e6 });
const socks = new Map(), seen = new Map();
const send = (ws, o) => ws.readyState === 1 && ws.send(JSON.stringify(o));
const online = p => (socks.get(p)?.size || 0) > 0;
const toPhone = (p, o) => { if (!online(p)) return false; socks.get(p).forEach(w => send(w, o)); return true; };
const presence = p => { const o = { t: 'presence', phone: p, on: online(p), seen: seen.get(p) || null };
  wss.clients.forEach(w => w.watch?.has(p) && send(w, o)); };
const gOut = g => ({ id: g._id, name: g.name, members: g.members, owner: g.owner });
const encOk = o => typeof o?.iv === 'string' && o.iv.length < 40 && typeof o?.ct === 'string' && o.ct.length < 2.8e6;
async function deliver(p, out) { // live if online, otherwise queued in MongoDB
  if (toPhone(p, out)) return true;
  if (await Queue.countDocuments({ to: p }) < 500) await Queue.insertOne({ ...out, to: p, createdAt: new Date() });
  return false;
}

const gcalls = new Map(); // group call state: gid -> { video, parts:Set }
function gLeave(phone, gid) {
  const c = gcalls.get(gid); if (!c || !c.parts.delete(phone)) return;
  c.parts.forEach(p => toPhone(p, { t: 'gcall', k: 'left', gid, phone }));
  if (!c.parts.size) { gcalls.delete(gid); Groups.findOne({ _id: gid }).then(g => g && g.members.forEach(p => toPhone(p, { t: 'gcall', k: 'ended', gid }))).catch(() => {}); }
}

wss.on('connection', (ws, req) => {
  let phone;
  try { phone = jwt.verify(new URL(req.url, 'http://x').searchParams.get('token'), JWT_SECRET).phone; }
  catch { return ws.close(4001); }
  if (!idOk(phone)) return ws.close(4001); // old phone-number sessions must sign in again
  ws.watch = new Set();
  if (!socks.has(phone)) socks.set(phone, new Set());
  socks.get(phone).add(ws);

  let chain = (async () => {
    const now = Date.now(); seen.set(phone, now);
    const me = await Users.findOneAndUpdate({ _id: phone }, { $set: { lastSeen: now } }, { upsert: true, returnDocument: 'after' });
    ws.name = me?.name; presence(phone);
    send(ws, { t: 'groups', list: (await Groups.find({ members: phone }).toArray()).map(gOut) });
    const q = await Queue.find({ to: phone }).sort({ createdAt: 1 }).toArray();
    if (q.length) {
      await Queue.deleteMany({ _id: { $in: q.map(d => d._id) } });
      for (const d of q) { const { _id, to, createdAt, ...msg } = d; send(ws, msg); toPhone(msg.from, { t: 'st', id: msg.id, by: phone, st: 'delivered', gid: msg.gid }); }
    }
  })().catch(console.error);

  async function handle(raw) {
    let m; try { m = JSON.parse(raw); } catch { return; }
    if (m.t === 'key') {
      const k = m.pub; if (k?.kty === 'EC' && k.crv === 'P-256' && typeof k.x === 'string' && typeof k.y === 'string' && k.x.length < 100 && k.y.length < 100)
        await Users.updateOne({ _id: phone }, { $set: { pub: { kty: 'EC', crv: 'P-256', x: k.x, y: k.y } } });
    } else if (m.t === 'profile') {
      ws.name = String(m.name || '').slice(0, 30);
      await Users.updateOne({ _id: phone }, { $set: { name: ws.name, about: String(m.about || '').slice(0, 80) } });
    } else if (m.t === 'lookup' && idOk(m.phone)) {
      const u = await Users.findOne({ _id: m.phone });
      send(ws, { t: 'lookup', phone: m.phone, found: !!u, name: u?.name, pub: u?.pub });
    } else if (m.t === 'watch' && Array.isArray(m.phones)) {
      const ps = m.phones.filter(idOk).slice(0, 500); ps.forEach(p => ws.watch.add(p));
      const ls = Object.fromEntries((await Users.find({ _id: { $in: ps } }, { projection: { lastSeen: 1 } }).toArray()).map(d => [d._id, d.lastSeen]));
      ps.forEach(p => send(ws, { t: 'presence', phone: p, on: online(p), seen: seen.get(p) || ls[p] || null }));
    } else if (m.t === 'typing' && idOk(m.to)) toPhone(m.to, { t: 'typing', from: phone });
    else if (m.t === 'read' && idOk(m.to) && Array.isArray(m.ids)) m.ids.slice(0, 200).forEach(id => toPhone(m.to, { t: 'st', id, by: phone, st: 'read', gid: typeof m.gid === 'string' ? m.gid.slice(0, 20) : undefined }));
    else if (m.t === 'msg' && idOk(m.to) && encOk(m) && await Users.countDocuments({ _id: m.to })) {
      const out = { t: 'msg', id: String(m.id).slice(0, 40), from: phone, name: ws.name, iv: m.iv, ct: m.ct, ts: Date.now() };
      if (await deliver(m.to, out)) send(ws, { t: 'st', id: out.id, by: m.to, st: 'delivered' });
    } else if (m.t === 'gnew') {
      const name = String(m.name || '').trim().slice(0, 40);
      let mem = [...new Set([phone, ...(Array.isArray(m.members) ? m.members.filter(idOk) : [])])].slice(0, 15);
      mem = (await Users.find({ _id: { $in: mem } }, { projection: { _id: 1 } }).toArray()).map(d => d._id);
      if (!name || mem.length < 3 || !mem.includes(phone)) return;
      const g = { _id: randomUUID().slice(0, 12), name, members: mem, owner: phone, createdAt: new Date() };
      await Groups.insertOne(g); mem.forEach(p => toPhone(p, { t: 'group', g: gOut(g) }));
    } else if (m.t === 'gmsg' && m.copies && typeof m.copies === 'object') {
      const g = await Groups.findOne({ _id: String(m.gid), members: phone }); if (!g) return;
      for (const [p, c] of Object.entries(m.copies)) if (p !== phone && g.members.includes(p) && encOk(c))
        if (await deliver(p, { t: 'msg', id: String(m.id).slice(0, 40), from: phone, name: ws.name, gid: g._id, iv: c.iv, ct: c.ct, ts: Date.now() }))
          send(ws, { t: 'st', id: String(m.id).slice(0, 40), by: p, st: 'delivered', gid: g._id });
    } else if (m.t === 'gedit') { // owner renames group / adds / removes members
      const g = await Groups.findOne({ _id: String(m.gid), owner: phone }); if (!g) return;
      const name = typeof m.name === 'string' && m.name.trim() ? m.name.trim().slice(0, 40) : g.name;
      const rm = new Set((Array.isArray(m.remove) ? m.remove : []).filter(p => p !== phone));
      const add = (await Users.find({ _id: { $in: (Array.isArray(m.add) ? m.add : []).filter(idOk) } }, { projection: { _id: 1 } }).toArray()).map(d => d._id);
      const mem = [...new Set([...g.members.filter(p => !rm.has(p)), ...add])].slice(0, 15);
      await Groups.updateOne({ _id: g._id }, { $set: { name, members: mem } });
      const g2 = { ...g, name, members: mem };
      mem.forEach(p => toPhone(p, { t: 'group', g: gOut(g2) }));
      g.members.filter(p => !mem.includes(p)).forEach(p => toPhone(p, { t: 'gremoved', id: g._id }));
    } else if (m.t === 'gleave') {
      const g = await Groups.findOne({ _id: String(m.gid), members: phone }); if (!g) return;
      const mem = g.members.filter(p => p !== phone);
      if (mem.length < 2) { await Groups.deleteOne({ _id: g._id }); g.members.forEach(p => toPhone(p, { t: 'gremoved', id: g._id })); return; }
      const owner = g.owner === phone ? mem[0] : g.owner;
      await Groups.updateOne({ _id: g._id }, { $set: { members: mem, owner } });
      const g2 = { ...g, members: mem, owner };
      mem.forEach(p => toPhone(p, { t: 'group', g: gOut(g2) })); toPhone(phone, { t: 'gremoved', id: g._id });
    } else if (m.t === 'gstart' || m.t === 'gjoin') { // group calls
      const gid = String(m.gid), g = await Groups.findOne({ _id: gid, members: phone }); if (!g) return;
      let c = gcalls.get(gid);
      if (m.t === 'gstart' && !c) {
        c = { video: !!m.video, parts: new Set([phone]) }; gcalls.set(gid, c);
        g.members.forEach(p => p !== phone && toPhone(p, { t: 'gcall', k: 'ring', gid, from: phone, video: c.video })); return;
      }
      if (!c) return send(ws, { t: 'gcall', k: 'ended', gid });
      if (c.parts.size >= 6 && !c.parts.has(phone)) return send(ws, { t: 'gcall', k: 'full', gid });
      const peers = [...c.parts].filter(p => p !== phone); c.parts.add(phone);
      send(ws, { t: 'gcall', k: 'peers', gid, peers, video: c.video });
      peers.forEach(p => toPhone(p, { t: 'gcall', k: 'joined', gid, phone }));
    } else if (m.t === 'gleavecall') gLeave(phone, String(m.gid));
    else if (m.t === 'gsig' && idOk(m.to) && ['offer', 'answer', 'ice'].includes(m.k)) {
      const c = gcalls.get(String(m.gid));
      if (c?.parts.has(phone) && c.parts.has(m.to)) toPhone(m.to, { t: 'gcall', k: 'sig', sk: m.k, gid: String(m.gid), from: phone, d: m.d });
    } else if (m.t === 'call' && idOk(m.to) && ['offer', 'answer', 'ice', 'end', 'reject'].includes(m.k)) {
      if (!toPhone(m.to, { t: 'call', from: phone, k: m.k, d: m.d, video: !!m.video }) && m.k === 'offer') send(ws, { t: 'call', from: m.to, k: 'unavail' });
    }
  }
  ws.on('message', raw => { chain = chain.then(() => handle(raw)).catch(console.error); });
  ws.on('close', () => {
    socks.get(phone)?.delete(ws);
    if (!online(phone)) { for (const gid of [...gcalls.keys()]) gLeave(phone, gid); const t = Date.now(); seen.set(phone, t); Users.updateOne({ _id: phone }, { $set: { lastSeen: t } }).catch(() => {}); presence(phone); }
  });
});

server.listen(process.env.PORT || 3000);
