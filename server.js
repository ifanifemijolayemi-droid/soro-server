import http from 'http';
import { randomUUID } from 'crypto';
import express from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import twilio from 'twilio';
import jwt from 'jsonwebtoken';
import { WebSocketServer } from 'ws';
import { MongoClient } from 'mongodb';

const { TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_VERIFY_SID, JWT_SECRET, ALLOWED_ORIGIN, MONGODB_URI } = process.env;
const verify = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN).verify.v2.services(TWILIO_VERIFY_SID);
const phoneOk = p => /^\+[1-9]\d{7,14}$/.test(p || '');

// ---- MongoDB (persistent storage) ----
const db = (await new MongoClient(MONGODB_URI).connect()).db('soro');
const Users = db.collection('users'), Queue = db.collection('queue'), Groups = db.collection('groups');
await Queue.createIndex({ to: 1, createdAt: 1 });
await Queue.createIndex({ createdAt: 1 }, { expireAfterSeconds: 30 * 86400 }); // undelivered messages kept 30 days
await Groups.createIndex({ members: 1 });

// ---- HTTP: SMS login ----
const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(cors({ origin: ALLOWED_ORIGIN }));
const limiter = rateLimit({ windowMs: 10 * 60 * 1000, limit: 5 });

app.post('/send-otp', limiter, async (req, res) => {
  const { phone } = req.body || {};
  if (!phoneOk(phone)) return res.status(400).json({ ok: false, error: 'Invalid phone number' });
  try { await verify.verifications.create({ to: phone, channel: 'sms' }); res.json({ ok: true }); }
  catch (e) { console.error(e.message); res.status(500).json({ ok: false, error: 'Could not send code' }); }
});
app.post('/verify-otp', limiter, async (req, res) => {
  const { phone, code } = req.body || {};
  if (!phoneOk(phone) || !/^\d{4,8}$/.test(code || '')) return res.status(400).json({ ok: false, error: 'Invalid request' });
  try {
    const r = await verify.verificationChecks.create({ to: phone, code });
    if (r.status !== 'approved') return res.status(401).json({ ok: false, error: 'Wrong or expired code' });
    await Users.updateOne({ _id: phone }, { $setOnInsert: { createdAt: new Date() } }, { upsert: true });
    res.json({ ok: true, token: jwt.sign({ phone }, JWT_SECRET, { expiresIn: '30d' }) });
  } catch (e) { res.status(401).json({ ok: false, error: 'Wrong or expired code' }); }
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

wss.on('connection', (ws, req) => {
  let phone;
  try { phone = jwt.verify(new URL(req.url, 'http://x').searchParams.get('token'), JWT_SECRET).phone; }
  catch { return ws.close(4001); }
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
      for (const d of q) { const { _id, to, createdAt, ...msg } = d; send(ws, msg); if (!msg.gid) toPhone(msg.from, { t: 'st', id: msg.id, by: phone, st: 'delivered' }); }
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
    } else if (m.t === 'lookup' && phoneOk(m.phone)) {
      const u = await Users.findOne({ _id: m.phone });
      send(ws, { t: 'lookup', phone: m.phone, found: !!u, name: u?.name, pub: u?.pub });
    } else if (m.t === 'watch' && Array.isArray(m.phones)) {
      const ps = m.phones.filter(phoneOk).slice(0, 500); ps.forEach(p => ws.watch.add(p));
      const ls = Object.fromEntries((await Users.find({ _id: { $in: ps } }, { projection: { lastSeen: 1 } }).toArray()).map(d => [d._id, d.lastSeen]));
      ps.forEach(p => send(ws, { t: 'presence', phone: p, on: online(p), seen: seen.get(p) || ls[p] || null }));
    } else if (m.t === 'typing' && phoneOk(m.to)) toPhone(m.to, { t: 'typing', from: phone });
    else if (m.t === 'read' && phoneOk(m.to) && Array.isArray(m.ids)) m.ids.slice(0, 200).forEach(id => toPhone(m.to, { t: 'st', id, by: phone, st: 'read' }));
    else if (m.t === 'msg' && phoneOk(m.to) && encOk(m) && await Users.countDocuments({ _id: m.to })) {
      const out = { t: 'msg', id: String(m.id).slice(0, 40), from: phone, name: ws.name, iv: m.iv, ct: m.ct, ts: Date.now() };
      if (await deliver(m.to, out)) send(ws, { t: 'st', id: out.id, by: m.to, st: 'delivered' });
    } else if (m.t === 'gnew') {
      const name = String(m.name || '').trim().slice(0, 40);
      let mem = [...new Set([phone, ...(Array.isArray(m.members) ? m.members.filter(phoneOk) : [])])].slice(0, 15);
      mem = (await Users.find({ _id: { $in: mem } }, { projection: { _id: 1 } }).toArray()).map(d => d._id);
      if (!name || mem.length < 3 || !mem.includes(phone)) return;
      const g = { _id: randomUUID().slice(0, 12), name, members: mem, owner: phone, createdAt: new Date() };
      await Groups.insertOne(g); mem.forEach(p => toPhone(p, { t: 'group', g: gOut(g) }));
    } else if (m.t === 'gmsg' && m.copies && typeof m.copies === 'object') {
      const g = await Groups.findOne({ _id: String(m.gid), members: phone }); if (!g) return;
      for (const [p, c] of Object.entries(m.copies)) if (p !== phone && g.members.includes(p) && encOk(c))
        await deliver(p, { t: 'msg', id: String(m.id).slice(0, 40), from: phone, name: ws.name, gid: g._id, iv: c.iv, ct: c.ct, ts: Date.now() });
    } else if (m.t === 'call' && phoneOk(m.to) && ['offer', 'answer', 'ice', 'end', 'reject'].includes(m.k)) {
      if (!toPhone(m.to, { t: 'call', from: phone, k: m.k, d: m.d, video: !!m.video }) && m.k === 'offer') send(ws, { t: 'call', from: m.to, k: 'unavail' });
    }
  }
  ws.on('message', raw => { chain = chain.then(() => handle(raw)).catch(console.error); });
  ws.on('close', () => {
    socks.get(phone)?.delete(ws);
    if (!online(phone)) { const t = Date.now(); seen.set(phone, t); Users.updateOne({ _id: phone }, { $set: { lastSeen: t } }).catch(() => {}); presence(phone); }
  });
});

server.listen(process.env.PORT || 3000);
