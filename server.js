import http from 'http';
import { randomUUID, createHash, createHmac, randomInt, timingSafeEqual, scryptSync, randomBytes } from 'crypto';
import express from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import { WebSocketServer } from 'ws';
import { MongoClient, ObjectId } from 'mongodb';

const { JWT_SECRET, ALLOWED_ORIGIN, MONGODB_URI, BREVO_API_KEY, MAIL_FROM, PAYSTACK_SECRET, PAYSTACK_PLAN, ADMIN_KEY } = process.env;
const PREMIUM_AMOUNT = +process.env.PREMIUM_AMOUNT || 100000; // in kobo (100000 = 1,000 NGN)
const PREMIUM_CURRENCY = process.env.PREMIUM_CURRENCY || 'NGN';
const VERIFY_AMOUNT = +process.env.VERIFY_AMOUNT || 300000; // verification badge, per year, in kobo (300000 = 3,000 NGN)
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
const Stories = db.collection('stories'), Media = db.collection('media');
await Stories.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // stories vanish after 24h
await Media.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
await Stories.createIndex({ owner: 1 });
const Reports = db.collection('reports'), Reels = db.collection('reels');
await Reels.createIndex({ createdAt: -1 });
await Reels.createIndex({ owner: 1 });
const Follows = db.collection('follows');
await Follows.createIndex({ from: 1, to: 1 }, { unique: true });
await Follows.createIndex({ to: 1 });
const Views = db.collection('rviews'); // one row per account that watched a reel, so view counts are real people
await Views.createIndex({ reel: 1, viewer: 1 }, { unique: true });
await Users.createIndex({ username: 1 }, { unique: true, sparse: true });
const Donations = db.collection('donations'), Comments = db.collection('comments'), Notifs = db.collection('notifs');
await Comments.createIndex({ reel: 1, at: -1 });
await Notifs.createIndex({ to: 1, at: -1 });
await Reports.createIndex({ status: 1, createdAt: -1 });

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
app.use(express.json({ verify: (req, _res, buf) => { req.rawBody = buf; } })); // raw body is needed to check Paystack signatures
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
    const u = await Users.findOne({ _id: email }, { projection: { pw: 1, suspended: 1 } });
    if (u?.suspended) return res.status(403).json({ ok: false, error: 'This account has been suspended.' });
    res.json({ ok: true, token: jwt.sign({ phone: email }, JWT_SECRET, { expiresIn: '30d' }), hasPw: !!u?.pw });
  } catch (e) { console.error(e.message); res.status(500).json({ ok: false, error: 'Server error' }); }
});
// ---- Password sign-in (account is still created with an emailed code first) ----
const hashPw = (pw, salt) => scryptSync(pw, salt, 32).toString('hex');
const authBearer = req => { try { const p = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), JWT_SECRET).phone; return idOk(p) ? p : null; } catch { return null; } };
app.post('/set-password', limiter, async (req, res) => {
  const phone = authBearer(req), pw = String(req.body?.password || '');
  if (!phone) return res.status(401).json({ ok: false, error: 'Please sign in again' });
  if (pw.length < 8 || pw.length > 100) return res.status(400).json({ ok: false, error: 'Use 8 to 100 characters' });
  const salt = randomBytes(16).toString('hex');
  await Users.updateOne({ _id: phone }, { $set: { pw: hashPw(pw, salt), salt, fails: 0 } });
  res.json({ ok: true });
});
app.post('/login', limiter, async (req, res) => {
  let email = norm(req.body?.phone); const pw = String(req.body?.password || '');
  if (email && !email.includes('@')) email = (await Users.findOne({ username: email }, { projection: { _id: 1 } }))?._id || ''; // sign in with a username
  if (!idOk(email) || !pw) return res.status(400).json({ ok: false, error: 'Enter your email or username and password' });
  const bad = () => res.status(401).json({ ok: false, error: 'Wrong email or password. Tap "Email me a code" if you forgot it.' });
  const u = await Users.findOne({ _id: email });
  if (!u || !u.pw) return bad();
  if (u.suspended) return res.status(403).json({ ok: false, error: 'This account has been suspended.' });
  if (u.lockUntil > Date.now()) return res.status(429).json({ ok: false, error: 'Too many tries. Try again in 15 minutes.' });
  const a = Buffer.from(u.pw), b = Buffer.from(hashPw(pw, u.salt));
  if (!(a.length === b.length && timingSafeEqual(a, b))) {
    const fails = (u.fails || 0) + 1;
    await Users.updateOne({ _id: email }, { $set: fails >= 5 ? { fails: 0, lockUntil: Date.now() + 900000 } : { fails } });
    return bad();
  }
  await Users.updateOne({ _id: email }, { $set: { fails: 0 } });
  res.json({ ok: true, email, token: jwt.sign({ phone: email }, JWT_SECRET, { expiresIn: '30d' }), hasPw: true });
});

// ---- Stories (photo / video / text, 24h), profile pictures, media serving ----
const bin = b => Buffer.from(b.buffer.subarray(0, b.length()));
const sOut = d => ({ id: d._id, owner: d.owner, kind: d.kind, caption: d.caption, media: d.media ? '/media/' + d.media : undefined, createdAt: d.createdAt });
const upLimiter = rateLimit({ windowMs: 10 * 60 * 1000, limit: 20 });
const asset = (res, req, buf, type) => {
  res.set({ 'Content-Type': type, 'Accept-Ranges': 'bytes', 'Cache-Control': 'public, max-age=3600', 'Cross-Origin-Resource-Policy': 'cross-origin' });
  const size = buf.length, r = /bytes=(\d*)-(\d*)/.exec(req.headers.range || '');
  if (!r) return res.set('Content-Length', size).end(buf);
  const s = r[1] ? +r[1] : 0, e = r[2] ? Math.min(+r[2], size - 1) : size - 1;
  if (s > e || s >= size) return res.status(416).set('Content-Range', `bytes */${size}`).end();
  res.status(206).set({ 'Content-Range': `bytes ${s}-${e}/${size}`, 'Content-Length': e - s + 1 }).end(buf.subarray(s, e + 1)); // Safari needs range support for video
};
app.post('/story', upLimiter, express.raw({ type: () => true, limit: '41mb' }), async (req, res) => {
  const phone = authBearer(req); if (!phone) return res.status(401).json({ ok: false, error: 'Please sign in again' });
  const kind = req.headers['x-kind'], type = String(req.headers['content-type'] || '').split(';')[0];
  let caption = ''; try { caption = decodeURIComponent(String(req.headers['x-caption'] || '')).slice(0, 200); } catch {}
  let media;
  if (kind === 'text') { if (!caption) return res.status(400).json({ ok: false, error: 'Write something first' }); }
  else if ((kind === 'img' && /^image\/(jpeg|png|webp)$/.test(type)) || (kind === 'video' && /^video\/(mp4|quicktime|webm)$/.test(type))) {
    if (!Buffer.isBuffer(req.body) || !req.body.length) return res.status(400).json({ ok: false, error: 'Empty file' });
    const pu = await Users.findOne({ _id: phone }, { projection: { premiumUntil: 1 } }), max = 40e6; // stories: same limit for everyone
    if (req.body.length > max) return res.status(413).json({ ok: false, error: `Too large. Free accounts can post up to ${max / 1e6} MB.` });
    media = randomUUID(); await Media.insertOne({ _id: media, owner: phone, type, data: req.body, expiresAt: new Date(Date.now() + 86400000) });
  } else return res.status(400).json({ ok: false, error: 'Unsupported file' });
  const d = { _id: randomUUID(), owner: phone, kind, caption, media, createdAt: Date.now(), expiresAt: new Date(Date.now() + 86400000) };
  await Stories.insertOne(d);
  const o = { t: 'story', s: sOut(d) }; wss.clients.forEach(w => w.watch?.has(phone) && send(w, o)); toPhone(phone, o);
  res.json({ ok: true });
});
app.get('/media/:id', async (req, res) => {
  const d = await Media.findOne({ _id: req.params.id }); if (!d) return res.sendStatus(404);
  asset(res, req, bin(d.data), d.type);
});
app.post('/avatar', upLimiter, express.raw({ type: () => true, limit: '400kb' }), async (req, res) => {
  const phone = authBearer(req); if (!phone) return res.status(401).json({ ok: false });
  const type = String(req.headers['content-type'] || '').split(';')[0];
  if (!/^image\/(jpeg|png|webp)$/.test(type) || !Buffer.isBuffer(req.body) || !req.body.length) return res.status(400).json({ ok: false, error: 'Use a JPEG, PNG or WebP image under 400 KB' });
  const r = await Users.findOneAndUpdate({ _id: phone }, { $set: { pic: req.body, picType: type }, $inc: { pv: 1 } }, { upsert: true, returnDocument: 'after' });
  prof.set(phone, { ...(prof.get(phone) || {}), pv: r.pv }); presence(phone);
  res.json({ ok: true, pv: r.pv });
});
app.get('/avatar', async (req, res) => {
  const u = norm(req.query.u), d = idOk(u) && await Users.findOne({ _id: u }, { projection: { pic: 1, picType: 1, priv: 1 } });
  if (!d || !d.pic || d.priv?.photo === 'none') return res.sendStatus(404);
  asset(res, req, bin(d.pic), d.picType || 'image/jpeg');
});
// ---- Account deletion (required by the App Store) ----
app.post('/delete-account', limiter, async (req, res) => {
  const phone = authBearer(req);
  if (!phone || req.body?.confirm !== 'DELETE') return res.status(400).json({ ok: false, error: 'Type DELETE to confirm' });
  for (const g of await Groups.find({ members: phone }).toArray()) {
    const mem = g.members.filter(p => p !== phone);
    if (mem.length < 2) { await Groups.deleteOne({ _id: g._id }); mem.forEach(p => toPhone(p, { t: 'gremoved', id: g._id })); }
    else { const owner = g.owner === phone ? mem[0] : g.owner; await Groups.updateOne({ _id: g._id }, { $set: { members: mem, owner } }); mem.forEach(p => toPhone(p, { t: 'group', g: gOut({ ...g, members: mem, owner }) })); }
  }
  await Media.deleteMany({ owner: phone }); await Stories.deleteMany({ owner: phone }); await Reels.deleteMany({ owner: phone }); await Comments.deleteMany({ owner: phone }); await Follows.deleteMany({ $or: [{ from: phone }, { to: phone }] }); await Views.deleteMany({ viewer: phone }); await Notifs.deleteMany({ $or: [{ to: phone }, { from: phone }] });
  await Queue.deleteMany({ $or: [{ to: phone }, { from: phone }] }); await Otps.deleteOne({ _id: phone });
  await Users.deleteOne({ _id: phone });
  socks.get(phone)?.forEach(w => w.close(4001));
  res.json({ ok: true });
});

// ---- Premium via Paystack (web only; iOS app purchases must use Apple in-app purchase) ----
app.get('/pricing', (_, res) => res.json({ amount: PREMIUM_AMOUNT / 100, currency: PREMIUM_CURRENCY, enabled: !!PAYSTACK_SECRET, verifyAmount: VERIFY_AMOUNT / 100 }));
app.post('/pay/init', limiter, async (req, res) => {
  const phone = authBearer(req);
  if (!phone || !PAYSTACK_SECRET) return res.status(400).json({ ok: false, error: 'Payments are not available yet' });
  const product = ['verify', 'donate'].includes(req.body?.product) ? req.body.product : 'premium';
  if (product === 'premium') return res.status(400).json({ ok: false, error: 'Premium has been retired. Everything is free except the verified badge.' });
  let amount = product === 'verify' ? VERIFY_AMOUNT : PREMIUM_AMOUNT;
  if (product === 'donate') { amount = Math.round(Number(req.body.amount) * 100); if (!(amount >= 10000 && amount <= 1e9)) return res.status(400).json({ ok: false, error: 'Enter an amount from 100 to 10,000,000' }); }
  const body = { email: phone, amount, currency: PREMIUM_CURRENCY, callback_url: ALLOWED_ORIGIN + '/?paid=1', metadata: { uid: phone, product } };
  if (PAYSTACK_PLAN && product === 'premium') body.plan = PAYSTACK_PLAN;
  try {
    const r = await fetch('https://api.paystack.co/transaction/initialize', { method: 'POST', headers: { Authorization: 'Bearer ' + PAYSTACK_SECRET, 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const j = await r.json(); if (!j.status) throw new Error(j.message);
    res.json({ ok: true, url: j.data.authorization_url });
  } catch (e) { console.error(e.message); res.status(500).json({ ok: false, error: 'Could not start the payment' }); }
});
app.post('/pay/webhook', async (req, res) => {
  const sig = createHmac('sha512', PAYSTACK_SECRET || '').update(req.rawBody || '').digest('hex');
  if (!PAYSTACK_SECRET || sig !== req.headers['x-paystack-signature']) return res.sendStatus(401);
  const ev = req.body;
  if (ev?.event === 'charge.success' && ev.data?.status === 'success') {
    const uid = norm(ev.data.metadata?.uid || ev.data.customer?.email);
    if (idOk(uid) && ev.data.metadata?.product === 'donate') {
      await Donations.updateOne({ _id: String(ev.data.reference) }, { $setOnInsert: { uid, amount: ev.data.amount / 100, currency: ev.data.currency, at: new Date() } }, { upsert: true });
      toPhone(uid, { t: 'thanks', amount: ev.data.amount / 100 });
    } else if (idOk(uid) && ev.data.metadata?.product === 'verify') {
      if (ev.data.amount >= VERIFY_AMOUNT) {
        const u = await Users.findOne({ _id: uid }, { projection: { verifiedUntil: 1 } });
        const until = Math.max(Date.now(), u?.verifiedUntil || 0) + 365 * 86400000;
        await Users.updateOne({ _id: uid }, { $set: { verifiedUntil: until } });
        prof.set(uid, { ...(prof.get(uid) || {}), vu: until }); toPhone(uid, { t: 'me', verifiedUntil: until }); presence(uid);
      }
    } else if (idOk(uid) && (ev.data.metadata?.product ?? 'premium') === 'premium' && (PAYSTACK_PLAN || ev.data.amount >= PREMIUM_AMOUNT)) {
      const u = await Users.findOne({ _id: uid }, { projection: { premiumUntil: 1 } });
      const until = Math.max(Date.now(), u?.premiumUntil || 0) + 30 * 86400000;
      await Users.updateOne({ _id: uid }, { $set: { premiumUntil: until } });
      toPhone(uid, { t: 'me', premiumUntil: until });
    }
  }
  res.sendStatus(200);
});

// ---- Reports: review at /admin (needs ADMIN_KEY). Apple expects timely action. ----
const ADMIN_HTML = `<!doctype html><meta name=viewport content="width=device-width,initial-scale=1"><title>SORO reports</title><body style="font:15px system-ui;max-width:640px;margin:auto;padding:16px"><h2>Open reports</h2><div id=l>Loading</div><script>
const k=sessionStorage.k||(sessionStorage.k=prompt('Admin key'));
async function load(){const r=await fetch('/admin/reports',{headers:{'x-admin-key':k}});const l=document.getElementById('l');if(!r.ok){l.textContent='Wrong key';sessionStorage.removeItem('k');return}
const a=await r.json();l.textContent='';if(!a.length)l.textContent='No open reports.';
a.forEach(x=>{const d=document.createElement('div');d.style.cssText='border:1px solid #ccc;border-radius:10px;padding:12px;margin:10px 0';
const t=document.createElement('div');t.textContent=x.target+' reported by '+x.reporter+' ('+x.reason+') '+new Date(x.createdAt).toLocaleString();d.append(t);
if(x.note){const n=document.createElement('p');n.textContent=x.note;d.append(n)}
(x.evidence||[]).forEach(e=>{const p=document.createElement('blockquote');p.textContent=e;d.append(p)});
[['suspend','Suspend account'],['dismiss','Dismiss']].forEach(([act,lab])=>{const b=document.createElement('button');b.textContent=lab;b.style.margin='4px 8px 0 0';b.onclick=async()=>{await fetch('/admin/act',{method:'POST',headers:{'x-admin-key':k,'content-type':'application/json'},body:JSON.stringify({id:x._id,action:act})});load()};d.append(b)});
l.append(d)})}
load()</script>`;
const adminOk = req => ADMIN_KEY && req.headers['x-admin-key'] === ADMIN_KEY;
app.get('/admin', (_, res) => res.type('html').send(ADMIN_HTML));
app.get('/admin/reports', async (req, res) => { if (!adminOk(req)) return res.sendStatus(401); res.json(await Reports.find({ status: 'open' }).sort({ createdAt: -1 }).limit(100).toArray()); });
app.post('/admin/act', async (req, res) => {
  if (!adminOk(req)) return res.sendStatus(401);
  try {
    const r = await Reports.findOne({ _id: new ObjectId(String(req.body?.id)) }); if (!r) return res.sendStatus(404);
    if (req.body.action === 'suspend') { await Users.updateOne({ _id: r.target }, { $set: { suspended: true } }); socks.get(r.target)?.forEach(w => w.close(4001)); await Reels.deleteMany({ owner: r.target }); await Media.deleteMany({ owner: r.target }); }
    await Reports.updateOne({ _id: r._id }, { $set: { status: req.body.action === 'suspend' ? 'actioned' : 'dismissed' } });
    res.json({ ok: true });
  } catch { res.sendStatus(400); }
});
// ---- Privacy choices: who can see last seen, photo, about, and who can add me to groups ----
const softLimiter = rateLimit({ windowMs: 60000, limit: 60 });
app.post('/privacy', softLimiter, async (req, res) => {
  const phone = authBearer(req); if (!phone) return res.status(401).json({ ok: false });
  const v = x => (x === 'none' ? 'none' : 'all'), b = req.body || {};
  const priv = { seen: v(b.seen), photo: v(b.photo), about: v(b.about), groups: v(b.groups) };
  await Users.updateOne({ _id: phone }, { $set: { priv } }); privs.set(phone, priv); presence(phone);
  res.json({ ok: true });
});
// ---- Reels: posts, likes, comments, activity ----
const usersMap = async ids => Object.fromEntries((await Users.find({ _id: { $in: [...new Set(ids)] }, suspended: { $ne: true } }, { projection: { name: 1, pv: 1, verifiedUntil: 1, blocked: 1, priv: 1 } }).toArray()).map(u => [u._id, u]));
const uOut = (id, u = {}) => ({ name: u.name || id.split('@')[0], pv: u.priv?.photo === 'none' ? 0 : (u.pv || 0), vf: (u.verifiedUntil || 0) > Date.now() });
// creator tools: text on screen, colour looks, slow-motion and zoom are saved with the reel and applied when it plays
const NICHES = ['relationships', 'psychology', 'tech', 'economics', 'policy', 'culture', 'travel', 'history', 'gaming', 'comedy'];
const FXV = { font: ['serif', 'sans', 'bold'], color: ['white', 'cream', 'gold', 'red'], pos: ['center', 'lower'], anim: ['fade', 'pop', 'word'], grade: ['none', 'warm', 'moody', 'cinema'] };
function cleanFx(raw) { try { const f = JSON.parse(raw), o = { text: String(f.text || '').slice(0, 90) }; for (const k in FXV) o[k] = FXV[k].includes(f[k]) ? f[k] : FXV[k][0]; o.speed = [1, 0.8, 0.5].includes(f.speed) ? f.speed : 1; o.zoom = !!f.zoom; return o; } catch { return null; } }
const reelOut = (r, us, phone, fs = new Set()) => ({ fol: fs.has(r.owner), rp: (r.reposts || []).length, reposted: (r.reposts || []).includes(phone), priv: !!r.priv, plays: r.plays || 0, snd: r.snd || null, sndMedia: r.sndMedia || null, sndName: r.sndName || null, id: r._id, owner: r.owner, ...uOut(r.owner, us[r.owner]), kind: r.kind, media: '/media/' + r.media, caption: r.caption, likes: r.likes.length, liked: r.likes.includes(phone), cc: r.cc || 0, fx: r.fx || null, niche: r.niche || '', shares: r.shares || 0, views: r.views || 0, createdAt: r.createdAt });
async function notify(to, n) { // one activity item per like; one per comment
  if (to === n.from) return;
  const r = await Notifs.updateOne(n.type === 'like' ? { to, type: 'like', from: n.from, reel: n.reel } : n.type === 'clike' ? { to, type: 'clike', from: n.from, comment: n.comment } : { _id: randomUUID() }, { $setOnInsert: { ...n, to, at: Date.now(), read: false } }, { upsert: true });
  if (r.upsertedCount) { const u = await Users.findOne({ _id: n.from }, { projection: { name: 1 } }); toPhone(to, { t: 'notif', n: { type: n.type, name: u?.name || n.from.split('@')[0], text: n.text } }); }
}
app.post('/reel', upLimiter, express.raw({ type: () => true, limit: '41mb' }), async (req, res) => {
  const phone = authBearer(req); if (!phone) return res.status(401).json({ ok: false, error: 'Please sign in again' });
  const kind = req.headers['x-kind'], type = String(req.headers['content-type'] || '').split(';')[0];
  let caption = ''; try { caption = decodeURIComponent(String(req.headers['x-caption'] || '')).slice(0, 150); } catch {}
  const okType = (kind === 'img' && /^image\/(jpeg|png|webp)$/.test(type)) || (kind === 'video' && /^video\/(mp4|quicktime|webm)$/.test(type));
  if (!okType || !Buffer.isBuffer(req.body) || !req.body.length) return res.status(400).json({ ok: false, error: 'Unsupported or empty file' });
  const pu = await Users.findOne({ _id: phone }, { projection: { suspended: 1 } });
  if (pu?.suspended) return res.status(403).json({ ok: false, error: 'This account has been suspended.' });
  if (req.body.length > (kind === 'img' ? 8e6 : 40e6)) return res.status(413).json({ ok: false, error: 'File too large' });
  const media = randomUUID(); await Media.insertOne({ _id: media, owner: phone, type, data: req.body }); // no expiry: reels stay until deleted
  let fx = null; try { fx = cleanFx(decodeURIComponent(String(req.headers['x-fx'] || ''))); } catch {}
  const niche = NICHES.includes(String(req.headers['x-niche'] || '')) ? String(req.headers['x-niche']) : '';
  let snd = {}; const sid = String(req.headers['x-snd'] || ''); // photo reels can carry a saved sound as music
  if (kind === 'img' && sid) { const sr = await Reels.findOne({ _id: sid, kind: 'video', priv: { $ne: true } }); if (sr) snd = { snd: sid, sndMedia: '/media/' + sr.media, sndName: ((await Users.findOne({ _id: sr.owner }, { projection: { name: 1 } }))?.name || sr.owner.split('@')[0]) + ' \u00b7 original sound' }; }
  await Reels.insertOne({ _id: randomUUID(), owner: phone, kind, media, caption, fx, niche, ...snd, priv: req.headers['x-priv'] === '1', reposts: [], likes: [], cc: 0, shares: 0, views: 0, wt: 0, r3: 0, createdAt: Date.now() });
  res.json({ ok: true });
});
app.get('/reels', softLimiter, async (req, res) => {
  const phone = authBearer(req); if (!phone) return res.status(401).json({ ok: false });
  const blocked = (await Users.findOne({ _id: phone }, { projection: { blocked: 1 } }))?.blocked || [];
  const before = Number(req.query.before) || Date.now() + 1, who = norm(req.query.owner), q = { createdAt: { $lt: before }, owner: { $nin: blocked } };
  if (who) { if (!idOk(who) || blocked.includes(who)) return res.json({ ok: true, list: [] }); q.owner = who; }
  const nq = String(req.query.niche || ''); if (NICHES.includes(nq)) q.niche = nq;
  const tg = String(req.query.tag || '').replace(/^#/, ''); if (/^[\p{L}\p{N}_]{1,30}$/u.test(tg)) q.caption = { $regex: '#' + tg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '($|[^A-Za-z0-9_])', $options: 'i' };
  q.priv = { $ne: true };
  const sd = String(req.query.snd || ''); if (sd) q.$or = [{ _id: sd }, { snd: sd }]; // the sound's own video plus reels that use it as music
  if (req.query.priv && who === phone) q.priv = true; // my private reels, visible only to me
  if (req.query.liked) { q.likes = phone; q.owner = { $nin: blocked }; } // reels I liked
  if (req.query.reposts && who) { q.reposts = who; q.owner = { $nin: blocked }; }
  if (req.query.following) { const fl = (await Follows.find({ from: phone }).toArray()).map(f => f.to).filter(x => !blocked.includes(x)); q.owner = { $in: fl }; }
  const list = await Reels.find(q).sort({ createdAt: -1 }).limit(12).toArray(), us = await usersMap(list.map(r => r.owner));
  const fs = new Set((await Follows.find({ from: phone, to: { $in: list.map(r => r.owner) } }).toArray()).map(f => f.to));
  res.json({ ok: true, list: list.filter(r => us[r.owner] && !(us[r.owner].blocked || []).includes(phone)).map(r => reelOut(r, us, phone, fs)) });
});
app.get('/reel/get', softLimiter, async (req, res) => {
  const phone = authBearer(req); if (!phone) return res.status(401).json({ ok: false });
  const r = await Reels.findOne({ _id: String(req.query.id) }); if (!r) return res.status(404).json({ ok: false, error: 'This reel is no longer available' });
  const us = await usersMap([r.owner]); if (!us[r.owner] || (us[r.owner].blocked || []).includes(phone)) return res.status(404).json({ ok: false, error: 'This reel is no longer available' });
  const fs = new Set((await Follows.find({ from: phone, to: r.owner }).toArray()).map(f => f.to));
  res.json({ ok: true, reel: reelOut(r, us, phone, fs) });
});
app.get('/reel/likes', softLimiter, async (req, res) => {
  const phone = authBearer(req); if (!phone) return res.status(401).json({ ok: false });
  const r = await Reels.findOne({ _id: String(req.query.id) }); if (!r) return res.json({ ok: true, list: [] });
  const ids = r.likes.slice(-50).reverse(), us = await usersMap(ids);
  res.json({ ok: true, total: r.likes.length, list: ids.filter(i => us[i]).map(i => ({ email: i, ...uOut(i, us[i]) })) });
});
app.get('/reel/comments', softLimiter, async (req, res) => {
  const phone = authBearer(req); if (!phone) return res.status(401).json({ ok: false });
  const par = String(req.query.parent || ''), q = { reel: String(req.query.id), parent: par || null }; if (Number(req.query.before)) q.at = { $lt: Number(req.query.before) };
  const list = await Comments.find(q).sort({ at: par ? 1 : -1 }).limit(30).toArray(), us = await usersMap(list.map(c => c.owner));
  res.json({ ok: true, list: list.filter(c => us[c.owner]).map(c => ({ id: c._id, owner: c.owner, text: c.text, at: c.at, parent: c.parent || null, likes: (c.likes || []).length, liked: (c.likes || []).includes(phone), rc: c.rc || 0, kind: c.kind || 'text', media: c.media ? '/media/' + c.media : null, ...uOut(c.owner, us[c.owner]) })) });
});
app.post('/reel/comment', softLimiter, async (req, res) => {
  const phone = authBearer(req); if (!phone) return res.status(401).json({ ok: false, error: 'Please sign in again' });
  const id = String(req.body?.id), text = String(req.body?.text || '').trim().slice(0, 300);
  if (!text) return res.status(400).json({ ok: false, error: 'Write something first' });
  const r = await Reels.findOne({ _id: id }); if (!r) return res.status(404).json({ ok: false, error: 'This reel is gone' });
  const [me, ow] = await Promise.all([Users.findOne({ _id: phone }), Users.findOne({ _id: r.owner }, { projection: { blocked: 1 } })]);
  if (me?.suspended || (ow?.blocked || []).includes(phone)) return res.status(403).json({ ok: false, error: 'You cannot comment on this reel' });
  let parent = null; const pid = String(req.body?.parent || '');
  if (pid) { const pc = await Comments.findOne({ _id: pid, reel: id }); if (!pc) return res.status(404).json({ ok: false, error: 'That comment is gone' }); parent = pc.parent || pc._id; }
  const c = { _id: randomUUID(), reel: id, owner: phone, text, kind: req.body?.kind === 'sticker' && [...text].length <= 6 ? 'sticker' : 'text', at: Date.now(), parent, likes: [], rc: 0 };
  await Comments.insertOne(c); await Reels.updateOne({ _id: id }, { $inc: { cc: 1 } }); if (parent) await Comments.updateOne({ _id: parent }, { $inc: { rc: 1 } });
  await notify(r.owner, { type: 'comment', from: phone, reel: id, text: text.slice(0, 80) });
  if (pid) { const po = (await Comments.findOne({ _id: pid }, { projection: { owner: 1 } }))?.owner; if (po && po !== r.owner) await notify(po, { type: 'reply', from: phone, reel: id, text: text.slice(0, 80) }); }
  res.json({ ok: true, comment: { id: c._id, owner: phone, text, at: c.at, parent, likes: 0, liked: false, rc: 0, kind: c.kind, media: null, ...uOut(phone, me || {}) } });
});
// Picture, voice and custom-sticker comments. Pictures and voice notes are a benefit of the verified badge.
const MEDIA_RULES = { img: [/^image\/(jpeg|png|webp)$/, 3e6], sticker: [/^image\/(jpeg|png|webp)$/, 3e5], audio: [/^audio\/(webm|mp4|mpeg|ogg|aac|x-m4a|m4a)$/, 2.5e6] };
app.post('/reel/comment/media', upLimiter, express.raw({ type: () => true, limit: '3mb' }), async (req, res) => {
  const phone = authBearer(req); if (!phone) return res.status(401).json({ ok: false, error: 'Please sign in again' });
  const kind = String(req.headers['x-kind'] || ''), rule = MEDIA_RULES[kind], type = String(req.headers['content-type'] || '').split(';')[0], id = String(req.headers['x-reel'] || '');
  if (!rule || !rule[0].test(type) || !Buffer.isBuffer(req.body) || !req.body.length || req.body.length > rule[1]) return res.status(400).json({ ok: false, error: 'That file is not supported or is too large' });
  const r = await Reels.findOne({ _id: id }); if (!r) return res.status(404).json({ ok: false, error: 'This reel is gone' });
  const [me, ow] = await Promise.all([Users.findOne({ _id: phone }), Users.findOne({ _id: r.owner }, { projection: { blocked: 1 } })]);
  if (me?.suspended || (ow?.blocked || []).includes(phone)) return res.status(403).json({ ok: false, error: 'You cannot comment on this reel' });
  if ((kind === 'img' || kind === 'audio') && !((me?.verifiedUntil || 0) > Date.now())) return res.status(403).json({ ok: false, needsVerify: true, error: 'Picture and voice comments are for verified accounts.' });
  let parent = null; const pid = String(req.headers['x-parent'] || '');
  if (pid) { const pc = await Comments.findOne({ _id: pid, reel: id }); if (!pc) return res.status(404).json({ ok: false, error: 'That comment is gone' }); parent = pc.parent || pc._id; }
  let text = ''; try { text = decodeURIComponent(String(req.headers['x-text'] || '')).trim().slice(0, 120); } catch {}
  const media = randomUUID(); await Media.insertOne({ _id: media, owner: phone, type, data: req.body }); // no expiry
  const c = { _id: randomUUID(), reel: id, owner: phone, text, kind, media, at: Date.now(), parent, likes: [], rc: 0 };
  await Comments.insertOne(c); await Reels.updateOne({ _id: id }, { $inc: { cc: 1 } }); if (parent) await Comments.updateOne({ _id: parent }, { $inc: { rc: 1 } });
  const what = kind === 'audio' ? 'sent a voice comment' : kind === 'img' ? 'sent a picture' : 'sent a sticker';
  await notify(r.owner, { type: 'comment', from: phone, reel: id, text: what });
  if (pid) { const po = (await Comments.findOne({ _id: pid }, { projection: { owner: 1 } }))?.owner; if (po && po !== r.owner) await notify(po, { type: 'reply', from: phone, reel: id, text: what }); }
  res.json({ ok: true, comment: { id: c._id, owner: phone, text, at: c.at, parent, likes: 0, liked: false, rc: 0, kind, media: '/media/' + media, ...uOut(phone, me || {}) } });
});
app.post('/reel/comment/delete', softLimiter, async (req, res) => {
  const phone = authBearer(req); if (!phone) return res.status(401).json({ ok: false });
  const c = await Comments.findOne({ _id: String(req.body?.id) }); if (!c) return res.json({ ok: false });
  const r = await Reels.findOne({ _id: c.reel });
  if (c.owner !== phone && r?.owner !== phone) return res.status(403).json({ ok: false });
  if (c.media) await Media.deleteOne({ _id: c.media });
  const kids = c.parent ? 0 : await Comments.countDocuments({ parent: c._id });
  if (!c.parent) await Comments.deleteMany({ parent: c._id });
  await Comments.deleteOne({ _id: c._id }); if (c.parent) await Comments.updateOne({ _id: c.parent }, { $inc: { rc: -1 } });
  if (r) await Reels.updateOne({ _id: r._id }, { $inc: { cc: -(1 + kids) } });
  res.json({ ok: true });
});
app.post('/reel/comment/like', softLimiter, async (req, res) => {
  const phone = authBearer(req); if (!phone) return res.status(401).json({ ok: false });
  const c = await Comments.findOneAndUpdate({ _id: String(req.body?.id) }, req.body?.on ? { $addToSet: { likes: phone } } : { $pull: { likes: phone } }, { returnDocument: 'after' });
  if (c && req.body?.on) await notify(c.owner, { type: 'clike', from: phone, reel: c.reel, comment: c._id, text: (c.text || '').slice(0, 60) });
  res.json({ ok: !!c, likes: c?.likes?.length || 0 });
});
app.post('/reel/repost', softLimiter, async (req, res) => {
  const phone = authBearer(req); if (!phone) return res.status(401).json({ ok: false });
  const r = await Reels.findOneAndUpdate({ _id: String(req.body?.id), priv: { $ne: true } }, req.body?.on ? { $addToSet: { reposts: phone } } : { $pull: { reposts: phone } }, { returnDocument: 'after' });
  res.json({ ok: !!r, rp: r?.reposts?.length || 0 });
});
// ---- Following, followers and the TikTok-style profile ----
app.post('/follow', softLimiter, async (req, res) => {
  const phone = authBearer(req); if (!phone) return res.status(401).json({ ok: false });
  const to = norm(req.body?.to); if (!idOk(to) || to === phone) return res.status(400).json({ ok: false, error: 'You cannot follow this account' });
  const t = await Users.findOne({ _id: to }, { projection: { blocked: 1, suspended: 1 } });
  if (!t || t.suspended || (t.blocked || []).includes(phone)) return res.status(404).json({ ok: false, error: 'This account is not available' });
  if (req.body?.on) await Follows.updateOne({ from: phone, to }, { $setOnInsert: { at: Date.now() } }, { upsert: true }); else await Follows.deleteOne({ from: phone, to });
  res.json({ ok: true, followers: await Follows.countDocuments({ to }) });
});
app.get('/profile', softLimiter, async (req, res) => {
  const phone = authBearer(req); if (!phone) return res.status(401).json({ ok: false });
  const u = norm(req.query.u); if (!idOk(u)) return res.status(400).json({ ok: false });
  const [d, fg, fr, mine, theirs, agg] = await Promise.all([Users.findOne({ _id: u }), Follows.countDocuments({ from: u }), Follows.countDocuments({ to: u }), Follows.findOne({ from: phone, to: u }), Follows.findOne({ from: u, to: phone }),
    Reels.aggregate([{ $match: { owner: u, priv: { $ne: true } } }, { $group: { _id: null, n: { $sum: 1 }, likes: { $sum: { $size: '$likes' } } } }]).toArray()]);
  if (!d || d.suspended || (d.blocked || []).includes(phone)) return res.json({ ok: false });
  res.json({ ok: true, ...uOut(u, d), username: d.username || '', about: d.priv?.about === 'none' && u !== phone ? '' : (d.about || ''), link: d.link || '', following: fg, followers: fr, likes: agg[0]?.likes || 0, reels: agg[0]?.n || 0, isFollowing: !!mine, followsMe: !!theirs });
});
app.get('/follows', softLimiter, async (req, res) => {
  const phone = authBearer(req); if (!phone) return res.status(401).json({ ok: false });
  const u = norm(req.query.u), t = req.query.t === 'following' ? 'following' : 'followers'; if (!idOk(u)) return res.json({ ok: true, list: [] });
  const rows = await Follows.find(t === 'following' ? { from: u } : { to: u }).sort({ at: -1 }).limit(60).toArray(), ids = rows.map(f => t === 'following' ? f.to : f.from), us = await usersMap(ids);
  const mine = new Set((await Follows.find({ from: phone, to: { $in: ids } }).toArray()).map(f => f.to));
  res.json({ ok: true, list: ids.filter(i => us[i] && !(us[i].blocked || []).includes(phone)).map(i => ({ email: i, ...uOut(i, us[i]), fol: mine.has(i) })) });
});
app.post('/reel/like', softLimiter, async (req, res) => {
  const phone = authBearer(req); if (!phone) return res.status(401).json({ ok: false });
  const id = String(req.body?.id), r = await Reels.findOneAndUpdate({ _id: id }, req.body?.on ? { $addToSet: { likes: phone } } : { $pull: { likes: phone } }, { returnDocument: 'after' });
  if (r && req.body?.on) await notify(r.owner, { type: 'like', from: phone, reel: id });
  res.json({ ok: !!r, likes: r?.likes.length || 0 });
});
app.post('/reel/delete', softLimiter, async (req, res) => {
  const phone = authBearer(req); if (!phone) return res.status(401).json({ ok: false });
  const id = String(req.body?.id), r = await Reels.findOneAndDelete({ _id: id, owner: phone });
  if (r) { await Media.deleteOne({ _id: r.media }); await Comments.deleteMany({ reel: id }); await Notifs.deleteMany({ reel: id }); await Views.deleteMany({ reel: id }); }
  res.json({ ok: !!r });
});
app.get('/notifs', softLimiter, async (req, res) => {
  const phone = authBearer(req); if (!phone) return res.status(401).json({ ok: false });
  const list = await Notifs.find({ to: phone }).sort({ at: -1 }).limit(60).toArray();
  const [us, rs] = await Promise.all([usersMap(list.map(n => n.from)), Reels.find({ _id: { $in: list.map(n => n.reel) } }).toArray()]);
  const rm = Object.fromEntries(rs.map(r => [r._id, r]));
  res.json({ ok: true, unread: list.filter(n => !n.read).length, list: list.filter(n => us[n.from] && rm[n.reel]).map(n => ({ id: n._id, type: n.type, from: n.from, ...uOut(n.from, us[n.from]), reel: n.reel, kind: rm[n.reel].kind, media: '/media/' + rm[n.reel].media, text: n.text, at: n.at, read: n.read })) });
});
app.post('/notifs/read', softLimiter, async (req, res) => {
  const phone = authBearer(req); if (!phone) return res.status(401).json({ ok: false });
  await Notifs.updateMany({ to: phone, read: false }, { $set: { read: true } });
  res.json({ ok: true });
});
// ---- Creator insights: views, watch time, 3-second hold, shares ----
app.post('/reel/view', softLimiter, async (req, res) => {
  const phone = authBearer(req); if (!phone) return res.status(401).json({ ok: false });
  const secs = Math.max(0, Math.min(Number(req.body?.secs) || 0, 180));
  const rid = String(req.body?.id), reel = secs >= 1 ? await Reels.findOne({ _id: rid }, { projection: { owner: 1 } }) : null;
  if (reel && reel.owner !== phone) { // "views" = different accounts that watched; "plays" = every qualifying watch
    const first = (await Views.updateOne({ reel: rid, viewer: phone }, { $setOnInsert: { at: Date.now() } }, { upsert: true })).upsertedCount > 0;
    await Reels.updateOne({ _id: rid }, { $inc: { plays: 1, wt: secs, r3: secs >= 3 ? 1 : 0, ...(first ? { views: 1 } : {}) } });
  }
  res.json({ ok: true });
});
app.post('/reel/share', softLimiter, async (req, res) => {
  const phone = authBearer(req); if (!phone) return res.status(401).json({ ok: false });
  await Reels.updateOne({ _id: String(req.body?.id) }, { $inc: { shares: 1 } }); res.json({ ok: true });
});
app.get('/reel/stats', softLimiter, async (req, res) => {
  const phone = authBearer(req); if (!phone) return res.status(401).json({ ok: false });
  const r = await Reels.findOne({ _id: String(req.query.id), owner: phone }); if (!r) return res.json({ ok: false });
  const v = r.views || 0, p = r.plays || v;
  res.json({ ok: true, views: v, plays: p, likes: r.likes.length, comments: r.cc || 0, shares: r.shares || 0, avgWatch: p ? (r.wt || 0) / p : 0, hold3: p ? (r.r3 || 0) / p : 0, shareRate: v ? (r.shares || 0) / v : 0 });
});
// ---- Saved sounds: keep the sound from a video reel and use it as music on photo reels ----
app.get('/sounds', softLimiter, async (req, res) => {
  const phone = authBearer(req); if (!phone) return res.status(401).json({ ok: false });
  const list = (await Users.findOne({ _id: phone }, { projection: { sounds: 1 } }))?.sounds || [];
  const alive = new Set((await Reels.find({ _id: { $in: list.map(x => x.reel) } }, { projection: { _id: 1 } }).toArray()).map(r => r._id));
  const live = list.filter(x => alive.has(x.reel)), cnt = {};
  for (const g of await Reels.aggregate([{ $match: { snd: { $in: live.map(x => x.reel) }, priv: { $ne: true } } }, { $group: { _id: '$snd', n: { $sum: 1 } } }]).toArray()) cnt[g._id] = g.n;
  res.json({ ok: true, list: live.reverse().map(x => ({ reel: x.reel, media: x.media, name: x.name, owner: x.owner, count: 1 + (cnt[x.reel] || 0) })) });
});
app.post('/sound/save', softLimiter, async (req, res) => {
  const phone = authBearer(req); if (!phone) return res.status(401).json({ ok: false });
  const r = await Reels.findOne({ _id: String(req.body?.reel), kind: 'video', priv: { $ne: true } }); if (!r) return res.status(404).json({ ok: false, error: 'This sound is not available' });
  const own = (await Users.findOne({ _id: r.owner }, { projection: { name: 1 } }))?.name || r.owner.split('@')[0];
  await Users.updateOne({ _id: phone }, { $pull: { sounds: { reel: r._id } } });
  await Users.updateOne({ _id: phone }, { $push: { sounds: { $each: [{ reel: r._id, media: '/media/' + r.media, name: own + ' \u00b7 original sound', owner: r.owner, at: Date.now() }], $slice: -100 } } });
  res.json({ ok: true });
});
app.post('/sound/remove', softLimiter, async (req, res) => {
  const phone = authBearer(req); if (!phone) return res.status(401).json({ ok: false });
  await Users.updateOne({ _id: phone }, { $pull: { sounds: { reel: String(req.body?.reel) } } }); res.json({ ok: true });
});
// ---- People map: only people who switch it on appear, and only as an approximate area (about 10 km) ----
app.post('/map/share', softLimiter, async (req, res) => {
  const phone = authBearer(req); if (!phone) return res.status(401).json({ ok: false });
  if (!req.body?.on) { await Users.updateOne({ _id: phone }, { $set: { mapOn: false }, $unset: { loc: 1 } }); return res.json({ ok: true }); }
  const lat = Number(req.body?.lat), lng = Number(req.body?.lng);
  if (!(lat >= -90 && lat <= 90 && lng >= -180 && lng <= 180)) return res.status(400).json({ ok: false, error: 'That location is not valid' });
  const r1 = v => Math.round(v * 10) / 10;
  await Users.updateOne({ _id: phone }, { $set: { mapOn: true, loc: { lat: r1(lat), lng: r1(lng), at: Date.now() } } });
  res.json({ ok: true, lat: r1(lat), lng: r1(lng) });
});
app.get('/map/users', softLimiter, async (req, res) => {
  const phone = authBearer(req); if (!phone) return res.status(401).json({ ok: false });
  const me = await Users.findOne({ _id: phone }, { projection: { blocked: 1, mapOn: 1, loc: 1 } }), blocked = me?.blocked || [];
  const list = await Users.find({ mapOn: true, loc: { $exists: true }, _id: { $nin: [...blocked, phone] }, blocked: { $ne: phone }, suspended: { $ne: true } }, { projection: { name: 1, pv: 1, priv: 1, verifiedUntil: 1, username: 1, loc: 1 } }).limit(300).toArray();
  res.json({ ok: true, me: { on: !!me?.mapOn, lat: me?.loc?.lat, lng: me?.loc?.lng }, list: list.map(u => ({ phone: u._id, username: u.username || '', ...uOut(u._id, u), lat: u.loc.lat, lng: u.loc.lng })) });
});
// ---- Usernames: pick one, and let others search for you ----
const RESERVED = ['admin', 'soro', 'support', 'help', 'root', 'moderator', 'official', 'staff'];
app.post('/username', softLimiter, async (req, res) => {
  const phone = authBearer(req); if (!phone) return res.status(401).json({ ok: false });
  const set = {}, b = req.body || {};
  if (b.username != null) {
    const u = String(b.username).trim().toLowerCase().replace(/^@/, '');
    if (!/^[a-z0-9_.]{3,20}$/.test(u) || /^[.]|[.]$/.test(u) || RESERVED.includes(u)) return res.status(400).json({ ok: false, error: 'Use 3 to 20 letters, numbers, _ or . (not at the start or end)' });
    set.username = u;
  }
  if (b.discoverable != null) set.discoverable = !!b.discoverable;
  if (b.link != null) { const l = String(b.link).trim().slice(0, 100); set.link = /^https?:\/\/\S+$/i.test(l) ? l : ''; }
  try { await Users.updateOne({ _id: phone }, { $set: set }); } catch (e) { return res.status(e.code === 11000 ? 409 : 500).json({ ok: false, error: e.code === 11000 ? 'That username is taken' : 'Could not save' }); }
  res.json({ ok: true, ...set });
});
app.get('/find', softLimiter, async (req, res) => {
  const phone = authBearer(req); if (!phone) return res.status(401).json({ ok: false });
  const q = String(req.query.q || '').trim().toLowerCase().replace(/^@/, '');
  if (!/^[a-z0-9_.]{2,20}$/.test(q)) return res.json({ ok: true, list: [] });
  const list = await Users.find({ username: { $regex: '^' + q.replace(/[.]/g, '\\.') }, discoverable: { $ne: false }, suspended: { $ne: true }, _id: { $ne: phone }, blocked: { $ne: phone } }, { projection: { name: 1, username: 1, pv: 1, priv: 1, verifiedUntil: 1 } }).limit(10).toArray();
  res.json({ ok: true, list: list.map(u => ({ email: u._id, username: u.username, name: u.name || u.username, pv: u.priv?.photo === 'none' ? 0 : (u.pv || 0), vf: (u.verifiedUntil || 0) > Date.now() })) });
});
app.get('/', (_, res) => res.send('SORO API running'));

// ---- WebSocket: messaging, groups, call signaling ----
const server = http.createServer(app);
const wss = new WebSocketServer({ server, maxPayload: 3e6 });
const socks = new Map(), seen = new Map(), prof = new Map(), privs = new Map();
const send = (ws, o) => ws.readyState === 1 && ws.send(JSON.stringify(o));
const online = p => (socks.get(p)?.size || 0) > 0;
const toPhone = (p, o) => { if (!online(p)) return false; socks.get(p).forEach(w => send(w, o)); return true; };
// what others may see about a user, honouring that user's privacy choices ('all' or 'none')
const view = (p, d = {}) => { const pr = privs.get(p) || d.priv || {}; return { on: pr.seen === 'none' ? false : online(p), seen: pr.seen === 'none' ? null : (seen.get(p) || d.lastSeen || null), name: d.name, about: pr.about === 'none' ? undefined : d.about, pv: pr.photo === 'none' ? 0 : (d.pv || 0), vf: (d.vu ?? d.verifiedUntil ?? 0) > Date.now() }; };
const presence = p => { const o = { t: 'presence', phone: p, ...view(p, prof.get(p) || {}) };
  wss.clients.forEach(w => w.watch?.has(p) && send(w, o)); };
const gOut = g => ({ id: g._id, name: g.name, members: g.members, owner: g.owner });
const encOk = o => typeof o?.iv === 'string' && o.iv.length < 40 && typeof o?.ct === 'string' && o.ct.length < 2.8e6;
async function deliver(p, out) { // live if online, otherwise queued in MongoDB
  if (toPhone(p, out)) return true;
  if (await Queue.countDocuments({ to: p }) < 500) await Queue.insertOne({ ...out, to: p, createdAt: new Date() });
  return false;
}

const blockedBy = async (to, from) => !!(await Users.findOne({ _id: to, blocked: from }, { projection: { _id: 1 } }));
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
    if (me?.suspended) return ws.close(4001);
    ws.name = me?.name; privs.set(phone, me?.priv || {}); send(ws, { t: 'blocks', list: me?.blocked || [] }); send(ws, { t: 'me', premiumUntil: me?.premiumUntil || 0, verifiedUntil: me?.verifiedUntil || 0, username: me?.username, link: me?.link, discoverable: me?.discoverable !== false, priv: me?.priv || {}, hasPw: !!me?.pw, createdAt: me?.createdAt }); prof.set(phone, { name: me?.name, about: me?.about, pv: me?.pv || 0, vu: me?.verifiedUntil || 0 }); presence(phone);
    send(ws, { t: 'notifs', unread: await Notifs.countDocuments({ to: phone, read: false }) });
    send(ws, { t: 'groups', list: (await Groups.find({ members: phone }).toArray()).map(gOut) });
    const q = await Queue.find({ to: phone }).sort({ createdAt: 1 }).toArray();
    if (q.length) {
      await Queue.deleteMany({ _id: { $in: q.map(d => d._id) } });
      for (const d of q) { const { _id, to, createdAt, ...msg } = d; send(ws, msg); if (msg.t === 'msg') toPhone(msg.from, { t: 'st', id: msg.id, by: phone, st: 'delivered', gid: msg.gid }); }
    }
  })().catch(console.error);

  async function handle(raw) {
    let m; try { m = JSON.parse(raw); } catch { return; }
    if (m.t === 'key') {
      const k = m.pub; if (k?.kty === 'EC' && k.crv === 'P-256' && typeof k.x === 'string' && typeof k.y === 'string' && k.x.length < 100 && k.y.length < 100)
        await Users.updateOne({ _id: phone }, { $set: { pub: { kty: 'EC', crv: 'P-256', x: k.x, y: k.y } } });
    } else if (m.t === 'profile') {
      ws.name = String(m.name || '').slice(0, 30);
      const about = String(m.about || '').slice(0, 80);
      await Users.updateOne({ _id: phone }, { $set: { name: ws.name, about } });
      prof.set(phone, { ...(prof.get(phone) || {}), name: ws.name, about }); presence(phone);
    } else if (m.t === 'lookup' && idOk(m.phone)) {
      const u = await Users.findOne({ _id: m.phone });
      send(ws, { t: 'lookup', phone: m.phone, found: !!u, name: u?.name, pub: u?.pub });
    } else if (m.t === 'watch' && Array.isArray(m.phones)) {
      const ps = m.phones.filter(idOk).slice(0, 500); ps.forEach(p => ws.watch.add(p));
      const docs = Object.fromEntries((await Users.find({ _id: { $in: ps } }, { projection: { lastSeen: 1, name: 1, about: 1, pv: 1, priv: 1, verifiedUntil: 1 } }).toArray()).map(d => [d._id, d]));
      ps.forEach(p => send(ws, { t: 'presence', phone: p, ...view(p, docs[p] || {}) }));
    } else if (m.t === 'typing' && idOk(m.to)) toPhone(m.to, { t: 'typing', from: phone });
    else if (m.t === 'read' && idOk(m.to) && Array.isArray(m.ids)) m.ids.slice(0, 200).forEach(id => toPhone(m.to, { t: 'st', id, by: phone, st: 'read', gid: typeof m.gid === 'string' ? m.gid.slice(0, 20) : undefined }));
    else if (m.t === 'msg' && idOk(m.to) && encOk(m) && await Users.countDocuments({ _id: m.to })) {
      if (await blockedBy(m.to, phone)) return; // recipient blocked this sender
      const out = { t: 'msg', id: String(m.id).slice(0, 40), from: phone, name: ws.name, iv: m.iv, ct: m.ct, ts: Date.now() };
      if (await deliver(m.to, out)) send(ws, { t: 'st', id: out.id, by: m.to, st: 'delivered' });
    } else if (m.t === 'gnew') {
      const name = String(m.name || '').trim().slice(0, 40);
      let mem = [...new Set([phone, ...(Array.isArray(m.members) ? m.members.filter(idOk) : [])])].slice(0, 15);
      mem = (await Users.find({ _id: { $in: mem }, $or: [{ _id: phone }, { 'priv.groups': { $ne: 'none' } }] }, { projection: { _id: 1 } }).toArray()).map(d => d._id);
      if (!name || mem.length < 3 || !mem.includes(phone)) return;
      const g = { _id: randomUUID().slice(0, 12), name, members: mem, owner: phone, createdAt: new Date() };
      await Groups.insertOne(g); mem.forEach(p => toPhone(p, { t: 'group', g: gOut(g) }));
    } else if (m.t === 'gmsg' && m.copies && typeof m.copies === 'object') {
      const g = await Groups.findOne({ _id: String(m.gid), members: phone }); if (!g) return;
      for (const [p, c] of Object.entries(m.copies)) if (p !== phone && g.members.includes(p) && encOk(c) && !(await blockedBy(p, phone)))
        if (await deliver(p, { t: 'msg', id: String(m.id).slice(0, 40), from: phone, name: ws.name, gid: g._id, iv: c.iv, ct: c.ct, ts: Date.now() }))
          send(ws, { t: 'st', id: String(m.id).slice(0, 40), by: p, st: 'delivered', gid: g._id });
    } else if (m.t === 'block' && idOk(m.phone) && m.phone !== phone) {
      await Users.updateOne({ _id: phone }, m.on ? { $addToSet: { blocked: m.phone } } : { $pull: { blocked: m.phone } });
    } else if (m.t === 'report' && idOk(m.phone)) {
      if (await Reports.countDocuments({ reporter: phone, createdAt: { $gt: Date.now() - 86400000 } }) >= 10) return;
      await Reports.insertOne({ reporter: phone, target: m.phone, reason: String(m.reason || '').slice(0, 40), note: String(m.note || '').slice(0, 500),
        evidence: (Array.isArray(m.evidence) ? m.evidence : []).slice(0, 5).map(x => String(x).slice(0, 300)), createdAt: Date.now(), status: 'open' });
    } else if (m.t === 'del' && Array.isArray(m.ids)) { // delete for everyone (sender only)
      const ids = m.ids.slice(0, 50).map(x => String(x).slice(0, 40));
      const targets = m.gid ? ((await Groups.findOne({ _id: String(m.gid), members: phone }))?.members.filter(p => p !== phone) || []) : (idOk(m.to) ? [m.to] : []);
      for (const p of targets) {
        await Queue.deleteMany({ to: p, from: phone, t: 'msg', id: { $in: ids } }); // not yet delivered: just drop it
        await deliver(p, { t: 'del', from: phone, ids, gid: m.gid ? String(m.gid) : undefined, ts: Date.now() });
      }
    } else if (m.t === 'stories' && Array.isArray(m.owners)) {
      const owners = m.owners.filter(idOk).slice(0, 500);
      send(ws, { t: 'stories', list: (await Stories.find({ owner: { $in: [...owners, phone] }, expiresAt: { $gt: new Date() } }).toArray()).map(sOut) });
    } else if (m.t === 'sdel') {
      const d = await Stories.findOneAndDelete({ _id: String(m.id), owner: phone });
      if (d) { if (d.media) await Media.deleteOne({ _id: d.media }); const o = { t: 'sdel', id: d._id }; wss.clients.forEach(w => w.watch?.has(phone) && send(w, o)); toPhone(phone, o); }
    } else if (m.t === 'gedit') { // owner renames group / adds / removes members
      const g = await Groups.findOne({ _id: String(m.gid), owner: phone }); if (!g) return;
      const name = typeof m.name === 'string' && m.name.trim() ? m.name.trim().slice(0, 40) : g.name;
      const rm = new Set((Array.isArray(m.remove) ? m.remove : []).filter(p => p !== phone));
      const add = (await Users.find({ _id: { $in: (Array.isArray(m.add) ? m.add : []).filter(idOk) }, 'priv.groups': { $ne: 'none' } }, { projection: { _id: 1 } }).toArray()).map(d => d._id);
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
      if (await blockedBy(m.to, phone)) return;
      if (!toPhone(m.to, { t: 'call', from: phone, k: m.k, d: m.d, video: !!m.video }) && m.k === 'offer') {
        send(ws, { t: 'call', from: m.to, k: 'unavail' });
        await deliver(m.to, { t: 'missed', from: phone, video: !!m.video, ts: Date.now() }); // they see it as a missed call later
      }
    }
  }
  ws.on('message', raw => { chain = chain.then(() => handle(raw)).catch(console.error); });
  ws.on('close', () => {
    socks.get(phone)?.delete(ws);
    if (!online(phone)) { for (const gid of [...gcalls.keys()]) gLeave(phone, gid); const t = Date.now(); seen.set(phone, t); Users.updateOne({ _id: phone }, { $set: { lastSeen: t } }).catch(() => {}); presence(phone); }
  });
});

server.listen(process.env.PORT || 3000);
