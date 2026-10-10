import { getStore } from '@netlify/blobs';
import { createHash, createHmac, randomBytes, randomUUID, scryptSync, timingSafeEqual } from 'node:crypto';

export const config = { path: '/api/*' };

const CATS = ['Mode', 'Beauté', 'Électronique', 'Maison', 'Alimentation', 'Services', 'Produits numériques', 'Autres'];
const PAYS = ['Wave', 'Orange Money', 'Carte bancaire', 'Paiement à la livraison', 'Discussion avec le vendeur'];
const STATUSES = ['En attente', 'Confirmée', 'Expédiée', 'Livrée', 'Annulée'];

class Err extends Error { constructor(m, s = 400) { super(m); this.s = s; } }
const need = (c, m, s) => { if (!c) throw new Err(m, s); };
const json = (d, s = 200) => Response.json(d, { status: s });
const str = (v, max = 200) => String(v ?? '').trim().slice(0, max);
const newId = (p) => p + randomUUID().replace(/-/g, '').slice(0, 12);

// ---- Base de données (Netlify Blobs) ----
const store = () => getStore({ name: 'louma', consistency: 'strong' });
const get = (k) => store().get(k, { type: 'json' });
const put = (k, v) => store().setJSON(k, v);
const list = async (prefix) => {
  const { blobs } = await store().list({ prefix });
  return (await Promise.all(blobs.map((b) => get(b.key)))).filter(Boolean);
};

// ---- Sécurité : mots de passe (scrypt) et jetons signés (HMAC-SHA256) ----
const hash = (pw) => { const salt = randomBytes(16); return salt.toString('hex') + ':' + scryptSync(pw, salt, 64).toString('hex'); };
const check = (pw, h) => { const [s, k] = h.split(':'); return timingSafeEqual(scryptSync(pw, Buffer.from(s, 'hex'), 64), Buffer.from(k, 'hex')); };
const same = (a, b) => timingSafeEqual(createHash('sha256').update(String(a)).digest(), createHash('sha256').update(String(b)).digest());
const secret = () => { const s = process.env.JWT_SECRET; need(s && s.length >= 16, 'Serveur mal configuré : JWT_SECRET manquant', 500); return s; };
const sign = (payload, ttl = 7 * 86400) => {
  const body = Buffer.from(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + ttl })).toString('base64url');
  return body + '.' + createHmac('sha256', secret()).update(body).digest('base64url');
};
const verify = (token) => {
  const [body, sig] = String(token || '').split('.');
  if (!body || !sig) return null;
  const good = createHmac('sha256', secret()).update(body).digest('base64url');
  if (sig.length !== good.length || !timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return null;
  const p = JSON.parse(Buffer.from(body, 'base64url').toString());
  return p.exp > Date.now() / 1000 ? p : null;
};
const auth = (req, role) => {
  const p = verify((req.headers.get('authorization') || '').replace('Bearer ', ''));
  need(p && p.role === role, 'Session expirée, reconnectez-vous.', 401);
  return p;
};
const seller = async (req) => { const u = await get('u:' + auth(req, 'seller').uid); need(u, 'Non autorisé', 401); return u; };

const safeUser = ({ password, ...u }) => u;
const pub = ({ id, name, category, city, description }) => ({ id, name, category, city, description });
const settings = async () => (await get('settings')) || { subscriptionPaid: false, monthly: 2000, annual: 20000 };

async function seed() {
  await put('s:demo', { id: 'demo', name: 'LOUMA Store', owner: 'Vendeur Démo', category: 'Mode', city: 'Dakar', description: 'Boutique de démonstration' });
  for (const [i, name, price, cat, stock, e] of [
    ['p1', 'T-shirt Sénégal', 8500, 'Mode', 20, '👕'], ['p2', 'Gloss brillant', 5000, 'Beauté', 15, '💄'],
    ['p3', 'Écouteurs Bluetooth', 12000, 'Électronique', 10, '🎧'], ['p4', 'Lampe LED', 7500, 'Maison', 12, '💡'],
  ]) await put('p:' + i, { id: i, shop: 'demo', name, price, cat, stock, e });
  await put('settings', { subscriptionPaid: false, monthly: 2000, annual: 20000 });
}

export default async (req) => {
  const path = new URL(req.url).pathname.replace(/^\/api/, '') || '/';
  const m = req.method, route = m + ' ' + path;
  try {
    const b = ['POST', 'PUT'].includes(m) ? await req.json().catch(() => ({})) : {};
    let r;

    // ----- Public -----
    if (route === 'GET /bootstrap') {
      if (!(await get('settings'))) await seed();
      const [shops, products] = await Promise.all([list('s:'), list('p:')]);
      const live = shops.filter((s) => !s.suspended), ok = new Set(live.map((s) => s.id));
      return json({ shops: live.map(pub), products: products.filter((p) => ok.has(p.shop)), settings: await settings() });
    }

    if (route === 'POST /register') {
      const email = str(b.email).toLowerCase(), pw = String(b.password || '');
      need(/^\S+@\S+\.\S+$/.test(email), 'E-mail invalide');
      need(pw.length >= 6, 'Mot de passe trop court (6 caractères minimum)');
      need(str(b.name) && str(b.phone) && str(b.shopName), 'Champs obligatoires manquants');
      need(!(await get('e:' + email)), 'Cet e-mail existe déjà.', 409);
      const shop = { id: newId('s'), name: str(b.shopName, 80), owner: str(b.name, 80), category: CATS.includes(b.category) ? b.category : 'Autres', city: str(b.city, 60), description: str(b.description, 500) || 'Boutique LOUMA SN', phone: str(b.phone, 30), email };
      const user = { id: newId('u'), name: shop.owner, phone: shop.phone, email, password: hash(pw), shop: shop.id };
      await put('s:' + shop.id, shop); await put('u:' + user.id, user); await put('e:' + email, user.id);
      return json({ token: sign({ role: 'seller', uid: user.id }) });
    }

    if (route === 'POST /login') {
      const id = await get('e:' + str(b.email).toLowerCase()), u = id && (await get('u:' + id));
      need(u && check(String(b.password || ''), u.password), 'Identifiants incorrects.', 401);
      return json({ token: sign({ role: 'seller', uid: u.id }) });
    }

    if (route === 'POST /orders') {
      const items = Array.isArray(b.items) ? b.items.slice(0, 50) : [];
      need(items.length, 'Panier vide');
      need(str(b.buyer) && str(b.phone) && str(b.address), 'Nom, téléphone et adresse requis');
      need(PAYS.includes(b.payment), 'Mode de paiement invalide');
      const qty = {};
      for (const it of items) qty[it.product] = (qty[it.product] || 0) + Math.round(+it.qty);
      const groups = {};
      for (const [pid, q] of Object.entries(qty)) {           // 1) on vérifie tout (prix et stock viennent du serveur)
        const p = await get('p:' + pid);
        need(p && q > 0, 'Produit introuvable', 404);
        const sh = await get('s:' + p.shop);
        need(sh && !sh.suspended, 'Boutique indisponible');
        need(p.stock >= q, 'Stock insuffisant : ' + p.name);
        (groups[p.shop] ||= []).push({ p, q });
      }
      const created = [];
      for (const [shop, rows] of Object.entries(groups)) {    // 2) puis on enregistre
        for (const { p, q } of rows) { p.stock -= q; await put('p:' + p.id, p); }
        const o = { id: 'CMD-' + randomUUID().slice(0, 8).toUpperCase(), shop, buyer: str(b.buyer, 80), phone: str(b.phone, 30), address: str(b.address, 300), payment: b.payment, items: rows.map(({ p, q }) => ({ product: p.id, name: p.name, price: p.price, qty: q })), total: rows.reduce((t, { p, q }) => t + p.price * q, 0), status: 'En attente', date: new Date().toISOString() };
        await put('o:' + o.id, o); created.push(o);
      }
      return json({ orders: created });
    }

    if (route === 'POST /orders/lookup') {
      const ids = (Array.isArray(b.ids) ? b.ids : []).slice(-50).filter((i) => /^CMD-[A-Z0-9]+$/.test(i));
      const orders = (await Promise.all(ids.map((i) => get('o:' + i)))).filter(Boolean).map(({ id, shop, total, payment, status, date }) => ({ id, shop, total, payment, status, date }));
      return json({ orders });
    }

    // ----- Vendeur connecté -----
    if (route === 'GET /me') {
      const u = await seller(req);
      const [shop, products, orders] = await Promise.all([get('s:' + u.shop), list('p:'), list('o:')]);
      return json({ me: safeUser(u), shop, products: products.filter((p) => p.shop === u.shop), orders: orders.filter((o) => o.shop === u.shop).sort((x, y) => y.date.localeCompare(x.date)) });
    }

    if (route === 'PUT /shop') {
      const u = await seller(req), s = await get('s:' + u.shop);
      Object.assign(s, { name: str(b.name, 80) || s.name, category: CATS.includes(b.category) ? b.category : s.category, city: str(b.city, 60), description: str(b.description, 500) });
      await put('s:' + s.id, s);
      return json(s);
    }

    if (route === 'POST /products') {
      const u = await seller(req), name = str(b.name, 100), price = Math.round(+b.price), stock = Math.round(+b.stock);
      need(name && price >= 0 && stock >= 0 && CATS.includes(b.cat), 'Produit invalide');
      const p = { id: newId('p'), shop: u.shop, name, price, stock, cat: b.cat, e: str(b.e, 8).replace(/[<>&"'`]/g, '') || '📦', desc: str(b.desc, 1000) };
      await put('p:' + p.id, p);
      return json(p);
    }

    if (m === 'DELETE' && (r = path.match(/^\/products\/([\w-]+)$/))) {
      const u = await seller(req), p = await get('p:' + r[1]);
      need(p && p.shop === u.shop, 'Introuvable', 404);
      await store().delete('p:' + p.id);
      return json({ ok: true });
    }

    if (m === 'PUT' && (r = path.match(/^\/orders\/([\w-]+)\/status$/))) {
      const u = await seller(req), o = await get('o:' + r[1]);
      need(o && o.shop === u.shop, 'Introuvable', 404);
      need(STATUSES.includes(b.status), 'Statut invalide');
      o.status = b.status; await put('o:' + o.id, o);
      return json({ ok: true });
    }

    // ----- Administration (identifiants dans les variables d'environnement) -----
    if (route === 'POST /admin/login') {
      need(process.env.ADMIN_USER && process.env.ADMIN_PASSWORD, "Admin non configuré sur le serveur", 500);
      const a = same(b.username, process.env.ADMIN_USER), c = same(b.password, process.env.ADMIN_PASSWORD);
      need(a && c, 'Identifiants admin incorrects.', 401);
      return json({ token: sign({ role: 'admin' }, 8 * 3600) });
    }

    if (route === 'GET /admin/data') {
      auth(req, 'admin');
      const [users, shops, products, orders] = await Promise.all(['u:', 's:', 'p:', 'o:'].map((p) => list(p)));
      return json({ users: users.map(safeUser), shops, products, orders, settings: await settings() });
    }

    if (route === 'PUT /admin/settings') {
      auth(req, 'admin');
      const s = { subscriptionPaid: !!b.subscriptionPaid, monthly: Math.max(0, +b.monthly || 0), annual: Math.max(0, +b.annual || 0) };
      await put('settings', s);
      return json(s);
    }

    if (m === 'POST' && (r = path.match(/^\/admin\/shops\/([\w-]+)\/suspend$/))) {
      auth(req, 'admin');
      const s = await get('s:' + r[1]);
      need(s, 'Introuvable', 404);
      s.suspended = !s.suspended; await put('s:' + s.id, s);
      return json(s);
    }

    throw new Err('Route introuvable', 404);
  } catch (e) {
    if (e instanceof Err) return json({ error: e.message }, e.s);
    console.error(e);
    return json({ error: 'Erreur serveur' }, 500);
  }
};
