// Cerberion CRM - API + Static server
// Serves the single-file HTML app and a JSON-backed shared store for the whole team.
// Persistent storage on Railway Volume mounted at /data (or ./data in local dev).

const express = require("express");
const compression = require("compression");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || (fs.existsSync("/data") ? "/data" : path.join(__dirname, "data"));
const STATE_FILE = path.join(DATA_DIR, "state.json");
const AUTH_FILE = path.join(DATA_DIR, "auth.json");
const JWT_SECRET = process.env.JWT_SECRET || "cerberion-default-secret-change-me-in-railway-env-vars";

try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch (e) {}

// ---------- Helpers ----------
const readJson = (file, fallback) => {
  try { return JSON.parse(fs.readFileSync(file, "utf8")); }
  catch (e) { return fallback; }
};
const writeJsonAtomic = (file, data) => {
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, file);
};
const uid = (p) => `${p}_${Date.now().toString(36)}_${crypto.randomBytes(4).toString("hex")}`;
const sha256 = (txt) => crypto.createHash("sha256").update(txt + "::cerberion-salt").digest("hex");
const nowISO = () => new Date().toISOString();

// Minimal JWT (HS256) — no external lib
const b64url = (buf) => Buffer.from(buf).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
const b64urlDecode = (s) => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
const signToken = (payload, ttlSec = 60*60*24*30) => {
  const header = { alg: "HS256", typ: "JWT" };
  const data = { ...payload, iat: Math.floor(Date.now()/1000), exp: Math.floor(Date.now()/1000) + ttlSec };
  const h = b64url(JSON.stringify(header));
  const p = b64url(JSON.stringify(data));
  const sig = b64url(crypto.createHmac("sha256", JWT_SECRET).update(`${h}.${p}`).digest());
  return `${h}.${p}.${sig}`;
};
const verifyToken = (token) => {
  try {
    if (!token) return null;
    const [h, p, sig] = token.split(".");
    if (!h || !p || !sig) return null;
    const expectedSig = b64url(crypto.createHmac("sha256", JWT_SECRET).update(`${h}.${p}`).digest());
    if (expectedSig !== sig) return null;
    const payload = JSON.parse(b64urlDecode(p).toString());
    if (payload.exp && Date.now()/1000 > payload.exp) return null;
    return payload;
  } catch (e) { return null; }
};

// ---------- State (CRM data) ----------
const emptyState = () => ({
  version: 3,
  clients: [], prospects: [], quotes: [], invoices: [],
  tasks: [], activities: [], notifications: [],
  products: [],
  settings: { vat: 17 },
  updatedAt: nowISO(),
});
let stateCache = readJson(STATE_FILE, null);
if (!stateCache) { stateCache = emptyState(); writeJsonAtomic(STATE_FILE, stateCache); }
// Backfill new fields if state was created with an older shape
if (!Array.isArray(stateCache.products)) stateCache.products = [];

// ---------- Auth (users + invitations) ----------
const emptyAuth = () => ({ users: [], invitations: [], sessions: [] });
let authCache = readJson(AUTH_FILE, null);
if (!authCache) { authCache = emptyAuth(); writeJsonAtomic(AUTH_FILE, authCache); }

const sanitizeUser = (u) => ({
  id: u.id, email: u.email, name: u.name, position: u.position || "",
  role: u.role, createdAt: u.createdAt, lastLogin: u.lastLogin || null,
});

// ---------- Middleware ----------
app.use(express.json({ limit: "5mb" }));
app.use(compression());

const authRequired = (req, res, next) => {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  const payload = verifyToken(token);
  if (!payload || !payload.uid) return res.status(401).json({ error: "unauthorized" });
  const user = authCache.users.find(u => u.id === payload.uid);
  if (!user) return res.status(401).json({ error: "user not found" });
  req.user = user;
  next();
};

const adminRequired = (req, res, next) => {
  if (req.user?.role !== "admin") return res.status(403).json({ error: "admin only" });
  next();
};

// ---------- Auth API ----------
app.get("/api/auth/me", authRequired, (req, res) => res.json({ user: sanitizeUser(req.user) }));

app.get("/api/auth/users", authRequired, (_req, res) => {
  res.json({ users: authCache.users.map(sanitizeUser) });
});

app.post("/api/auth/signup", (req, res) => {
  const { email, name, password, position, role, inviteToken } = req.body || {};
  if (!email || !name || !password) return res.status(400).json({ error: "Tous les champs sont requis" });
  if (password.length < 6) return res.status(400).json({ error: "Mot de passe trop court (6 caractères min)" });
  const e = String(email).trim().toLowerCase();
  if (authCache.users.find(u => u.email === e)) return res.status(400).json({ error: "Email déjà utilisé" });

  let finalRole = "commercial";
  let invitation = null;
  if (authCache.users.length === 0) {
    finalRole = "admin"; // first user is always admin
  } else if (inviteToken) {
    invitation = authCache.invitations.find(i => i.token === inviteToken && !i.usedAt);
    if (!invitation) return res.status(400).json({ error: "Invitation invalide ou déjà utilisée" });
    finalRole = invitation.role || "commercial";
  } else if (["manager", "commercial", "technicien"].includes(role)) {
    finalRole = role;
  }

  const user = {
    id: uid("usr"),
    email: e,
    name: String(name).trim(),
    position: String(position || invitation?.position || "").trim(),
    role: finalRole,
    passwordHash: sha256(password),
    createdAt: nowISO(),
    lastLogin: nowISO(),
    invitedBy: invitation?.createdBy || null,
  };
  authCache.users.push(user);
  if (invitation) {
    invitation.usedAt = nowISO();
    invitation.usedBy = user.id;
  }
  writeJsonAtomic(AUTH_FILE, authCache);

  const token = signToken({ uid: user.id });
  res.json({ token, user: sanitizeUser(user) });
});

app.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Email et mot de passe requis" });
  const e = String(email).trim().toLowerCase();
  const user = authCache.users.find(u => u.email === e);
  if (!user) return res.status(401).json({ error: "Email introuvable" });
  if (sha256(password) !== user.passwordHash) return res.status(401).json({ error: "Mot de passe incorrect" });
  user.lastLogin = nowISO();
  writeJsonAtomic(AUTH_FILE, authCache);
  const token = signToken({ uid: user.id });
  res.json({ token, user: sanitizeUser(user) });
});

// Admin: update user
app.patch("/api/auth/users/:id", authRequired, adminRequired, (req, res) => {
  const u = authCache.users.find(u => u.id === req.params.id);
  if (!u) return res.status(404).json({ error: "Not found" });
  const { role, name, position } = req.body || {};
  if (role && ["admin","manager","commercial","technicien"].includes(role)) u.role = role;
  if (name != null) u.name = String(name).trim();
  if (position != null) u.position = String(position).trim();
  writeJsonAtomic(AUTH_FILE, authCache);
  res.json({ user: sanitizeUser(u) });
});

// Admin: change another user's password
app.post("/api/auth/users/:id/password", authRequired, adminRequired, (req, res) => {
  const u = authCache.users.find(u => u.id === req.params.id);
  if (!u) return res.status(404).json({ error: "Not found" });
  const { password } = req.body || {};
  if (!password || password.length < 6) return res.status(400).json({ error: "6 caractères minimum" });
  u.passwordHash = sha256(password);
  writeJsonAtomic(AUTH_FILE, authCache);
  res.json({ ok: true });
});

// Admin: delete user
app.delete("/api/auth/users/:id", authRequired, adminRequired, (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: "Vous ne pouvez pas vous supprimer" });
  authCache.users = authCache.users.filter(u => u.id !== req.params.id);
  writeJsonAtomic(AUTH_FILE, authCache);
  res.json({ ok: true });
});

// Admin: invitations
app.get("/api/invitations", authRequired, adminRequired, (_req, res) => res.json({ invitations: authCache.invitations }));
app.post("/api/invitations", authRequired, adminRequired, (req, res) => {
  const { email, role, position } = req.body || {};
  const inv = {
    id: uid("inv"),
    email: String(email || "").trim().toLowerCase(),
    role: role || "commercial",
    position: String(position || "").trim(),
    token: crypto.randomBytes(16).toString("hex"),
    createdAt: nowISO(),
    createdBy: req.user.id,
    usedAt: null, usedBy: null,
  };
  authCache.invitations.push(inv);
  writeJsonAtomic(AUTH_FILE, authCache);
  res.json({ invitation: inv });
});
app.delete("/api/invitations/:id", authRequired, adminRequired, (req, res) => {
  authCache.invitations = authCache.invitations.filter(i => i.id !== req.params.id);
  writeJsonAtomic(AUTH_FILE, authCache);
  res.json({ ok: true });
});

// Public: check if invitation token is valid (used by signup form)
app.get("/api/invitations/check/:token", (req, res) => {
  const inv = authCache.invitations.find(i => i.token === req.params.token && !i.usedAt);
  if (!inv) return res.status(404).json({ error: "Invitation invalide" });
  res.json({ invitation: { email: inv.email, role: inv.role, position: inv.position } });
});

// ---------- State API (CRM data) ----------
app.get("/api/state", authRequired, (_req, res) => res.json({ state: stateCache }));

// Patch endpoints: granular updates to avoid race conditions
// Each entity has its own endpoints. The frontend dispatches "actions" that the server applies.
app.post("/api/state/dispatch", authRequired, (req, res) => {
  const { action, payload } = req.body || {};
  if (!action) return res.status(400).json({ error: "missing action" });

  const userId = req.user.id;
  const now = nowISO();
  const newUid = (p) => `${p}_${Date.now().toString(36)}_${crypto.randomBytes(4).toString("hex")}`;
  const findById = (arr, id) => arr.find(x => x.id === id);

  try {
    switch (action) {
      // Clients
      case "upsertClient": {
        const data = payload;
        if (data.id && findById(stateCache.clients, data.id)) {
          stateCache.clients = stateCache.clients.map(c => c.id === data.id ? { ...c, ...data } : c);
        } else {
          const id = data.id || newUid("cli");
          stateCache.clients.push({ ...data, id, createdAt: now, createdBy: userId });
          stateCache.activities.unshift({ id: newUid("a"), type: "client_created", title: "Nouveau client", description: `${data.name} ajouté`, clientId: id, createdAt: now, createdBy: userId });
        }
        break;
      }
      case "deleteClient": {
        const id = payload.id;
        stateCache.clients = stateCache.clients.filter(c => c.id !== id);
        stateCache.quotes = stateCache.quotes.map(q => q.clientId === id ? { ...q, clientId: null } : q);
        stateCache.tasks = stateCache.tasks.map(t => t.clientId === id ? { ...t, clientId: null } : t);
        break;
      }
      // Prospects
      case "upsertProspect": {
        const data = payload;
        if (data.id && findById(stateCache.prospects, data.id)) {
          stateCache.prospects = stateCache.prospects.map(p => p.id === data.id ? { ...p, ...data } : p);
        } else {
          const id = data.id || newUid("pro");
          stateCache.prospects.push({ ...data, id, createdAt: now, createdBy: userId, stage: data.stage || "contact" });
          stateCache.activities.unshift({ id: newUid("a"), type: "prospect_created", title: "Nouveau prospect", description: `${data.name} ajouté au pipeline`, prospectId: id, createdAt: now, createdBy: userId });
        }
        break;
      }
      case "deleteProspect": {
        const id = payload.id;
        stateCache.prospects = stateCache.prospects.filter(p => p.id !== id);
        stateCache.quotes = stateCache.quotes.map(q => q.prospectId === id ? { ...q, prospectId: null } : q);
        stateCache.tasks = stateCache.tasks.map(t => t.prospectId === id ? { ...t, prospectId: null } : t);
        break;
      }
      case "moveProspectStage": {
        const { id, stage } = payload;
        const p = findById(stateCache.prospects, id);
        if (!p || p.stage === stage) break;
        const oldStage = p.stage;
        stateCache.prospects = stateCache.prospects.map(x => x.id === id ? { ...x, stage } : x);
        stateCache.activities.unshift({ id: newUid("a"), type: "stage_changed", title: "Étape changée", description: `${p.name} : ${oldStage} → ${stage}`, prospectId: id, createdAt: now, createdBy: userId });
        if (stage === "gagne" && !findById(stateCache.clients, p.id)) {
          stateCache.clients.push({ id: p.id, name: p.name, type: p.type, contact: p.contact, email: p.email, phone: p.phone, address: p.address, city: p.city, zip: p.zip, country: p.country, vat: p.vat || "", tags: p.tags || [], notes: p.notes || "", createdAt: now, createdBy: userId });
          stateCache.notifications.unshift({ id: newUid("n"), type: "prospect_won", title: "Prospect converti", message: `${p.name} est devenu client !`, readBy: [], createdAt: now, link: { page: "clients", id: p.id } });
        }
        break;
      }
      // Quotes
      case "upsertQuote": {
        const data = payload;
        if (data.id && findById(stateCache.quotes, data.id)) {
          stateCache.quotes = stateCache.quotes.map(q => q.id === data.id ? { ...q, ...data } : q);
        } else {
          const id = data.id || newUid("q");
          stateCache.quotes.push({ ...data, id, createdAt: now, createdBy: userId, status: data.status || "brouillon" });
        }
        break;
      }
      case "deleteQuote": {
        stateCache.quotes = stateCache.quotes.filter(q => q.id !== payload.id);
        break;
      }
      case "setQuoteStatus": {
        const { id, status, extra } = payload;
        const q = findById(stateCache.quotes, id);
        if (!q) break;
        const next = { ...q, status, ...(extra||{}) };
        stateCache.quotes = stateCache.quotes.map(x => x.id === id ? next : x);
        if (status === "envoye" && q.status !== "envoye") {
          stateCache.activities.unshift({ id: newUid("a"), type: "quote_sent", title: "Devis envoyé", description: `Devis ${q.number} envoyé`, clientId: q.clientId, prospectId: q.prospectId, quoteId: q.id, createdAt: now, createdBy: userId });
        } else if (status === "signe") {
          stateCache.activities.unshift({ id: newUid("a"), type: "quote_signed", title: "Devis signé", description: `Devis ${q.number} signé par ${extra?.signedBy || "client"}`, clientId: q.clientId, prospectId: q.prospectId, quoteId: q.id, createdAt: now, createdBy: userId });
          stateCache.notifications.unshift({ id: newUid("n"), type: "quote_signed", title: "Devis signé !", message: `${extra?.signedBy || "Le client"} a signé le devis ${q.number}`, readBy: [], createdAt: now, link: { page: "devis", id: q.id } });
        } else if (status === "perdu") {
          stateCache.activities.unshift({ id: newUid("a"), type: "quote_lost", title: "Devis perdu", description: `Devis ${q.number} perdu — ${extra?.lostReason || "raison non précisée"}`, clientId: q.clientId, prospectId: q.prospectId, quoteId: q.id, createdAt: now, createdBy: userId });
        }
        break;
      }
      // Invoices
      case "upsertInvoice": {
        const data = payload;
        if (data.id && findById(stateCache.invoices, data.id)) {
          stateCache.invoices = stateCache.invoices.map(i => i.id === data.id ? { ...i, ...data } : i);
        } else {
          stateCache.invoices.push({ ...data, id: data.id || newUid("inv"), createdAt: now, createdBy: userId, status: data.status || "brouillon" });
        }
        break;
      }
      case "deleteInvoice": {
        stateCache.invoices = stateCache.invoices.filter(i => i.id !== payload.id);
        break;
      }
      case "setInvoiceStatus": {
        const { id, status, extra } = payload;
        const inv = findById(stateCache.invoices, id);
        if (!inv) break;
        stateCache.invoices = stateCache.invoices.map(x => x.id === id ? { ...x, status, ...(extra||{}) } : x);
        if (status === "payee") {
          stateCache.activities.unshift({ id: newUid("a"), type: "invoice_paid", title: "Facture payée", description: `Facture ${inv.number} encaissée`, clientId: inv.clientId, createdAt: now, createdBy: userId });
        }
        break;
      }
      case "generateInvoiceFromQuote": {
        const q = findById(stateCache.quotes, payload.quoteId);
        if (!q) break;
        const exists = stateCache.invoices.find(inv => inv.quoteId === q.id);
        if (exists) break;
        // Propagate VAT rate from the source quote (fallback to settings default, then LU 17%)
        const vatRate = q.vat != null ? Number(q.vat)
                      : (stateCache.settings && stateCache.settings.vat != null ? Number(stateCache.settings.vat) : 17);
        stateCache.invoices.push({
          id: newUid("inv"),
          number: payload.number,
          quoteId: q.id, clientId: q.clientId, prospectId: q.prospectId,
          title: q.title, lines: q.lines, discount: q.discount || 0,
          subTotal: q.subTotal, ht: q.ht, tva: q.tva, ttc: q.ttc, vat: vatRate,
          issueDate: now, dueDate: payload.dueDate, status: "brouillon",
          paidAt: null, paymentMethod: null,
          notes: q.notes, terms: payload.terms || "Paiement à 30 jours fin de mois.",
          createdAt: now, createdBy: userId,
        });
        break;
      }
      // Tasks
      case "upsertTask": {
        const data = payload;
        if (data.id && findById(stateCache.tasks, data.id)) {
          stateCache.tasks = stateCache.tasks.map(t => t.id === data.id ? { ...t, ...data } : t);
        } else {
          stateCache.tasks.push({ ...data, id: data.id || newUid("t"), createdAt: now, createdBy: userId, status: data.status || "open" });
        }
        break;
      }
      case "deleteTask": {
        stateCache.tasks = stateCache.tasks.filter(t => t.id !== payload.id);
        break;
      }
      case "toggleTask": {
        stateCache.tasks = stateCache.tasks.map(t => t.id === payload.id ? { ...t, status: t.status === "done" ? "open" : "done" } : t);
        break;
      }
      // Notifications
      case "markNotifRead": {
        const n = findById(stateCache.notifications, payload.id);
        if (n && !(n.readBy||[]).includes(userId)) {
          n.readBy = [...(n.readBy||[]), userId];
        }
        break;
      }
      case "markAllNotifsRead": {
        stateCache.notifications = stateCache.notifications.map(n => ({ ...n, readBy: Array.from(new Set([...(n.readBy||[]), userId])) }));
        break;
      }
      case "deleteNotif": {
        stateCache.notifications = stateCache.notifications.filter(n => n.id !== payload.id);
        break;
      }
      // Products (catalogue)
      case "upsertProduct": {
        const data = payload;
        const products = stateCache.products || [];
        if (data.id) {
          stateCache.products = products.map(p => p.id === data.id ? { ...p, ...data, updatedAt: now } : p);
        } else {
          stateCache.products = [...products, { ...data, id: uid("prod"), createdAt: now, updatedAt: now, createdBy: req.user.id }];
        }
        break;
      }
      case "deleteProduct": {
        stateCache.products = (stateCache.products || []).filter(p => p.id !== payload.id);
        break;
      }
      // Settings
      case "updateSettings": {
        stateCache.settings = { ...stateCache.settings, ...payload };
        break;
      }
      // Reset (admin only)
      case "resetAll": {
        if (req.user.role !== "admin") return res.status(403).json({ error: "admin only" });
        stateCache = emptyState();
        break;
      }
      default:
        return res.status(400).json({ error: "unknown action" });
    }
    stateCache.updatedAt = now;
    writeJsonAtomic(STATE_FILE, stateCache);
    res.json({ state: stateCache });
  } catch (err) {
    console.error("dispatch error", err);
    res.status(500).json({ error: "server error" });
  }
});

// Public read for signature page (single quote by id)
app.get("/api/public/quote/:id", (req, res) => {
  const q = stateCache.quotes.find(x => x.id === req.params.id);
  if (!q) return res.status(404).json({ error: "not found" });
  const recipient = q.clientId ? stateCache.clients.find(c => c.id === q.clientId) : q.prospectId ? stateCache.prospects.find(p => p.id === q.prospectId) : null;
  res.json({ quote: q, recipient, settings: stateCache.settings });
});

// Public sign endpoint
app.post("/api/public/quote/:id/sign", (req, res) => {
  const { signedBy, signatureData } = req.body || {};
  if (!signedBy) return res.status(400).json({ error: "signedBy required" });
  const q = stateCache.quotes.find(x => x.id === req.params.id);
  if (!q) return res.status(404).json({ error: "not found" });
  q.status = "signe";
  q.signedAt = nowISO();
  q.signedBy = signedBy;
  q.signatureMethod = "lien";
  q.signatureData = signatureData || signedBy;
  stateCache.activities.unshift({ id: uid("a"), type: "quote_signed", title: "Devis signé", description: `Devis ${q.number} signé par ${signedBy}`, clientId: q.clientId, prospectId: q.prospectId, quoteId: q.id, createdAt: nowISO() });
  stateCache.notifications.unshift({ id: uid("n"), type: "quote_signed", title: "Devis signé !", message: `${signedBy} a signé le devis ${q.number}`, readBy: [], createdAt: nowISO(), link: { page: "devis", id: q.id } });
  stateCache.updatedAt = nowISO();
  writeJsonAtomic(STATE_FILE, stateCache);
  res.json({ ok: true });
});

// ---------- Static + health ----------
app.use(express.static(path.join(__dirname, "public"), {
  maxAge: "1h",
  setHeaders: (res, filePath) => {
    if (filePath.endsWith(".html")) {
      res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    }
  }
}));

app.get("/health", (_req, res) => res.status(200).send("ok"));

// SPA fallback for non-API routes
app.get(/^(?!\/api).*/, (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`Cerberion CRM running on port ${PORT}`);
  console.log(`Data directory: ${DATA_DIR}`);
  console.log(`Users: ${authCache.users.length} · Clients: ${stateCache.clients.length} · Quotes: ${stateCache.quotes.length}`);
});
