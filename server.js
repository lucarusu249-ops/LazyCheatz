const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const helmet = require("helmet");
const fs = require("fs");
const { v4: uuidv4 } = require("uuid");

const app = express();

app.use(helmet({
  hsts: false,
  contentSecurityPolicy: false,
  crossOriginOpenerPolicy: false,
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: false
}));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("public"));

app.set("view engine", "ejs");

app.use(session({
  secret: "supersecretkey",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false,
    sameSite: "strict"
  }
}));

function loadUsers() {
  return JSON.parse(fs.readFileSync("users.json"));
}

function saveUsers(users) {
  fs.writeFileSync("users.json", JSON.stringify(users, null, 2));
}

function loadScripts() {
  return JSON.parse(fs.readFileSync("scripts.json"));
}

function loadKeys() {
  try {
    return JSON.parse(fs.readFileSync("keys.json"));
  } catch (e) {
    return [];
  }
}

function saveKeys(keys) {
  fs.writeFileSync("keys.json", JSON.stringify(keys, null, 2));
}

function loadPurchases() {
  try { return JSON.parse(fs.readFileSync("purchases.json")); } catch (e) { return []; }
}

function savePurchases(purchases) {
  fs.writeFileSync("purchases.json", JSON.stringify(purchases, null, 2));
}

function loadPromo() {
  return JSON.parse(fs.readFileSync("promo.json"));
}

function savePromo(data) {
  fs.writeFileSync("promo.json", JSON.stringify(data, null, 2));
}

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

function requireOwner(req, res, next) {
  if (!req.session.user || req.session.user.role !== "owner")
    return res.status(403).send("Access denied");
  next();
}

app.get("/", (req, res) => {
  res.redirect("/login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  // Keep existing form-based register working; map to email
  const users = loadUsers();
  const { username, password, email } = req.body;

  const userEmail = email || username;
  if (users.find(u => u.email === userEmail)) return res.send("User already exists");

  const hash = await bcrypt.hash(password, 12);

  const newUser = {
    id: uuidv4(),
    email: userEmail,
    password: hash,
    role: userEmail === "Ghosty" ? "owner" : "user",
    vipExpires: null,
    ip: null,
    device: null
  };

  users.push(newUser);
  saveUsers(users);

  res.redirect("/login");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  // Keep form-based login working (username field maps to email)
  const users = loadUsers();
  const { username, password, email } = req.body;
  const userEmail = email || username;

  const user = users.find(u => u.email === userEmail);
  if (!user) return res.send("User not found");

  // support plaintext-password users.json (old) and bcrypt hashes
  let valid = false;
  try {
    valid = await bcrypt.compare(password, user.password);
  } catch (e) {
    valid = user.password === password;
  }

  if (!valid) return res.send("Invalid credentials");

  user.ip = req.ip;
  user.device = req.headers["user-agent"];
  saveUsers(users);

  req.session.user = user;

  res.redirect("/dashboard");
});

// JSON API: Register/login for SPA (returns JSON)
app.post('/api/register', async (req, res) => {
  const users = loadUsers();
  const { email, password } = req.body;
  if (!email || !password) return res.json({ success: false, message: 'Missing fields' });
  if (users.find(u => u.email === email)) return res.json({ success: false, message: 'User exists' });
  const hash = await bcrypt.hash(password, 12);
  const newUser = { id: uuidv4(), email, password: hash, role: 'user', vipExpires: null };
  users.push(newUser);
  saveUsers(users);
  res.json({ success: true, message: 'Registered' });
});

app.post('/api/login', async (req, res) => {
  console.log('[/api/login] incoming', { body: req.body, ip: req.ip });
  try {
    const users = loadUsers();
    const { email, password } = req.body;
    if (!email || !password) return res.json({ success: false, message: 'Missing fields' });
    const user = users.find(u => u.email === email);
    if (!user) return res.json({ success: false, message: 'User not found' });
    let valid = false;
    try { valid = await bcrypt.compare(password, user.password); } catch (e) { valid = user.password === password; }
    if (!valid) return res.json({ success: false, message: 'Invalid credentials' });
    req.session.user = user;
    console.log('[/api/login] success for', email);
    res.json({ success: true });
  } catch (err) {
    console.error('[/api/login] error', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Debug route to inspect incoming requests
app.all('/debug', (req, res) => {
  console.log('[/debug]', req.method, req.path, { headers: req.headers, body: req.body });
  res.json({ ok: true, method: req.method, headers: req.headers, body: req.body });
});

// Logout route
app.post('/logout', (req, res) => {
  if (req.session) {
    req.session.destroy(err => {
      if (err) return res.status(500).json({ success: false, message: 'Logout failed' });
      res.json({ success: true });
    });
  } else {
    res.json({ success: true });
  }
});

// Return sanitized users list (no passwords)
app.get('/users', (req, res) => {
  const users = loadUsers();
  const sanitized = users.map(u => ({ id: u.id, email: u.email, role: u.role, vipExpires: u.vipExpires }));
  res.json(sanitized);
});

// Product and purchase APIs
app.get('/api/products', (req, res) => {
  res.json(loadScripts());
});

app.post('/api/purchase', (req, res) => {
  const { email, productId } = req.body;
  if (!email || !productId) return res.status(400).json({ success: false, message: 'Missing fields' });
  const prods = loadScripts();
  const prod = prods.find(p => p.id == productId);
  if (!prod) return res.status(400).json({ success: false, message: 'Product not found' });

  // simulate purchase, generate a key, and record purchase
  const keys = loadKeys();
  const newKey = { key: uuidv4().split('-')[0].toUpperCase(), productId: prod.id, owner: email, created: Date.now() };
  keys.push(newKey);
  saveKeys(keys);

  const purchases = loadPurchases();
  const purchase = { id: uuidv4(), buyer: email, productId: prod.id, price: prod.price || 0, keys: [newKey.key], created: Date.now() };
  purchases.push(purchase);
  savePurchases(purchases);

  res.json({ success: true, keys: [newKey], purchase });
});

// API promo endpoint for frontend
app.post('/api/promo', (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) return res.status(400).json({ success: false, message: 'Missing fields' });
  const promos = loadPromo();
  const promo = promos.find(p => p.code === code && p.uses > 0);
  if (!promo) return res.json({ success: false, message: 'Invalid code' });
  const users = loadUsers();
  const user = users.find(u => u.email === email);
  if (!user) return res.json({ success: false, message: 'User not found' });
  user.role = 'vip';
  user.vipExpires = Date.now() + 30 * 24 * 60 * 60 * 1000;
  promo.uses -= 1;
  saveUsers(users);
  savePromo(promos);
  res.json({ success: true, message: 'Upgraded to VIP' });
});

// Admin: add a product
app.post('/api/admin/product', requireOwner, (req, res) => {
  const { name, description, vipOnly, price } = req.body;
  if (!name) return res.status(400).json({ success: false, message: 'Missing name' });
  const prods = loadScripts();
  const id = (prods.length + 1).toString();
  const p = { id, name, description: description||'', vipOnly: !!vipOnly, price: price || 0 };
  prods.push(p);
  fs.writeFileSync('scripts.json', JSON.stringify(prods, null, 2));
  res.json({ success: true, product: p });
});

// Admin: add keys in bulk
app.post('/api/admin/keys', requireOwner, (req, res) => {
  const { productId, keys } = req.body;
  if (!productId || !Array.isArray(keys)) return res.status(400).json({ success: false, message: 'Missing fields' });
  const all = loadKeys();
  const now = Date.now();
  const toAdd = keys.map(k => ({ key: k, productId, owner: null, created: now }));
  const combined = all.concat(toAdd);
  saveKeys(combined);
  res.json({ success: true, added: toAdd.length });
});

// Purchases listing: owner sees all, users can query by email
app.get('/api/purchases', (req, res) => {
  const email = req.query.email;
  const purchases = loadPurchases();
  if (email) {
    return res.json(purchases.filter(p => p.buyer === email));
  }
  // owner-only
  if (!req.session.user || req.session.user.role !== 'owner') return res.status(403).json({ success: false, message: 'Access denied' });
  res.json(purchases);
});

app.get('/api/account/keys', (req, res) => {
  const email = req.query.email;
  if (!email) return res.status(400).json({ success: false, message: 'Missing email' });
  const keys = loadKeys().filter(k => k.owner === email);
  res.json(keys);
});

app.get('/api/keys', requireOwner, (req, res) => {
  res.json(loadKeys());
});

app.get("/dashboard", requireLogin, (req, res) => {
  const scripts = loadScripts();
  res.render("dashboard", { user: req.session.user, scripts });
});

app.get("/owner", requireOwner, (req, res) => {
  const users = loadUsers();
  res.render("owner", { users });
});

// Convenience redirects
app.get('/shop', (req, res) => res.redirect('/shop.html'));
app.get('/admin', (req, res) => res.redirect('/admin.html'));

app.post("/promo", requireLogin, (req, res) => {
  const promos = loadPromo();
  const users = loadUsers();

  const code = promos.find(p => p.code === req.body.code && p.uses > 0);
  if (!code) return res.send("Invalid code");

  const user = users.find(u => u.id === req.session.user.id);
  user.vipExpires = Date.now() + 30 * 24 * 60 * 60 * 1000;

  code.uses -= 1;

  saveUsers(users);
  savePromo(promos);

  res.redirect("/dashboard");
});

const BASE_PORT = parseInt(process.env.PORT, 10) || 3000;

function tryListen(port, attemptsLeft) {
  const server = app.listen(port, () => {
    console.log(`Server listening on http://lazycheatz.local:${port}`);
  });

  server.on('error', (err) => {
    if (err && err.code === 'EADDRINUSE') {
      console.error(`Port ${port} in use.`);
      server.close();
      if (attemptsLeft > 0) {
        const next = port + 1;
        console.log(`Trying port ${next}...`);
        tryListen(next, attemptsLeft - 1);
      } else {
        console.error('No available ports found. Exiting.');
        process.exit(1);
      }
    } else {
      console.error('Server error:', err);
      process.exit(1);
    }
  });
}

tryListen(BASE_PORT, 10);
