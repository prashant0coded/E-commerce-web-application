require('dotenv').config();
const path = require('path');
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const { MONGODB_URI, JWT_SECRET, ADMIN_EMAIL } = process.env;
if (!MONGODB_URI || !JWT_SECRET) { console.error('Set MONGODB_URI and JWT_SECRET in .env'); process.exit(1); }

const app = express();
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Models (prices are integer cents) ----------
const User = mongoose.model('User', new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 80 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
}));
const Product = mongoose.model('Product', new mongoose.Schema({
  title: { type: String, required: true, trim: true, maxlength: 120 },
  description: { type: String, default: '', maxlength: 2000 },
  category: { type: String, default: 'General', trim: true },
  price: { type: Number, required: true, min: 0, validate: Number.isInteger },
  stock: { type: Number, required: true, min: 0, validate: Number.isInteger },
  imageUrl: { type: String, default: '' },
}, { timestamps: true }));
const STATUSES = ['pending', 'processing', 'shipped', 'delivered', 'cancelled'];
const Order = mongoose.model('Order', new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  items: [{ product: mongoose.Schema.Types.ObjectId, title: String, price: Number, qty: Number }],
  total: Number,
  status: { type: String, enum: STATUSES, default: 'pending' },
  shipping: { name: String, address: String, phone: String },
}, { timestamps: true }));

// ---------- Auth & roles ----------
const sign = u => jwt.sign({ id: u._id }, JWT_SECRET, { expiresIn: '7d' });
const publicUser = u => ({ id: u._id, name: u.name, email: u.email, role: u.role });

async function auth(req, res, next) {
  try {
    const { id } = jwt.verify((req.get('authorization') || '').replace('Bearer ', ''), JWT_SECRET);
    req.user = await User.findById(id);               // role is read fresh from the DB every request
    req.user ? next() : res.status(401).json({ error: 'Please log in again.' });
  } catch { res.status(401).json({ error: 'Please log in again.' }); }
}
const adminOnly = (req, res, next) =>
  req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Admins only.' });

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30 });
app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !/^\S+@\S+\.\S+$/.test(email || '')) return res.status(400).json({ error: 'Enter a name and a valid email.' });
  if (!password || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  if (await User.findOne({ email: email.toLowerCase() })) return res.status(409).json({ error: 'That email is already registered.' });
  const role = ADMIN_EMAIL && email.toLowerCase() === ADMIN_EMAIL.toLowerCase() ? 'admin' : 'user';
  const user = await User.create({ name, email, role, password: await bcrypt.hash(password, 10) });
  res.status(201).json({ token: sign(user), user: publicUser(user) });
});
app.post('/api/auth/login', authLimiter, async (req, res) => {
  const user = await User.findOne({ email: String(req.body.email || '').toLowerCase() });
  if (!user || !(await bcrypt.compare(req.body.password || '', user.password)))
    return res.status(401).json({ error: 'Wrong email or password.' });
  res.json({ token: sign(user), user: publicUser(user) });
});
app.get('/api/auth/me', auth, (req, res) => res.json(publicUser(req.user)));

// ---------- Products ----------
const productFields = b => ({
  title: b.title, description: b.description, category: b.category || 'General',
  price: Math.round(Number(b.price) * 100), stock: parseInt(b.stock, 10), imageUrl: b.imageUrl || '',
});
const escRe = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

app.get('/api/products', async (req, res) => {
  const f = {};
  if (req.query.category) f.category = String(req.query.category);
  if (req.query.search) f.title = new RegExp(escRe(String(req.query.search)), 'i');
  res.json(await Product.find(f).sort({ createdAt: -1 }));
});
app.post('/api/products', auth, adminOnly, async (req, res) => {
  try { res.status(201).json(await Product.create(productFields(req.body))); }
  catch { res.status(400).json({ error: 'Title, a valid price and whole-number stock are required.' }); }
});
app.put('/api/products/:id', auth, adminOnly, async (req, res) => {
  try {
    const p = await Product.findByIdAndUpdate(req.params.id, productFields(req.body), { new: true, runValidators: true });
    p ? res.json(p) : res.status(404).json({ error: 'Product not found.' });
  } catch { res.status(400).json({ error: 'Invalid product data.' }); }
});
app.delete('/api/products/:id', auth, adminOnly, async (req, res) => {
  await Product.findByIdAndDelete(req.params.id).catch(() => {});
  res.json({ ok: true });
});

// ---------- Orders ----------
const restock = items => Promise.all(items.map(i => Product.updateOne({ _id: i.product }, { $inc: { stock: i.qty } })));

app.post('/api/orders', auth, async (req, res) => {
  const { items, shipping } = req.body;
  if (!Array.isArray(items) || !items.length) return res.status(400).json({ error: 'Your cart is empty.' });
  if (!shipping?.name || !shipping?.address || !shipping?.phone) return res.status(400).json({ error: 'Enter name, address and phone.' });

  const qty = {};                                       // merge duplicates, validate quantities
  for (const it of items) {
    const q = parseInt(it.productId && it.qty, 10);
    if (!mongoose.isValidObjectId(it.productId) || !(q > 0 && q <= 99)) return res.status(400).json({ error: 'Invalid cart item.' });
    qty[it.productId] = (qty[it.productId] || 0) + q;
  }
  const products = await Product.find({ _id: { $in: Object.keys(qty) } });
  if (products.length !== Object.keys(qty).length) return res.status(400).json({ error: 'A product in your cart is no longer available.' });

  // Reserve stock atomically per product; undo everything if any line fails
  const reserved = [];
  for (const p of products) {
    const n = qty[p._id];
    const r = await Product.updateOne({ _id: p._id, stock: { $gte: n } }, { $inc: { stock: -n } });
    if (!r.modifiedCount) { await restock(reserved); return res.status(409).json({ error: `Not enough stock for "${p.title}".` }); }
    reserved.push({ product: p._id, qty: n });
  }
  try {
    const lines = products.map(p => ({ product: p._id, title: p.title, price: p.price, qty: qty[p._id] })); // price taken from DB, never from the client
    const order = await Order.create({
      user: req.user._id, items: lines, shipping: { name: shipping.name, address: shipping.address, phone: shipping.phone },
      total: lines.reduce((s, l) => s + l.price * l.qty, 0),
    });
    res.status(201).json(order);
  } catch { await restock(reserved); res.status(500).json({ error: 'Could not place the order.' }); }
});

app.get('/api/orders', auth, async (req, res) => {          // users: own orders. admin + ?all=1: every order
  const all = req.user.role === 'admin' && req.query.all;
  const q = Order.find(all ? {} : { user: req.user._id }).sort({ createdAt: -1 });
  res.json(await (all ? q.populate('user', 'name email') : q));
});

app.put('/api/orders/:id/cancel', auth, async (req, res) => {   // owners can cancel while pending
  const o = mongoose.isValidObjectId(req.params.id) && await Order.findOneAndUpdate(
    { _id: req.params.id, user: req.user._id, status: 'pending' }, { status: 'cancelled' }, { new: true });
  if (!o) return res.status(400).json({ error: 'Only your own pending orders can be cancelled.' });
  await restock(o.items); res.json(o);
});

app.put('/api/orders/:id/status', auth, adminOnly, async (req, res) => {
  const { status } = req.body;
  if (!STATUSES.includes(status)) return res.status(400).json({ error: 'Invalid status.' });
  const o = mongoose.isValidObjectId(req.params.id) && await Order.findById(req.params.id);
  if (!o) return res.status(404).json({ error: 'Order not found.' });
  if (o.status === 'cancelled') return res.status(400).json({ error: 'Cancelled orders cannot be changed.' });
  if (status === 'cancelled') await restock(o.items);
  o.status = status; await o.save(); res.json(o);
});

// ---------- Start (seed sample products on first run) ----------
mongoose.connect(MONGODB_URI).then(async () => {
  if (!(await Product.countDocuments())) await Product.insertMany([
    { title: 'Canvas Backpack', category: 'Bags', price: 4900, stock: 25, description: 'Water-resistant 20L pack with laptop sleeve.' },
    { title: 'Steel Water Bottle', category: 'Outdoors', price: 2200, stock: 60, description: 'Keeps drinks cold for 24 hours.' },
    { title: 'Wireless Mouse', category: 'Tech', price: 1900, stock: 40, description: 'Quiet clicks, 12-month battery.' },
    { title: 'Notebook Set (3 pack)', category: 'Stationery', price: 1200, stock: 100, description: 'Dotted pages, lay-flat binding.' },
  ]);
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`http://localhost:${port}`));
}).catch(e => { console.error('MongoDB connection failed:', e.message); process.exit(1); });
