import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import jwt from 'jsonwebtoken';

const app = express();
const PORT = 3000;

const JWT_SECRET = '123'; // hardcoded secret (not recommended for prod)
const DB_URI = "mongodb+srv://123:123@cluster0.kwwd9ao.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

app.use(cors());
app.use(express.json());

// Connect MongoDB
mongoose.connect(DB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch(err => {
  console.error('❌ MongoDB connection error:', err);
  process.exit(1);
});

// User schema
const userSchema = new mongoose.Schema({
  username: String,
  name: String,
  email: String,
  age: Number,
  role: { type: String, enum: ['user', 'manager', 'admin'], default: 'user' }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// JWT Middleware - verify token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Admin role middleware - allow only admins
const authorizeAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied. Admins only.' });
  }
  next();
};

// POST /login - generate JWT token
app.post('/login', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) return res.status(401).json({ error: 'Invalid email' });

    const payload = { id: user._id, email: user.email, role: user.role };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

    res.status(200).json({ message: 'Login successful', token, user });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// GET /users - accessible by authenticated users, returns users with role 'user' or 'manager'
app.get('/users', authenticateToken, async (req, res) => {
  try {
    const users = await User.find({ role: { $in: ['user', 'manager'] } }).select('-__v');
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Group all /admin routes and protect them with admin authorization
app.use('/admin', authenticateToken, authorizeAdmin);

// GET /admin/admins - returns all admins
app.get('/admin/admins', async (req, res) => {
  try {
    const admins = await User.find({ role: 'admin' }).select('-__v');
    res.json(admins);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch admins' });
  }
});

// GET /admin/data - example admin-only data
app.get('/admin/data', (req, res) => {
  res.json({ secretAdminData: 'This is admin only!' });
});

// GET /profile - accessible by any authenticated user
app.get('/profile', authenticateToken, (req, res) => {
  res.json({ message: 'Welcome to your profile', user: req.user });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
