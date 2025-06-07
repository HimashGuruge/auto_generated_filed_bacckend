import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import multer from 'multer';
import path from 'path';

const app = express();
const PORT = 3000;
const JWT_SECRET = '123';

const DB_URI = "mongodb+srv://123:123@cluster0.kwwd9ao.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";

// Middleware
app.use(cors({ origin: '*' }));
app.use(express.json());
app.use('/uploads', express.static(path.join(process.cwd(), 'uploads')));

// Multer config for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + '-' + uniqueSuffix + ext);
  }
});
const upload = multer({ storage });

// Connect to MongoDB
mongoose.connect(DB_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  });

// Schemas
const userSchema = new mongoose.Schema({
  username: String,
  name: String,
  email: { type: String, unique: true, lowercase: true },
  password: String,
  age: Number,
  role: { type: String, enum: ['user', 'manager', 'admin'], default: 'user' }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

const addCardSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true },
  description: { type: String, required: true },
  image: { type: String }
}, { timestamps: true });

const AddCard = mongoose.model('AddCard', addCardSchema);

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'] || req.headers['Authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Authentication token required' });

  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Malformed authentication token' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

// Admin check middleware
const authorizeAdmin = (req, res, next) => {
  if (!req.user) return res.status(401).json({ error: 'Unauthorized: user data missing' });
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied. Admins only.' });
  next();
};

// Routes

// ✅ Check email
app.get('/users/check-email', async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const exists = await User.exists({ email: email.toLowerCase() });
    res.json({ exists: !!exists });
  } catch (err) {
    res.status(500).json({ error: 'Failed to check email' });
  }
});

// ✅ Register
app.post('/users', async (req, res) => {
  try {
    const { username, name, email, password, age } = req.body;
    if (!username || !name || !email || !password) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const exists = await User.findOne({ email: email.toLowerCase() });
    if (exists) return res.status(409).json({ error: 'Email already registered' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, name, email: email.toLowerCase(), password: hashedPassword, age });
    await user.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

// ✅ Login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user._id, role: user.role, email: user.email }, JWT_SECRET, { expiresIn: '1h' });

    res.json({
      message: 'Login successful',
      token,
      user: {
        username: user.username,
        name: user.name,
        email: user.email,
        age: user.age,
        role: user.role,
        _id: user._id
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// ✅ Get all non-admin users
app.get('/users', authenticateToken, async (req, res) => {
  try {
    const users = await User.find({ role: { $in: ['user', 'manager'] } }).select('-password -__v');
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// ✅ Admins only - Get admins
app.get('/admin/admins', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const admins = await User.find({ role: 'admin' }).select('-password -__v');
    res.json(admins);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch admins' });
  }
});

// ✅ Delete user (admin only)
app.delete('/users/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const deleted = await User.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// ✅ Update user (admin only)
app.put('/users/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { username, name, email, age, role, password } = req.body;

    const currentUser = await User.findById(req.params.id);
    if (!currentUser) return res.status(404).json({ error: 'User not found' });

    if (role && role === 'admin' && currentUser.role !== 'admin') {
      return res.status(403).json({ error: 'Cannot assign admin role via API' });
    }

    if (email) {
      const emailUsed = await User.findOne({ email: email.toLowerCase() });
      if (emailUsed && emailUsed._id.toString() !== req.params.id) {
        return res.status(409).json({ error: 'Email already in use' });
      }
    }

    const updateData = {
      username,
      name,
      email: email?.toLowerCase(),
      age,
      role,
    };

    if (password && password.trim() !== '') {
      updateData.password = await bcrypt.hash(password, 10);
    }

    const updated = await User.findByIdAndUpdate(req.params.id, updateData, { new: true, runValidators: true });
    if (!updated) return res.status(404).json({ error: 'User not found' });

    const userObj = updated.toObject();
    delete userObj.password;
    delete userObj.__v;

    res.json({ message: 'User updated successfully', user: userObj });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// ✅ AddCard: Create (admin only)
app.post('/addcard', authenticateToken, authorizeAdmin, upload.single('image'), async (req, res) => {
  try {
    const { title, description } = req.body;
    if (!title || !description) return res.status(400).json({ error: 'Title and description are required' });

    const newCard = new AddCard({
      title,
      description,
      image: req.file ? `/uploads/${req.file.filename}` : '',
    });

    await newCard.save();
    res.status(201).json({ message: 'AddCard created', card: newCard });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create card' });
  }
});

// ✅ AddCard: Get all (public)
app.get('/addcard', async (req, res) => {
  try {
    const cards = await AddCard.find().sort({ createdAt: -1 });
    res.json(cards);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch cards' });
  }
});

// ✅ AddCard: Get single
app.get('/addcard/:id', async (req, res) => {
  try {
    const card = await AddCard.findById(req.params.id);
    if (!card) return res.status(404).json({ error: 'Card not found' });
    res.json(card);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch card' });
  }
});

// ✅ AddCard: Update (admin only)
app.put('/addcard/:id', authenticateToken, authorizeAdmin, upload.single('image'), async (req, res) => {
  try {
    const updateData = {
      title: req.body.title,
      description: req.body.description,
    };
    if (req.file) {
      updateData.image = `/uploads/${req.file.filename}`;
    }

    const updatedCard = await AddCard.findByIdAndUpdate(req.params.id, updateData, { new: true });
    if (!updatedCard) return res.status(404).json({ error: 'Card not found' });

    res.json({ message: 'Card updated', card: updatedCard });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update card' });
  }
});

// ✅ AddCard: Delete (admin only)
app.delete('/addcard/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const deleted = await AddCard.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Card not found' });
    res.json({ message: 'Card deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete card' });
  }
});




// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
