import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import multer from 'multer';
import path from 'path';
import fs from 'fs';

const app = express();
const PORT = 3000;
const JWT_SECRET = '123';
const DB_URI =
  "mongodb+srv://123:123@cluster0.kwwd9ao.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";

// Create uploads folder if not exists
const uploadsDir = path.join(process.cwd(), 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}

// Middleware
app.use(cors({ origin: '*' }));
app.use(express.json());
app.use('/uploads', express.static(uploadsDir));

// Multer config for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + '-' + uniqueSuffix + ext);
  },
});
const upload = multer({ storage });

// Connect to MongoDB
mongoose.connect(DB_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  });

// Mongoose Schemas
const userSchema = new mongoose.Schema({
  username: String,
  name: String,
  email: { type: String, unique: true, lowercase: true },
  password: String,
  age: Number, // 👈 Now it's a Number
  role: { type: String, enum: ['user', 'manager', 'admin'], default: 'user' },
  profileImage: { type: String },
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

const addCardSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true },
  description: { type: String, required: true },
  image: String,
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

const authorizeAdmin = (req, res, next) => {
  if (!req.user) return res.status(401).json({ error: 'Unauthorized: user data missing' });
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied. Admins only.' });
  next();
};

// Check if email exists
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

// Register new user
app.post('/users', upload.single('profileImage'), async (req, res) => {
  try {
    const { username, name, email, password, age } = req.body;

    if (!username || !name || !email || !password) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const emailUsed = await User.findOne({ email: email.toLowerCase() });
    if (emailUsed) return res.status(409).json({ error: 'Email already registered' });

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      username,
      name,
      email: email.toLowerCase(),
      password: hashedPassword,
      age: age ? Number(age) : undefined, // 👈 Fixed: Convert age to Number
      profileImage: req.file ? `/uploads/${req.file.filename}` : undefined,
    });

    await user.save();
    res.status(201).json({ message: 'User registered successfully' });

  } catch (err) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user._id, role: user.role, email: user.email },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        _id: user._id,
        username: user.username,
        name: user.name,
        email: user.email,
        age: user.age,
        role: user.role,
        profileImage: user.profileImage,
      },
    });

  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get all users (non-admin roles)
app.get('/users', authenticateToken, async (req, res) => {
  try {
    const users = await User.find({ role: { $in: ['user', 'manager'] } }).select('-password -__v');
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Delete user (admin only)
app.delete('/users/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const deleted = await User.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// Update user (admin only)
app.put('/users/:id', authenticateToken, authorizeAdmin, upload.single('profileImage'), async (req, res) => {
  try {
    const { username, name, email, age, role, password } = req.body;
    const currentUser = await User.findById(req.params.id);
    if (!currentUser) return res.status(404).json({ error: 'User not found' });

    const updateData = {
      username,
      name,
      email: email?.toLowerCase(),
      age: age ? Number(age) : undefined,
      role,
    };

    if (password && password.trim() !== '') {
      updateData.password = await bcrypt.hash(password, 10);
    }

    if (req.file) {
      updateData.profileImage = `/uploads/${req.file.filename}`;
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

// AddCard routes (admin only)
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

// Get all non-admin users
app.get('/users', authenticateToken, async (req, res) => {
  try {
    const users = await User.find({ role: { $in: ['user', 'manager'] } }).select('-password -__v');
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

//get all profileimage links
app.get('/users/prfileimage', authenticateToken, async (req, res) => {
  try {
    const users = await User.find({ role: { $in: ['user', 'manager'] } }).select('-password -__v');
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});










// Admins only - Get admins
app.get('/admin/admins', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const admins = await User.find({ role: 'admin' }).select('-password -__v');
    res.json(admins);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch admins' });
  }
});

app.get('/addcard', authenticateToken, async (req, res) => {
  try {
    const cards = await AddCard.find({});
    res.json(cards);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch cards' });
  }
});


// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});