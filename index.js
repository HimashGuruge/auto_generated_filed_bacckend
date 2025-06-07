import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

const app = express();
const PORT = 3000;

const JWT_SECRET = '123'; // Use environment variables in production
const DB_URI = "mongodb+srv://123:123@cluster0.kwwd9ao.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";

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

// User Schema
const userSchema = new mongoose.Schema({
  username: String,
  name: String,
  email: { type: String, unique: true, lowercase: true },
  password: String,
  age: Number,
  role: { type: String, enum: ['user', 'manager', 'admin'], default: 'user' }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// JWT middleware
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

// Admin role middleware
const authorizeAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied. Admins only.' });
  }
  next();
};

// Check if email exists
app.get('/users/check-email', async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) return res.status(400).json({ error: 'Email query parameter is required' });

    const exists = await User.exists({ email: email.toLowerCase() });
    res.json({ exists: !!exists });
  } catch (err) {
    res.status(500).json({ error: 'Failed to check email' });
  }
});

// User registration (hashed password) - ADMIN ROLE PREVENTED
app.post('/users', async (req, res) => {
  try {
    const { username, name, email, password, age } = req.body;

    if (!username || !name || !email || !password) {
      return res.status(400).json({ error: 'Username, name, email, and password are required' });
    }

    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // Force role to 'user' - prevents admin creation through API
    const newUser = new User({
      username,
      name,
      email: email.toLowerCase(),
      password: hashedPassword,
      age,
      role: 'user' // Hardcoded - cannot be set to admin via API
    });

    await newUser.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to register user' });
  }
});

// Login (hashed password check)
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const payload = { id: user._id, email: user.email, role: user.role };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

    res.status(200).json({
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

// Get users (only users and managers)
app.get('/users', authenticateToken, async (req, res) => {
  try {
    const users = await User.find({ role: { $in: ['user', 'manager'] } }).select('-__v -password');
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Delete user - only admin
app.delete('/users/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const deletedUser = await User.findByIdAndDelete(id);

    if (!deletedUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// Update user - only admin (WITH ADMIN ROLE PROTECTION AND PASSWORD HASHING)
app.put('/users/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { username, name, email, age, role, password } = req.body;

    // Validate role
    const allowedRoles = ['user', 'manager', 'admin'];
    if (role && !allowedRoles.includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    // Fetch current user from database
    const currentUser = await User.findById(id);
    if (!currentUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Prevent admin role modifications via API
    if (role) {
      // Block changing TO admin
      if (role === 'admin' && currentUser.role !== 'admin') {
        return res.status(403).json({ 
          error: 'Cannot assign admin role via API. Must update database manually.' 
        });
      }
      
      // Block changing FROM admin
      if (currentUser.role === 'admin' && role !== 'admin') {
        return res.status(403).json({ 
          error: 'Cannot remove admin role via API. Must update database manually.' 
        });
      }
    }

    // Check email uniqueness
    if (email) {
      const emailUser = await User.findOne({ email: email.toLowerCase() });
      if (emailUser && emailUser._id.toString() !== id) {
        return res.status(409).json({ error: 'Email already in use by another user' });
      }
    }

    // Prepare update data
    const updateData = {
      username,
      name,
      age,
      role,
    };

    if (email) updateData.email = email.toLowerCase();

    // Handle password hashing if password is provided and not empty
    if (password && password.trim() !== '') {
      const hashedPassword = await bcrypt.hash(password, 10);
      updateData.password = hashedPassword;
    }

    const updatedUser = await User.findByIdAndUpdate(id, updateData, {
      new: true,
      runValidators: true,
    });

    if (!updatedUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Don't send password back in response
    const userResponse = updatedUser.toObject();
    delete userResponse.password;
    delete userResponse.__v;

    res.json({ message: 'User updated successfully', user: userResponse });
  } catch (err) {
    console.error('Update error:', err);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// Admin routes (admins only)
app.use('/admin', authenticateToken, authorizeAdmin);

app.get('/admin/admins', async (req, res) => {
  try {
    const admins = await User.find({ role: 'admin' }).select('-__v -password');
    res.json(admins);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch admins' });
  }
});

app.get('/admin/data', (req, res) => {
  res.json({ secretAdminData: 'This is admin only!' });
});

// Profile
app.get('/profile', authenticateToken, (req, res) => {
  res.json({ message: 'Welcome to your profile', user: req.user });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
