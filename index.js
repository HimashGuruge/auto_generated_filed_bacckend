import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';

const app = express();
const PORT = process.env.PORT || 3000;

// MongoDB connection URI
const DB_URI = 'mongodb+srv://123:123@cluster0.kwwd9ao.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';

// Middleware
app.use(cors());
app.use(express.json());

// Connect to MongoDB
mongoose.connect(DB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch((err) => {
  console.error('❌ MongoDB connection error:', err);
  process.exit(1);
});

// Base user schema with common fields
const baseUserSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: true, 
    unique: true,
    trim: true,
    minlength: 3
  },
  name: { 
    type: String, 
    required: true,
    trim: true
  },
  email: { 
    type: String, 
    required: true, 
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address']
  },
  age: { 
    type: Number,
    min: 13,
    max: 120
  },
  role: {
    type: String,
    required: true,
    enum: ['user', 'manager', 'admin'],
    default: 'user'
  }
}, { timestamps: true });

// Main User model
const User = mongoose.model('User', baseUserSchema);

// Input validation middleware
const validateUserInput = (req, res, next) => {
  const { username, name, email, age, role = 'user' } = req.body;

  if (!username || !name || !email) {
    return res.status(400).json({ error: 'Username, name, and email are required' });
  }

  if (!['user', 'admin', 'manager'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }

  if (age && (typeof age !== 'number' || age < 13 || age > 120)) {
    return res.status(400).json({ error: 'Age must be between 13 and 120' });
  }

  req.validatedData = { username, name, email, age, role };
  next();
};

// POST /users - Add user/admin/manager
app.post('/users', validateUserInput, async (req, res) => {
  try {
    const { username, name, email, age, role } = req.validatedData;

    // Check for existing user
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ error: 'Email or username already exists' });
    }

    const user = new User({ username, name, email, age, role });
    await user.save();

    res.status(201).json({
      message: `${role.charAt(0).toUpperCase() + role.slice(1)} saved successfully!`,
      user
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to save user' });
  }
});

// GET /users - Get all users and managers (not admins)
app.get('/users', async (_req, res) => {
  try {
    const users = await User.find({ role: { $in: ['user', 'manager'] } });
    res.status(200).json(users);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// GET /admins - Get all admins
app.get('/admins', async (_req, res) => {
  try {
    const admins = await User.find({ role: 'admin' });
    res.status(200).json(admins);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch admins' });
  }
});

// GET /users/:email - Search user or admin by email (case-insensitive)
app.get('/users/:email', async (req, res) => {
  try {
    const { email } = req.params;
    const user = await User.findOne({ email: new RegExp(`^${email}$`, 'i') });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.status(200).json(user);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});




// POST /login (email only)
app.post('/login', async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email' });
    }

    // Login successful (email only)
    res.status(200).json({ message: 'Login successful', user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Login failed' });
  }
});




























// DELETE /users/:id - delete user/admin by _id
app.delete('/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const deletedUser = await User.findByIdAndDelete(id);

    if (!deletedUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.status(200).json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// PUT /users/:id - update user/admin details
app.put('/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = req.body;

    // Validate role if provided
    if (updateData.role && !['admin', 'user', 'manager'].includes(updateData.role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    const updatedUser = await User.findByIdAndUpdate(id, updateData, { 
      new: true,
      runValidators: true
    });

    if (!updatedUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.status(200).json({ message: 'User updated successfully', user: updatedUser });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});