import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';

const app = express();
const PORT = 3000;

// MongoDB connection URI
const DB_URI = 'mongodb+srv://123:123@cluster0.kwwd9ao.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';

// Middleware
app.use(cors());
app.use(express.json());

// Connect to MongoDB
mongoose
  .connect(DB_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch((err) => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  });

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  age: { type: Number }
});

const User = mongoose.model('User', userSchema);

// POST /users - Register new user
app.post('/users', async (req, res) => {
  try {
    const { username, name, email, age } = req.body;

    if (!username || !name || !email) {
      return res.status(400).json({ error: 'Username, name, and email are required' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already exists' });
    }

    const newUser = new User({ username, name, email, age });
    await newUser.save();

    res.status(201).json({ message: 'User saved successfully!', user: newUser });
  } catch (error) {
    res.status(500).json({ error: 'Failed to save user' });
  }
});

// GET /users - Get all users
app.get('/users', async (req, res) => {
  try {
    const users = await User.find();
    res.status(200).json(users);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// GET /users/check-email - Check if email already exists
app.get('/users/check-email', async (req, res) => {
  try {
    const { email } = req.query;
    const user = await User.findOne({ email });
    res.json({ exists: !!user });
  } catch (error) {
    res.status(500).json({ error: 'Error checking email' });
  }
});

// GET /users/:email - Get user by email (case-insensitive)
app.get('/users/:email', async (req, res) => {
  try {
    const { email } = req.params;

    const user = await User.findOne({ email: new RegExp(`^${email}$`, 'i') });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});

