import express from 'express';
import bodyParser from 'body-parser';
import mongoose from 'mongoose';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import multer from 'multer';
import path from 'path';
import fs from 'fs';

const app = express();
const JWT_SECRET = '123'; // 🔐 WARNING: This should be in an .env file for production!

// Ensure 'uploads' directory exists
const uploadDir = path.join('uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}
app.use('/uploads', express.static(uploadDir));

// Middleware
app.use(cors());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Connect to MongoDB
mongoose.connect('mongodb+srv://123:123@cluster0.ecr0ssx.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Schemas & Models
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  username: { type: String, required: true, unique: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  age: { type: Number, min: 0 },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  ProfileImage: { type: String, default: '' },
}, { timestamps: true });

const addCardSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true },
  description: { type: String, required: true, trim: true },
  image: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);
const AddCard = mongoose.model('AddCard', addCardSchema);

// Multer Storage Configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    cb(null, Date.now() + ext);
  },
});
const upload = multer({ storage });

// ---

// ## Authentication Middleware

/**
 * Middleware to verify a JWT and attach the decoded user information to req.user.
 */
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied, token missing' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

/**
 * Middleware to verify a JWT and ensure the authenticated user has an 'admin' role.
 */
function verifyAdminToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authorization token required' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Admins only' });
    }
    req.user = decoded;
    next();
  } catch (err) {
    console.error('Admin token verification error:', err);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ---

// ## User Management Routes

/**
 * POST /admin/signup
 * Allows an admin to create new user accounts, including other admins.
 * Requires admin token.
 * ✅ ඔබේ කලින් තිබූ /signup route එක admin-specific ලෙස වෙනස් කරන ලදි.
 */
app.post('/admin/signup', verifyAdminToken, async (req, res) => { // ✅ Path එක වෙනස් කර ඇත
  try {
    const { name, username, email, password, confirmPassword, age, role } = req.body;

    if (!name || !username || !email || !password || !confirmPassword) {
      return res.status(400).json({ error: 'All required fields must be provided' });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }

    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(409).json({ error: 'User with this email or username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      name,
      username,
      email,
      password: hashedPassword,
      age,
      role: role === 'admin' ? 'admin' : 'user', // Only allow 'admin' role if explicitly set
    });

    await newUser.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    console.error('Admin signup error:', err); // ✅ Log message වෙනස් කර ඇත
    res.status(500).json({ error: 'Server error during admin signup' });
  }
});

/**
 * POST /signup
 * Allows a regular user to create a new user account (role defaults to 'user').
 * Does NOT require any token.
 * ✅ සාමාන්‍ය user registration සඳහා නව route එකක් එකතු කර ඇත.
 */
app.post('/signup', async (req, res) => { // ✅ මෙය JWT අවශ්‍ය නොවන නව route එකයි
  try {
    const { name, username, email, password, confirmPassword, age } = req.body; // role එක බාර ගන්නේ නැහැ

    if (!name || !username || !email || !password || !confirmPassword) {
      return res.status(400).json({ error: 'All required fields must be provided' });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }

    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(409).json({ error: 'User with this email or username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      name,
      username,
      email,
      password: hashedPassword,
      age,
      role: 'user', // ✅ Default to 'user' for public registration
    });

    await newUser.save();
    res.status(201).json({ message: 'Registration successful. You can now login.' });
  } catch (err) {
    console.error('Public signup error:', err); // ✅ Log message වෙනස් කර ඇත
    res.status(500).json({ error: 'Server error during registration' });
  }
});

/**
 * POST /login
 * Authenticates a user and returns a JWT.
 */
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({
      token,
      user: { id: user._id, email: user.email, name: user.name, role: user.role },
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error during login' });
  }
});

/**
 * GET /profile
 * Retrieves the profile of the authenticated user.
 * Requires any valid JWT.
 */
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
  } catch (err) {
    console.error('Profile retrieval error:', err);
    res.status(500).json({ error: 'Server error during profile retrieval' });
  }
});

/**
 * GET /users
 * Retrieves a list of all users.
 * Requires any valid JWT. Consider changing to verifyAdminToken for production.
 */
app.get('/users', authenticateToken, async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json(users);
  } catch (error) {
    console.error('Failed to fetch users:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

/**
 * PUT /users/:id
 * Allows updating a user's information.
 * Requires any valid JWT. Users can update their own profile; admins can update any profile.
 */
app.put('/users/:id', authenticateToken, async (req, res) => {
  try {
    const { username, name, email, age, role, password } = req.body;
    const updateData = {};

    // Only allow specific fields to be updated if provided
    if (username !== undefined) updateData.username = username;
    if (name !== undefined) updateData.name = name;
    if (email !== undefined) updateData.email = email;
    if (age !== undefined) updateData.age = age;

    if (password) {
      updateData.password = await bcrypt.hash(password, 10);
    }

    // Only allow role change if the current user is an admin
    if (role !== undefined) {
      if (req.user.role !== 'admin' && role !== req.user.role) {
        return res.status(403).json({ error: 'Unauthorized to change user role' });
      }
      updateData.role = role;
    }

    // Ensure users can only update their own profile unless they are an admin
    if (req.user.role !== 'admin' && req.user.userId !== req.params.id) {
        return res.status(403).json({ error: 'Unauthorized to update other user profiles' });
    }

    const updatedUser = await User.findByIdAndUpdate(req.params.id, updateData, {
      new: true, // Return the updated document
      runValidators: true, // Run schema validators on update
    }).select('-password');

    if (!updatedUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ message: 'User updated successfully', user: updatedUser });
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

/**
 * DELETE /users/:id
 * Allows deleting a user account.
 * Requires any valid JWT. Users can delete their own account; admins can delete any account.
 */
app.delete('/users/:id', authenticateToken, async (req, res) => {
  try {
    // Only allow deletion if the current user is an admin or is deleting their own account
    if (req.user.role !== 'admin' && req.user.userId !== req.params.id) {
        return res.status(403).json({ error: 'Unauthorized to delete this user' });
    }

    const deletedUser = await User.findByIdAndDelete(req.params.id);

    if (!deletedUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

/**
 * GET /admin/admins
 * Retrieves a list of all users with the 'admin' role.
 * Requires admin token.
 */
app.get('/admin/admins', verifyAdminToken, async (req, res) => {
  try {
    const admins = await User.find({ role: 'admin' }).select('-password');
    res.json(admins);
  } catch (err) {
    console.error('Failed to fetch admins:', err);
    res.status(500).json({ error: 'Server error fetching admins' });
  }
});

// ---

// ## Card Management Routes

/**
 * GET /cards
 * Fetches all existing cards. Publicly accessible.
 */
app.get('/cards', async (req, res) => {
  try {
    const cards = await AddCard.find().sort({ createdAt: -1 });
    res.status(200).json(cards);
  } catch (err) {
    console.error('Failed to fetch cards:', err);
    res.status(500).json({ message: 'Failed to fetch cards', error: err.message });
  }
});

/**
 * GET /cards/:id
 * Fetches a single card by its ID. Publicly accessible.
 */
app.get('/cards/:id', async (req, res) => {
  try {
    const card = await AddCard.findById(req.params.id);
    if (!card) {
      return res.status(404).json({ error: 'Card not found' });
    }
    res.json(card);
  } catch (err) {
    console.error('Failed to fetch card by ID:', err);
    res.status(500).json({ error: 'Failed to fetch card' });
  }
});

/**
 * POST /addcard
 * Allows an admin to add a new card with an image.
 * Requires admin token.
 */
app.post('/addcard', verifyAdminToken, upload.single('image'), async (req, res) => {
  try {
    const { title, description } = req.body;
    const imageUrl = req.file ? `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}` : null;

    if (!title || !description || !imageUrl) {
      // If a file was uploaded but other fields are missing, delete the file to prevent orphaned files
      if (req.file) {
        fs.unlinkSync(req.file.path);
      }
      return res.status(400).json({ error: 'All fields including image are required' });
    }

    const newCard = new AddCard({ title, description, image: imageUrl });
    await newCard.save();
    res.status(201).json({ message: 'Card created successfully', card: newCard });
  } catch (err) {
    console.error('Add card error:', err);
    // If an error occurs after file upload, ensure the uploaded file is removed
    if (req.file) {
      fs.unlinkSync(req.file.path);
    }
    res.status(500).json({ error: 'Server error creating card' });
  }
});

// ---

// ## Server Initialization

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});