require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/furni', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');
});

// User Schema
const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Security Middleware
app.use(helmet());
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Rate limiting for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later'
});

// Apply to auth routes
app.use('/api/signin', authLimiter);
app.use('/api/signup', authLimiter);
app.use('/api/forgot-password', authLimiter);
app.use('/api/reset-password', authLimiter);

// Email transporter configuration
const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE || 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Verify transporter
transporter.verify((error, success) => {
  if (error) {
    console.error('Error with mail config:', error);
  } else {
    console.log('Server is ready to send emails');
  }
});

// In-memory storage for reset tokens (use database in production)
const resetTokens = new Map();

// Generate JWT Token
const generateToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET || 'your-secret-key', {
    expiresIn: '1h'
  });
};

// Signup endpoint with MongoDB
app.post('/api/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password, confirmPassword } = req.body;

    // Validate input
    if (!firstName || !email || !password || !confirmPassword) {
      return res.status(400).json({ 
        success: false, 
        message: 'All fields are required' 
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ 
        success: false, 
        message: 'Passwords do not match' 
      });
    }

    if (password.length < 8) {
      return res.status(400).json({ 
        success: false, 
        message: 'Password must be at least 8 characters' 
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email already in use' 
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const newUser = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword
    });

    await newUser.save();

    // Send welcome email
    const mailOptions = {
      from: process.env.EMAIL_FROM,
      to: email,
      subject: 'Welcome to Furni!',
      html: `
        <h2>Welcome to Furni, ${firstName}!</h2>
        <p>Thank you for creating an account with us.</p>
        <p>Start exploring our furniture collection and create your perfect space.</p>
        <a href="http://localhost:3000/shop" style="
          display: inline-block;
          padding: 10px 20px;
          background-color: #0d6efd;
          color: white;
          text-decoration: none;
          border-radius: 5px;
          margin-top: 15px;
        ">Start Shopping</a>
        <p>If you didn't create this account, please contact us immediately.</p>
      `
    };

    await transporter.sendMail(mailOptions);
    
    // Generate token
    const token = generateToken(newUser._id);
    
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error creating account' 
    });
  }
});

// Signin endpoint with MongoDB


app.post('/api/signin', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email and password are required' 
      });
    }

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid credentials' 
      });
    }

    // Compare passwords
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid credentials' 
      });
    }

    // Generate token
    const token = generateToken(user._id);
    
    res.status(200).json({ 
      success: true, 
      message: 'Sign in successful',
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email
      },
      redirect: '/dashboard.html'
    });
  } catch (error) {
    console.error('Signin error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error signing in' 
    });
  }
});

// Forgot password endpoint
app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email is required' 
      });
    }

    // In a real app, check if email exists in database
    // For demo, we'll proceed regardless

    // Generate token
    const token = crypto.randomBytes(20).toString('hex');
    resetTokens.set(email, {
      token,
      expires: Date.now() + 3600000 // 1 hour
    });
    
    // Create reset link
    const resetLink = `http://localhost:3000/reset-password.html?token=${token}&email=${encodeURIComponent(email)}`;
    
    const mailOptions = {
      from: process.env.EMAIL_FROM,
      to: email,
      subject: 'Password Reset Request',
      html: `
        <h3>Password Reset</h3>
        <p>You requested a password reset. Click the link below to proceed:</p>
        <a href="${resetLink}" style="
          display: inline-block;
          padding: 10px 20px;
          background-color: #0d6efd;
          color: white;
          text-decoration: none;
          border-radius: 5px;
          margin: 15px 0;
        ">Reset Password</a>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn't request this, please ignore this email.</p>
      `
    };
    
    await transporter.sendMail(mailOptions);
    res.status(200).json({ 
      success: true, 
      message: 'Reset link sent to your email' 
    });
  } catch (error) {
    console.error('Password reset error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error sending reset email' 
    });
  }
});

// Reset password endpoint
app.post('/api/reset-password', async (req, res) => {
  try {
    const { email, token, newPassword } = req.body;
    
    // Validate input
    if (!email || !token || !newPassword) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email, token and new password are required' 
      });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ 
        success: false, 
        message: 'Password must be at least 8 characters' 
      });
    }
    
    // Check token
    const storedToken = resetTokens.get(email);
    
    if (!storedToken || storedToken.token !== token) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid or expired token' 
      });
    }
    
    if (storedToken.expires < Date.now()) {
      resetTokens.delete(email);
      return res.status(400).json({ 
        success: false, 
        message: 'Token has expired' 
      });
    }
    
    // In a real app:
    // 1. Find user by email
    // 2. Hash the new password
    // 3. Update user's password in database
    
    // Send confirmation email
    const mailOptions = {
      from: process.env.EMAIL_FROM,
      to: email,
      subject: 'Password Changed Successfully',
      html: `
        <h3>Password Updated</h3>
        <p>Your password has been successfully changed.</p>
        <p>If you didn't make this change, please contact us immediately.</p>
      `
    };
    
    await transporter.sendMail(mailOptions);
    
    // Remove used token
    resetTokens.delete(email);
    
    res.status(200).json({ 
      success: true, 
      message: 'Password updated successfully' 
    });
  } catch (error) {
    console.error('Password update error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error updating password' 
    });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK',
    message: 'Server is running',
    timestamp: new Date().toISOString()
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    success: false, 
    message: 'Something broke!' 
  });
});


// Authentication middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ 
        success: false, 
        message: 'No token provided' 
      });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        message: 'User not found' 
      });
    }
    
    req.user = user;
    next();
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(401).json({ 
      success: false, 
      message: 'Invalid token' 
    });
  }
};

// Protected route example
app.get('/api/profile', authenticate, (req, res) => {
  res.status(200).json({ 
    success: true, 
    user: {
      id: req.user._id,
      firstName: req.user.firstName,
      lastName: req.user.lastName,
      email: req.user.email
    }
  });
});

// Start server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
