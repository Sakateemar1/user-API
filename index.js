const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const app = express();
require('dotenv').config();

const mongoURI = process.env.DATABASE_URI;
const port = process.env.PORT || 4000;

mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch((err) => {
    console.error('Error connecting to MongoDB:', err);
  });

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  age: {
    type: Number,
  },
  phoneNo: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    match: /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$/,
  },
  password: {
    type: String,
    required: true,
    match: /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$/,
  },
});

const User = mongoose.model('User', userSchema);
app.use(express.json());

// Create a Token model and schema for MongoDB
const tokenSchema = new mongoose.Schema({
  token: {
    type: String,
    required: true,
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
  },
});

const Token = mongoose.model('Token', tokenSchema);

function generateCustomToken(user) {
  const token = crypto.randomBytes(32).toString('hex');

  // Store the token in the database
  const newToken = new Token({
    token,
    userId: user._id,
  });

  newToken.save();

  return token;
}

async function verifyCustomToken(req, res, next) {
  const token = req.header('Authorization');

  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  try {
    const tokenDocument = await Token.findOne({ token });

    if (!tokenDocument) {
      return res.status(401).json({ error: 'Invalid token.' });
    }

    req.userId = tokenDocument.userId;
    next();
  } catch (error) {
    console.error('Token verification error:', error);
    return res.status(401).json({ error: 'Invalid token.' });
  }
}

app.post('/register', async (req, res) => {
  try {
    const { name, age, phoneNo, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, age, phoneNo, email, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Error registering user'});
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = generateCustomToken(user);

    res.json({ message: 'Login successful', token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error logging in' });
  }
});

app.get('/profile', verifyCustomToken, (req, res) => {
  res.json({ message: `Welcome to your profile ${req.userId}!` });
});

app.post('/logout', (req, res) => {
  // Remove the token from the database when logging out
  const token = req.header('Authorization');

  Token.deleteOne({ token }, (err) => {
    if (err) {
      return res.status(500).json({ error: 'Error logging out' });
    }
    res.json({ message: 'Logout successful' });
  });
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
