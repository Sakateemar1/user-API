//importing necessary modules
const express = require('express');//express.js(this is a framework)
const mongoose = require('mongoose');// for interactin with mongodb
const jwt = require('jsonwebtoken');// (jsonWebToken) for JWT authentication
const session = require('express-session');//for  session management
const bcrypt = require('bcrypt');// for hashing password
const app = express();// setting up an express application
require('dotenv').config();//loading an enviroment variable form an .env file

// accessing the enviroment variables.
const mongoURI = process.env.DATABASE_URI;
const secretKey = process.env.SECRET_KEY;

//using the secretKey
//const mySecret= secretKey

//declaring the port number 
const port = process.env.PORT || 4000; // Changed the default port

//define an object containing options for configuring the mongodb connection
const mongooseOptions = {
  useNewUrlParser: true,
  useUnifiedTopology: true,
};

//Connecting  to the MongoDB database using mongoose and loging a success or error message
mongoose.connect(mongoURI, mongooseOptions)
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch((err) => {
    console.error('Error connecting to MongoDB:', err);
  });


  // Define the Mongoose schema for the "User" collection
  const userSchema = new mongoose.Schema({
    name: {
      type: String,
      required: true,//Name is a required field
    },
    age: {
      type: Number,
    },

    phoneNo:{
        type: String,
        required: true,//phoneNo is required
    },
    email: {
      type: String,
      required: true, // Email is now a required field
      match: /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$/, // validating the email using regex(regular expression)
    },
    password: {
      type: String,
      required: true, // Password is now a required field
      match: /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$/,
  
    },

  });

  // createing a mongoose model called user based on the schema
  const User = mongoose.model('User', userSchema);

  // Middleware to parse JSON requests bodies
    app.use(express.json());

    // Middleware for  managing user session
    app.use(session({
        secret: secretKey,
        resave: false,
        saveUninitialized: false,
     }));

     // Function to generate a JWT token(based on provided user information)
    function generateToken(user) {
    return jwt.sign({ userId: user._id }, secretKey, {
    expiresIn: '1h', // Token expiration time (adjust as needed)
    });
    }

    // Registration Route
    app.post('/register', async (req, res) => {
  try {
    const { name, age, phoneNo, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, age, phoneNo, email, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Error registering user' });
  }
});


    // Login Route
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
  
      // Generate a JWT token with user information
      const token = generateToken(user);
  
         // Send the token in the response
    res.json({ message: 'Login successful', token });
    } catch (error) {
     res.status(500).json({ error: 'Error logging in' });
        }
    });

        // Middleware to verify JWT tokens
    function verifyToken(req, res, next) {
    const token = req.header('Authorization');
  
    if (!token) {
      return res.status(401).json({ error: 'Access denied. No token provided.' });
    }
  
    try {
      const decoded = jwt.verify(token, secretKey);
      req.userId = decoded.userId;
      next();
    } catch (error) {
      res.status(401).json({ error: 'Invalid token.' });
    }
  }
  //Protected Route (Example: Dashboard)
  app.get('/dashboard', verifyToken, (req, res) => {
    // You can access the user's ID through req.userId
    res.json({ message: `Welcome to your dashboard, user with ID ${req.userId}!` });
  });
  
  // Logout Route 
  app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({ error: 'Error logging out' });
      }
      res.json({ message: 'Logout successful' });
    });
  });

  app.listen(port|| 4000, () => {
    console.log(`Server is running on port ${port}`);
  });