const jwt = require('jsonwebtoken');// (jsonWebToken) for JWT authentication
//require('dotenv').config();
//const secretKey = process.env.JWT_SECRET;
const config = require('./config');
const secretKey = config.secretKey;


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
    console.error('Token verification error:', error);
    return res.status(401).json({ error: 'Invalid token.' });
  }
}


   // Function to generate a JWT token(based on provided user information)
   function generateToken(user) {
    try {
      const token = jwt.sign({ userId: user._id }, secretKey, {
        expiresIn: '1h', // Token expiration time (adjust as needed)
      });
      return token;
    } catch (error) {
      console.error('Token generation error:', error);
      throw error;
    }
  }

module.exports = {generateToken, verifyToken};
