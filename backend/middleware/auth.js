'use strict';

const jwt = require('jsonwebtoken');

/**
 * Verifies a JWT token and returns the decoded payload.
 * Returns null on failure instead of throwing, so callers decide the response.
 *
 * @param {string} token - The JWT string to verify
 * @returns {object|null} Decoded payload, or null if invalid/expired
 */
const verifyToken = (token) => {
  try {
    if(!process.env.JWT_SECRET) {
      console.error('[verifyToken] JWT_SECRET is not defined in environment variables');
      return null;
    }
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    console.error('[verifyToken] Verification failed:', err.message);
    return null;
  }
};

/**
 * Authentication middleware.
 * Expects: Authorization: Bearer <token>
 * Attaches decoded payload to req.user on success.
 *
 * @type {import('express').RequestHandler}
 */
const authMiddleware = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ message: 'Authorization header missing' });
    if (!authHeader.startsWith('Bearer ')) return res.status(401).json({ message: 'Invalid authorization format. Use: Bearer <token>' });

    const token = authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ message: 'Token missing' });

    const decoded = verifyToken(token);

    if (!decoded) return res.status(401).json({ message: 'Invalid or expired token' });

    req.user = decoded;
    next();
  } catch (err) {
    console.error('[authMiddleware] Unexpected error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
};

/**
 * Authorization middleware — restricts access to admin users only.
 * Must be used AFTER authMiddleware so req.user is populated.
 *
 * @type {import('express').RequestHandler}
 */
const adminMiddleware = (req, res, next) => {
  if (!req.user) return res.status(401).json({ message: 'Not authenticated' });
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden: admin access required' });
  next();
};

module.exports = { authMiddleware, adminMiddleware, verifyToken };