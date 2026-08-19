const express = require('express');
const router = express.Router();
const rateLimiter = require('express-rate-limit');

const {
  register,
  login,
  logout,
  logoutAllSessions,
  getSessions,
  revokeSession,
  verifyEmail,
  forgotPassword,
  resetPassword,
} = require('../controllers/authController');
const { authenticateUser } = require('../middleware/authentication');

// tighter than the app-wide limiter (60/15min) - these endpoints are the
// ones credential-stuffing/enumeration/spam attempts actually target
const authLimiter = rateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { msg: 'Too many requests, please try again later.' },
});

router.post('/register', authLimiter, register);
router.post('/login', authLimiter, login);
router.post('/verify-email', authLimiter, verifyEmail);
router.post('/forgot-password', authLimiter, forgotPassword);
router.post('/reset-password', authLimiter, resetPassword);
router.delete('/logout', authenticateUser, logout);
router.get('/sessions', authenticateUser, getSessions);
router.delete('/sessions/:id', authenticateUser, revokeSession);
router.delete('/sessions', authenticateUser, logoutAllSessions);

module.exports = router;
