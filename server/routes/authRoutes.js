const express = require('express');
const router = express.Router();

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

router.post('/register', register);
router.post('/login', login);
router.post('/verify-email', verifyEmail);
router.post('/forgot-password', forgotPassword);
router.post('/reset-password', resetPassword);
router.get('/logout', authenticateUser, logout);
router.get('/sessions', authenticateUser, getSessions);
router.delete('/sessions/:id', authenticateUser, revokeSession);
router.delete('/sessions', authenticateUser, logoutAllSessions);

module.exports = router;
