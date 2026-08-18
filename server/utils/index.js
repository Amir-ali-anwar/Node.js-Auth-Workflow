const { createJWT, isTokenValid, attachCookiesToResponse } = require('./jwt');
const createTokenUser = require('./createTokenUser');
const checkPermissions = require('./checkPermissions');
const sendVerificationEmail=require('./sendVerificationEmail')
const sendResetPasswordEmail = require('./sendResetPasswordEmail');
const sendNewDeviceAlertEmail = require('./sendNewDeviceAlertEmail');
const createHash = require('./createHash');
const validatePasswordStrength = require('./validatePasswordStrength');
module.exports = {
  createJWT,
  isTokenValid,
  attachCookiesToResponse,
  createTokenUser,
  checkPermissions,
  sendVerificationEmail,
  sendResetPasswordEmail,
  sendNewDeviceAlertEmail,
  createHash,
  validatePasswordStrength,
};
