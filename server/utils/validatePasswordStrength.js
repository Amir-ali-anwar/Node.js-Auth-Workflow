const zxcvbn = require('zxcvbn');
const CustomError = require('../errors');
const checkPwnedPassword = require('./checkPwnedPassword');

const MIN_SCORE = 2; // zxcvbn scores 0 (too guessable) - 4 (very unguessable)

const validatePasswordStrength = async (password, userInputs = []) => {
  const { score, feedback } = zxcvbn(password, userInputs);
  if (score < MIN_SCORE) {
    const suggestion =
      feedback.warning || feedback.suggestions[0] || 'Please choose a stronger password.';
    throw new CustomError.BadRequestError(`Password is too weak. ${suggestion}`);
  }

  const isPwned = await checkPwnedPassword(password);
  if (isPwned) {
    throw new CustomError.BadRequestError(
      'This password has appeared in a known data breach. Please choose a different password.'
    );
  }
};

module.exports = validatePasswordStrength;
