const crypto = require('crypto');

// constant-time string comparison - avoids leaking how many leading
// characters matched via response-time differences
const safeCompare = (a = '', b = '') => {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
};

module.exports = safeCompare;
