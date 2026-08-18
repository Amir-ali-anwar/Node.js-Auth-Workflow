const https = require('https');
const crypto = require('crypto');

// k-anonymity check against the HaveIBeenPwned breached-password corpus:
// only a 5-char SHA-1 prefix ever leaves the server, never the password itself
const checkPwnedPassword = (password) => {
  return new Promise((resolve) => {
    const sha1 = crypto
      .createHash('sha1')
      .update(password)
      .digest('hex')
      .toUpperCase();
    const prefix = sha1.slice(0, 5);
    const suffix = sha1.slice(5);

    const req = https.request(
      {
        hostname: 'api.pwnedpasswords.com',
        path: `/range/${prefix}`,
        method: 'GET',
        timeout: 3000,
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          const isPwned = data
            .split('\n')
            .some((line) => line.split(':')[0].trim() === suffix);
          resolve(isPwned);
        });
      }
    );
    // fail-open: if the breach-check service is unreachable, don't block the user
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
    req.end();
  });
};

module.exports = checkPwnedPassword;
