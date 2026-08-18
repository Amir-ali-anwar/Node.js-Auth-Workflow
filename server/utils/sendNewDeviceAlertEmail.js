const sendEmail = require('./sendEmail');

const sendNewDeviceAlertEmail = async ({ name, email, ip, userAgent }) => {
  const message = `<p>We noticed a login to your account from a new device or location:</p>
  <ul>
    <li>IP address: ${ip}</li>
    <li>Device: ${userAgent}</li>
    <li>Time: ${new Date().toUTCString()}</li>
  </ul>
  <p>If this was you, no action is needed. If you don't recognize this activity, please reset your password immediately.</p>`;

  return sendEmail({
    to: email,
    subject: 'New login to your account',
    html: `<h4> Hello, ${name}</h4>
    ${message}
    `,
  });
};

module.exports = sendNewDeviceAlertEmail;
