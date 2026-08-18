const sendEmail = require('./sendEmail');

const sendResetPasswordEmail = async ({ name, email, token, origin }) => {
  const resetURL = `${origin}/reset-password?token=${token}&email=${encodeURIComponent(
    email
  )}`;
  const message = `<p>Please reset your password by clicking on the following link :
  <a href="${resetURL}">Reset Password</a> (link valid for 10 minutes)</p>`;

  return sendEmail({
    to: email,
    subject: 'Reset Password',
    html: `<h4> Hello, ${name}</h4>
    ${message}
    `,
  });
};

module.exports = sendResetPasswordEmail;
