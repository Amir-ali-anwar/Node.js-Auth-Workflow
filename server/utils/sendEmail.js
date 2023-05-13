const nodemailer = require('nodemailer');
const nodemailerConfig = require('./nodemailerconfiguration');

const sendEmail= async ({ to, subject, html })=>{
    let testAccount = await nodemailer.createTestAccount();
    const transporter=  nodemailer.createTransport(nodemailerConfig)
    return transporter.sendMail({
        from: '"Amir Ali Anwar" <amiralianwar611@gmail.com>',
        to,
        subject,
        html
    })
}
module.exports = sendEmail;