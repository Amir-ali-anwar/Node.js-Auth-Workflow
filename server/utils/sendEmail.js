const nodemailer = require('nodemailer');
const nodemailerConfig = require('./nodemailerconfiguration');

const sendEmail= async ({ to, subject, html })=>{
    const transporter=  nodemailer.createTransport(nodemailerConfig)
    return transporter.sendMail({
        from: process.env.EMAIL_FROM,
        to,
        subject,
        html
    })
}
module.exports = sendEmail;