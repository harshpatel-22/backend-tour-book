const nodemailer = require('nodemailer');

const sendEmail = async options => {
    //create a transporter
    // Looking to send emails in production? Check out our Email API/SMTP product!
    var transport = nodemailer.createTransport({
        host: 'sandbox.smtp.mailtrap.io',
        port: 2525,
        auth: {
            user: '5694bdac6e99e8',
            pass: 'bd7bb095f111b0'
        }
    });

    //define email options
    const mailOptions = {
        from: 'testmailer <example@gmail.com>',
        to: options.email,
        subject: options.subject,
        text: options.message
    };

    //send the mail

    await transport.sendMail(mailOptions);
};

module.exports = sendEmail;
