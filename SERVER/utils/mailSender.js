const nodemailer = require("nodemailer");

const mailSender = async (email, title, body) => {
  try {
    const transporter = nodemailer.createTransport({
      host: process.env.MAIL_HOST,
      port: process.env.MAIL_PORT,
      secure: false, // Set to true for port 465, false for 587 or 2525
      auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASS,
      },
    });

    const info = await transporter.sendMail({
      from: `"${process.env.EMAIL_FROM}" <${process.env.MAIL_USER}>`,
      to: email,
      subject: title,
      html: body,
    });

    console.log("Mail sent successfully:", info.response);
    return info;
  } catch (error) {
    console.error("Error sending email:", error.message);
    throw error;
  }
};

module.exports = mailSender;
