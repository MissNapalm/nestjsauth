"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
require("dotenv/config");
const nodemailer_1 = __importDefault(require("nodemailer"));
// Create Gmail transporter
const transporter = nodemailer_1.default.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS,
    },
});
async function sendEmails() {
    try {
        console.log('Sending email via Gmail SMTP...');
        const result = await transporter.sendMail({
            from: process.env.SENDER_EMAIL,
            to: ['captainaptos1@gmail.com', 'cybersecsarah99@gmail.com', 'cexivob258@cimario.com'],
            subject: 'Welcome!',
            html: `
        <h1>Welcome to Our Service!</h1>
        <p>This is a test email from NestJS with Gmail SMTP.</p>
        <p>Emails sent to all recipients!</p>
      `,
            text: 'Welcome! This is a test email from NestJS with Gmail SMTP.',
        });
        console.log('✓ Email sent successfully!');
        console.log('Message ID:', result.messageId);
        console.log('\n✓ Check your Gmail inbox for the emails!');
    }
    catch (error) {
        console.error('✗ Error sending email:', error);
        process.exit(1);
    }
}
sendEmails();
//# sourceMappingURL=send-email.js.map