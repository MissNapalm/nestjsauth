"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
require("dotenv/config");
const nodemailer_1 = __importDefault(require("nodemailer"));
/**
 * Script to send emails using Mailtrap SMTP service
 * Make sure to set Mailtrap credentials in .env file
 *
 * Usage: npm run send-email
 */
const transporter = nodemailer_1.default.createTransport({
    host: process.env.MAILTRAP_HOST,
    port: parseInt(process.env.MAILTRAP_PORT || '587'),
    auth: {
        user: process.env.MAILTRAP_USER,
        pass: process.env.MAILTRAP_PASS,
    },
});
const recipients = ['captainaptos1@gmail.com', 'cybersecsarah99@gmail.com', 'cexivob258@cimario.com'];
async function sendEmails() {
    console.log('Starting email sending process...');
    console.log(`Recipients: ${recipients.join(', ')}`);
    try {
        const result = await transporter.sendMail({
            from: process.env.SENDER_EMAIL,
            to: recipients,
            subject: 'Welcome to Our Service',
            html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h1 style="color: #333;">Welcome to Our Service!</h1>
          <p style="color: #666; font-size: 16px;">
            Thank you for being part of our community. We're excited to have you onboard.
          </p>
          <div style="background-color: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <h2 style="color: #333;">What's Next?</h2>
            <ul style="color: #666;">
              <li>Explore our platform features</li>
              <li>Set up your profile</li>
              <li>Connect with other users</li>
            </ul>
          </div>
          <p style="color: #999; font-size: 12px; margin-top: 30px;">
            If you have any questions, feel free to reach out to our support team.
          </p>
        </div>
      `,
            text: 'Welcome to Our Service! Thank you for being part of our community. We are excited to have you onboard.',
        });
        console.log('✓ Emails sent successfully!');
        console.log('Message ID:', result.messageId);
        console.log('\nCheck your Mailtrap inbox: https://mailtrap.io/inboxes');
    }
    catch (error) {
        console.error('✗ Failed to send emails:', error);
        process.exit(1);
    }
}
sendEmails();
//# sourceMappingURL=send-email.js.map