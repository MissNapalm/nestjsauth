import { Injectable } from '@nestjs/common';
import nodemailer from 'nodemailer';

interface SendEmailDto {
  to: string[];
  subject: string;
  html: string;
  text?: string;
}

// Simple HTML sanitization function
function sanitizeHtml(html: string): string {
  return html
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

@Injectable()
export class EmailService {
  private transporter: any;

  constructor() {
    // Create Gmail transporter with explicit SMTP settings
    this.transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 587,
      secure: false, // Use TLS
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS,
      },
    });
  }

  async sendEmail(data: SendEmailDto): Promise<any> {
    try {
      // Validate email addresses
      if (!Array.isArray(data.to) || data.to.length === 0) {
        throw new Error('Invalid recipient email(s)');
      }

      // Sanitize inputs
      const sanitizedTo = data.to.map(email => {
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          throw new Error(`Invalid email format: ${email}`);
        }
        return email.toLowerCase().trim();
      });

      const result = await this.transporter.sendMail({
        from: process.env.SENDER_EMAIL,
        to: sanitizedTo,
        subject: data.subject.substring(0, 200), // Limit subject length
        html: data.html,
        text: data.text,
      });

      console.log('✓ Email sent successfully');
      return { success: true, result };
    } catch (error) {
      console.error('✗ Email failed:', error.message);
      // Don't throw - return error status instead
      return { success: false, error: error.message };
    }
  }

  async sendWelcomeEmail(recipientEmail: string): Promise<any> {
    const html = `
      <h1>Welcome!</h1>
      <p>Thank you for joining our platform.</p>
      <p>We're excited to have you onboard.</p>
    `;

    return this.sendEmail({
      to: [recipientEmail],
      subject: 'Welcome to Our Platform',
      html,
      text: 'Welcome to Our Platform! Thank you for joining.',
    });
  }
}

