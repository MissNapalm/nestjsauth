"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.EmailService = void 0;
const common_1 = require("@nestjs/common");
const nodemailer_1 = __importDefault(require("nodemailer"));
let EmailService = class EmailService {
    constructor() {
        // Create Gmail transporter
        this.transporter = nodemailer_1.default.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.GMAIL_USER,
                pass: process.env.GMAIL_PASS,
            },
        });
    }
    async sendEmail(data) {
        try {
            const result = await this.transporter.sendMail({
                from: process.env.SENDER_EMAIL,
                to: data.to,
                subject: data.subject,
                html: data.html,
                text: data.text,
            });
            console.log('Email sent successfully:', result);
            return result;
        }
        catch (error) {
            console.error('Failed to send email:', error);
            throw error;
        }
    }
    async sendWelcomeEmail(recipientEmail) {
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
};
exports.EmailService = EmailService;
exports.EmailService = EmailService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [])
], EmailService);
//# sourceMappingURL=email.service.js.map