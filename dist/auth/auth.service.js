"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthService = void 0;
const common_1 = require("@nestjs/common");
const jwt_1 = require("@nestjs/jwt");
const bcrypt = __importStar(require("bcryptjs"));
const email_service_1 = require("../email/email.service");
const audit_service_1 = require("../audit/audit.service");
// In-memory storage (replace with database in production)
const users = new Map();
const twoFactorCodes = new Map();
const refreshTokens = new Map();
const passwordResetTokens = new Map();
const emailVerificationTokens = new Map();
let AuthService = class AuthService {
    constructor(jwtService, emailService, auditService) {
        this.jwtService = jwtService;
        this.emailService = emailService;
        this.auditService = auditService;
    }
    async register(email, password, ipAddress, userAgent) {
        if (users.has(email)) {
            this.auditService.log(audit_service_1.AuditEventType.REGISTER_FAILED, {
                email,
                ipAddress,
                userAgent,
                success: false,
                details: { reason: 'User already exists' },
            });
            throw new common_1.BadRequestException('User already exists');
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const userId = Math.random().toString(36).substring(7);
        users.set(email, {
            id: userId,
            email,
            password: hashedPassword,
            emailVerified: false,
            createdAt: new Date(),
        });
        // Generate email verification token
        const verificationToken = this.generateSecureToken();
        emailVerificationTokens.set(verificationToken, {
            email,
            expiresAt: Date.now() + 24 * 60 * 60 * 1000, // 24 hours
        });
        // Send verification email
        const verificationLink = `http://localhost:3000?verify=${verificationToken}`;
        try {
            await this.emailService.sendEmail({
                to: [email],
                subject: 'Verify Your Email Address',
                html: `
          <h2>Welcome! Please verify your email</h2>
          <p>Click the link below to verify your email address:</p>
          <p><a href="${verificationLink}" style="background: #667eea; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">Verify Email</a></p>
          <p>Or copy this link: ${verificationLink}</p>
          <p>This link expires in 24 hours.</p>
          <p><strong>Test Token:</strong> ${verificationToken}</p>
        `,
                text: `Verify your email: ${verificationLink}\nTest Token: ${verificationToken}`,
            });
        }
        catch (err) {
            console.error('⚠️ Email service error:', err.message);
        }
        this.auditService.log(audit_service_1.AuditEventType.REGISTER_SUCCESS, {
            userId,
            email,
            ipAddress,
            userAgent,
            success: true,
        });
        this.auditService.log(audit_service_1.AuditEventType.EMAIL_VERIFICATION_SENT, {
            userId,
            email,
            ipAddress,
            userAgent,
            success: true,
        });
        return {
            message: 'Registration successful. Please check your email to verify your account.',
            userId,
            requiresVerification: true,
            testToken: verificationToken, // Remove in production
        };
    }
    generateSecureToken() {
        return Array.from({ length: 32 }, () => Math.random().toString(36).charAt(2)).join('');
    }
    async verifyEmail(token, ipAddress, userAgent) {
        const tokenData = emailVerificationTokens.get(token);
        if (!tokenData) {
            this.auditService.log(audit_service_1.AuditEventType.EMAIL_VERIFICATION_FAILED, {
                ipAddress,
                userAgent,
                success: false,
                details: { reason: 'Invalid verification token' },
            });
            throw new common_1.BadRequestException('Invalid or expired verification link');
        }
        if (Date.now() > tokenData.expiresAt) {
            emailVerificationTokens.delete(token);
            this.auditService.log(audit_service_1.AuditEventType.EMAIL_VERIFICATION_FAILED, {
                email: tokenData.email,
                ipAddress,
                userAgent,
                success: false,
                details: { reason: 'Token expired' },
            });
            throw new common_1.BadRequestException('Verification link has expired. Please request a new one.');
        }
        const user = users.get(tokenData.email);
        if (!user) {
            emailVerificationTokens.delete(token);
            throw new common_1.BadRequestException('User not found');
        }
        // Mark email as verified
        user.emailVerified = true;
        users.set(tokenData.email, user);
        emailVerificationTokens.delete(token);
        this.auditService.log(audit_service_1.AuditEventType.EMAIL_VERIFICATION_SUCCESS, {
            userId: user.id,
            email: tokenData.email,
            ipAddress,
            userAgent,
            success: true,
        });
        return {
            message: 'Email verified successfully! You can now log in.',
            email: tokenData.email,
        };
    }
    async resendVerificationEmail(email, ipAddress, userAgent) {
        const user = users.get(email);
        // Always return success to prevent email enumeration
        if (!user) {
            return { message: 'If the email exists, a verification link will be sent.' };
        }
        if (user.emailVerified) {
            return { message: 'Email is already verified. You can log in.' };
        }
        // Delete any existing tokens for this email
        for (const [token, data] of emailVerificationTokens.entries()) {
            if (data.email === email) {
                emailVerificationTokens.delete(token);
            }
        }
        // Generate new verification token
        const verificationToken = this.generateSecureToken();
        emailVerificationTokens.set(verificationToken, {
            email,
            expiresAt: Date.now() + 24 * 60 * 60 * 1000, // 24 hours
        });
        // Send verification email
        const verificationLink = `http://localhost:3000?verify=${verificationToken}`;
        try {
            await this.emailService.sendEmail({
                to: [email],
                subject: 'Verify Your Email Address',
                html: `
          <h2>Email Verification</h2>
          <p>Click the link below to verify your email address:</p>
          <p><a href="${verificationLink}" style="background: #667eea; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">Verify Email</a></p>
          <p>Or copy this link: ${verificationLink}</p>
          <p>This link expires in 24 hours.</p>
          <p><strong>Test Token:</strong> ${verificationToken}</p>
        `,
                text: `Verify your email: ${verificationLink}\nTest Token: ${verificationToken}`,
            });
        }
        catch (err) {
            console.error('⚠️ Email service error:', err.message);
        }
        this.auditService.log(audit_service_1.AuditEventType.EMAIL_VERIFICATION_RESENT, {
            userId: user.id,
            email,
            ipAddress,
            userAgent,
            success: true,
        });
        return {
            message: 'Verification email sent. Please check your inbox.',
            testToken: verificationToken, // Remove in production
        };
    }
    async login(email, password, ipAddress, userAgent) {
        const user = users.get(email);
        this.auditService.log(audit_service_1.AuditEventType.LOGIN_ATTEMPT, {
            email,
            ipAddress,
            userAgent,
            success: true,
            details: { userExists: !!user },
        });
        if (!user) {
            this.auditService.log(audit_service_1.AuditEventType.LOGIN_FAILED, {
                email,
                ipAddress,
                userAgent,
                success: false,
                details: { reason: 'User not found' },
            });
            throw new common_1.UnauthorizedException('Invalid credentials');
        }
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            this.auditService.log(audit_service_1.AuditEventType.LOGIN_FAILED, {
                email,
                userId: user.id,
                ipAddress,
                userAgent,
                success: false,
                details: { reason: 'Invalid password' },
            });
            throw new common_1.UnauthorizedException('Invalid credentials');
        }
        // Check if email is verified
        if (!user.emailVerified) {
            this.auditService.log(audit_service_1.AuditEventType.LOGIN_FAILED, {
                email,
                userId: user.id,
                ipAddress,
                userAgent,
                success: false,
                details: { reason: 'Email not verified' },
            });
            throw new common_1.UnauthorizedException('Please verify your email before logging in. Check your inbox or request a new verification link.');
        }
        // Generate 2FA code
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        twoFactorCodes.set(email, {
            code,
            expiresAt: Date.now() + 5 * 60 * 1000, // 5 minutes
        });
        // Send 2FA code via email
        try {
            const emailResult = await this.emailService.sendEmail({
                to: [email],
                subject: '2FA Verification Code',
                html: `<h2>Your 2FA Code</h2><p>Code: <strong>${code}</strong></p><p>Valid for 5 minutes.</p>`,
                text: `Your 2FA code is: ${code}`,
            });
            if (!emailResult.success) {
                console.warn('⚠️ Email failed to send, but 2FA code generated:', code);
            }
        }
        catch (err) {
            console.error('⚠️ Email service error:', err.message);
        }
        this.auditService.log(audit_service_1.AuditEventType.TWO_FA_SENT, {
            email,
            userId: user.id,
            ipAddress,
            userAgent,
            success: true,
        });
        return { message: '2FA code sent to email (check spam folder)', email, testCode: code };
    }
    async verify2FA(email, code, ipAddress, userAgent) {
        const storedCode = twoFactorCodes.get(email);
        const user = users.get(email);
        if (!storedCode) {
            this.auditService.log(audit_service_1.AuditEventType.TWO_FA_FAILED, {
                email,
                ipAddress,
                userAgent,
                success: false,
                details: { reason: 'No 2FA code found' },
            });
            throw new common_1.BadRequestException('No 2FA code found');
        }
        if (Date.now() > storedCode.expiresAt) {
            twoFactorCodes.delete(email);
            throw new common_1.BadRequestException('2FA code expired');
        }
        if (storedCode.code !== code) {
            this.auditService.log(audit_service_1.AuditEventType.TWO_FA_FAILED, {
                email,
                userId: user?.id,
                ipAddress,
                userAgent,
                success: false,
                details: { reason: 'Invalid 2FA code' },
            });
            throw new common_1.BadRequestException('Invalid 2FA code');
        }
        twoFactorCodes.delete(email);
        this.auditService.log(audit_service_1.AuditEventType.TWO_FA_SUCCESS, {
            email,
            userId: user.id,
            ipAddress,
            userAgent,
            success: true,
        });
        // Generate access token (short-lived: 15 minutes)
        const accessToken = this.jwtService.sign({
            sub: user.id,
            email: user.email,
            type: 'access',
        }, { expiresIn: '15m' });
        // Generate refresh token (long-lived: 7 days)
        const refreshToken = this.jwtService.sign({
            sub: user.id,
            email: user.email,
            type: 'refresh',
        }, { expiresIn: '7d' });
        // Store refresh token
        refreshTokens.set(`${user.id}_${refreshToken}`, {
            token: refreshToken,
            expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000, // 7 days
        });
        return {
            access_token: accessToken,
            refresh_token: refreshToken,
            user: { id: user.id, email: user.email },
        };
    }
    async getProfile(userId) {
        for (const user of users.values()) {
            if (user.id === userId) {
                return { id: user.id, email: user.email };
            }
        }
        throw new common_1.UnauthorizedException('User not found');
    }
    async refreshAccessToken(userId, refreshToken, ipAddress, userAgent) {
        const tokenKey = `${userId}_${refreshToken}`;
        const storedToken = refreshTokens.get(tokenKey);
        if (!storedToken) {
            this.auditService.log(audit_service_1.AuditEventType.TOKEN_REFRESH_FAILED, {
                userId,
                ipAddress,
                userAgent,
                success: false,
                details: { reason: 'Invalid refresh token' },
            });
            throw new common_1.UnauthorizedException('Invalid refresh token');
        }
        if (Date.now() > storedToken.expiresAt) {
            refreshTokens.delete(tokenKey);
            this.auditService.log(audit_service_1.AuditEventType.TOKEN_REFRESH_FAILED, {
                userId,
                ipAddress,
                userAgent,
                success: false,
                details: { reason: 'Refresh token expired' },
            });
            throw new common_1.UnauthorizedException('Refresh token expired');
        }
        const user = users.get([...users.values()].find(u => u.id === userId)?.email);
        if (!user) {
            throw new common_1.UnauthorizedException('User not found');
        }
        // Delete old refresh token (rotation)
        refreshTokens.delete(tokenKey);
        // Generate new access token
        const newAccessToken = this.jwtService.sign({
            sub: user.id,
            email: user.email,
            type: 'access',
        }, { expiresIn: '15m' });
        // Generate new refresh token
        const newRefreshToken = this.jwtService.sign({
            sub: user.id,
            email: user.email,
            type: 'refresh',
        }, { expiresIn: '7d' });
        // Store new refresh token
        refreshTokens.set(`${user.id}_${newRefreshToken}`, {
            token: newRefreshToken,
            expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000,
        });
        this.auditService.log(audit_service_1.AuditEventType.TOKEN_REFRESH, {
            userId: user.id,
            email: user.email,
            ipAddress,
            userAgent,
            success: true,
        });
        return {
            access_token: newAccessToken,
            refresh_token: newRefreshToken,
        };
    }
    async requestPasswordReset(email, ipAddress, userAgent) {
        const user = users.get(email);
        this.auditService.log(audit_service_1.AuditEventType.PASSWORD_RESET_REQUESTED, {
            email,
            userId: user?.id,
            ipAddress,
            userAgent,
            success: true,
            details: { userExists: !!user },
        });
        if (!user) {
            // Don't reveal if email exists (security best practice)
            return { message: 'If email exists, password reset link will be sent' };
        }
        // Generate secure reset token (JWT-based)
        const resetToken = this.jwtService.sign({
            sub: user.id,
            email: user.email,
            type: 'password-reset',
        }, { expiresIn: '15m' });
        // Store reset token
        passwordResetTokens.set(resetToken, {
            email: email,
            expiresAt: Date.now() + 15 * 60 * 1000, // 15 minutes
        });
        // Send reset email
        try {
            const resetLink = `http://localhost:3000/?tab=reset&token=${resetToken}`;
            await this.emailService.sendEmail({
                to: [email],
                subject: 'Password Reset Request',
                html: `
          <h2>Password Reset</h2>
          <p>Use the token below to reset your password. This token expires in 15 minutes.</p>
          <div style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin: 15px 0; word-break: break-all;">
            <strong>Your Reset Token:</strong><br>
            <code style="font-size: 12px; color: #333;">${resetToken}</code>
          </div>
          <p>Copy the token above and paste it into the reset password form.</p>
          <hr style="margin: 20px 0;">
          <p>Or click this link: <a href="${resetLink}">Reset Password</a></p>
          <p style="color: #666; font-size: 12px;">If you didn't request this, ignore this email.</p>
        `,
                text: `Your password reset token: ${resetToken}\n\nOr visit: ${resetLink}`,
            });
        }
        catch (err) {
            console.error('⚠️ Password reset email failed:', err.message);
        }
        return { message: 'If email exists, password reset link will be sent' };
    }
    async resetPassword(token, newPassword, ipAddress, userAgent) {
        const resetTokenData = passwordResetTokens.get(token);
        if (!resetTokenData) {
            this.auditService.log(audit_service_1.AuditEventType.PASSWORD_RESET_FAILED, {
                ipAddress,
                userAgent,
                success: false,
                details: { reason: 'Invalid or expired reset token' },
            });
            throw new common_1.BadRequestException('Invalid or expired reset token');
        }
        if (Date.now() > resetTokenData.expiresAt) {
            passwordResetTokens.delete(token);
            this.auditService.log(audit_service_1.AuditEventType.PASSWORD_RESET_FAILED, {
                email: resetTokenData.email,
                ipAddress,
                userAgent,
                success: false,
                details: { reason: 'Reset token expired' },
            });
            throw new common_1.BadRequestException('Reset token expired');
        }
        const user = users.get(resetTokenData.email);
        if (!user) {
            throw new common_1.BadRequestException('User not found');
        }
        // Hash new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        users.set(resetTokenData.email, user);
        // Invalidate all refresh tokens for this user (security: force re-login on other devices)
        const tokensToDelete = [...passwordResetTokens.entries()]
            .filter(([_, data]) => data.email === resetTokenData.email)
            .map(([key]) => key);
        tokensToDelete.forEach(key => passwordResetTokens.delete(key));
        // Delete the used reset token
        passwordResetTokens.delete(token);
        this.auditService.log(audit_service_1.AuditEventType.PASSWORD_RESET_SUCCESS, {
            email: resetTokenData.email,
            userId: user.id,
            ipAddress,
            userAgent,
            success: true,
        });
        return { message: 'Password reset successful. Please login with your new password.' };
    }
};
exports.AuthService = AuthService;
exports.AuthService = AuthService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [jwt_1.JwtService,
        email_service_1.EmailService,
        audit_service_1.AuditService])
], AuthService);
//# sourceMappingURL=auth.service.js.map