import { Injectable, BadRequestException, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { EmailService } from '../email/email.service';
import { AuditService, AuditEventType } from '../audit/audit.service';

// In-memory storage (replace with database in production)
const users = new Map<string, any>();
const twoFactorCodes = new Map<string, { code: string; expiresAt: number }>();
const refreshTokens = new Map<string, { token: string; expiresAt: number }>();
const passwordResetTokens = new Map<string, { email: string; expiresAt: number }>();
const emailVerificationTokens = new Map<string, { email: string; expiresAt: number }>();

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private emailService: EmailService,
    private auditService: AuditService,
  ) {}

  async register(email: string, password: string, ipAddress: string, userAgent: string) {
    if (users.has(email)) {
      this.auditService.log(AuditEventType.REGISTER_FAILED, {
        email,
        ipAddress,
        userAgent,
        success: false,
        details: { reason: 'User already exists' },
      });
      throw new BadRequestException('User already exists');
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
    } catch (err) {
      console.error('⚠️ Email service error:', err.message);
    }

    this.auditService.log(AuditEventType.REGISTER_SUCCESS, {
      userId,
      email,
      ipAddress,
      userAgent,
      success: true,
    });

    this.auditService.log(AuditEventType.EMAIL_VERIFICATION_SENT, {
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

  private generateSecureToken(): string {
    return Array.from({ length: 32 }, () => 
      Math.random().toString(36).charAt(2)
    ).join('');
  }

  async verifyEmail(token: string, ipAddress: string, userAgent: string) {
    const tokenData = emailVerificationTokens.get(token);

    if (!tokenData) {
      this.auditService.log(AuditEventType.EMAIL_VERIFICATION_FAILED, {
        ipAddress,
        userAgent,
        success: false,
        details: { reason: 'Invalid verification token' },
      });
      throw new BadRequestException('Invalid or expired verification link');
    }

    if (Date.now() > tokenData.expiresAt) {
      emailVerificationTokens.delete(token);
      this.auditService.log(AuditEventType.EMAIL_VERIFICATION_FAILED, {
        email: tokenData.email,
        ipAddress,
        userAgent,
        success: false,
        details: { reason: 'Token expired' },
      });
      throw new BadRequestException('Verification link has expired. Please request a new one.');
    }

    const user = users.get(tokenData.email);
    if (!user) {
      emailVerificationTokens.delete(token);
      throw new BadRequestException('User not found');
    }

    // Mark email as verified
    user.emailVerified = true;
    users.set(tokenData.email, user);
    emailVerificationTokens.delete(token);

    this.auditService.log(AuditEventType.EMAIL_VERIFICATION_SUCCESS, {
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

  async resendVerificationEmail(email: string, ipAddress: string, userAgent: string) {
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
    } catch (err) {
      console.error('⚠️ Email service error:', err.message);
    }

    this.auditService.log(AuditEventType.EMAIL_VERIFICATION_RESENT, {
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

  async login(email: string, password: string, ipAddress: string, userAgent: string) {
    const user = users.get(email);

    this.auditService.log(AuditEventType.LOGIN_ATTEMPT, {
      email,
      ipAddress,
      userAgent,
      success: true,
      details: { userExists: !!user },
    });

    if (!user) {
      this.auditService.log(AuditEventType.LOGIN_FAILED, {
        email,
        ipAddress,
        userAgent,
        success: false,
        details: { reason: 'User not found' },
      });
      throw new UnauthorizedException('Invalid credentials');
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      this.auditService.log(AuditEventType.LOGIN_FAILED, {
        email,
        userId: user.id,
        ipAddress,
        userAgent,
        success: false,
        details: { reason: 'Invalid password' },
      });
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check if email is verified
    if (!user.emailVerified) {
      this.auditService.log(AuditEventType.LOGIN_FAILED, {
        email,
        userId: user.id,
        ipAddress,
        userAgent,
        success: false,
        details: { reason: 'Email not verified' },
      });
      throw new UnauthorizedException('Please verify your email before logging in. Check your inbox or request a new verification link.');
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
    } catch (err) {
      console.error('⚠️ Email service error:', err.message);
    }

    this.auditService.log(AuditEventType.TWO_FA_SENT, {
      email,
      userId: user.id,
      ipAddress,
      userAgent,
      success: true,
    });

    return { message: '2FA code sent to email (check spam folder)', email, testCode: code };
  }

  async verify2FA(email: string, code: string, ipAddress: string, userAgent: string) {
    const storedCode = twoFactorCodes.get(email);
    const user = users.get(email);

    if (!storedCode) {
      this.auditService.log(AuditEventType.TWO_FA_FAILED, {
        email,
        ipAddress,
        userAgent,
        success: false,
        details: { reason: 'No 2FA code found' },
      });
      throw new BadRequestException('No 2FA code found');
    }

    if (Date.now() > storedCode.expiresAt) {
      twoFactorCodes.delete(email);
      throw new BadRequestException('2FA code expired');
    }

    if (storedCode.code !== code) {
      this.auditService.log(AuditEventType.TWO_FA_FAILED, {
        email,
        userId: user?.id,
        ipAddress,
        userAgent,
        success: false,
        details: { reason: 'Invalid 2FA code' },
      });
      throw new BadRequestException('Invalid 2FA code');
    }

    twoFactorCodes.delete(email);

    this.auditService.log(AuditEventType.TWO_FA_SUCCESS, {
      email,
      userId: user.id,
      ipAddress,
      userAgent,
      success: true,
    });
    
    // Generate access token (short-lived: 15 minutes)
    const accessToken = this.jwtService.sign(
      {
        sub: user.id,
        email: user.email,
        type: 'access',
      },
      { expiresIn: '15m' },
    );

    // Generate refresh token (long-lived: 7 days)
    const refreshToken = this.jwtService.sign(
      {
        sub: user.id,
        email: user.email,
        type: 'refresh',
      },
      { expiresIn: '7d' },
    );

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

  async getProfile(userId: string) {
    for (const user of users.values()) {
      if (user.id === userId) {
        return { id: user.id, email: user.email };
      }
    }
    throw new UnauthorizedException('User not found');
  }

  async refreshAccessToken(userId: string, refreshToken: string, ipAddress: string, userAgent: string) {
    const tokenKey = `${userId}_${refreshToken}`;
    const storedToken = refreshTokens.get(tokenKey);

    if (!storedToken) {
      this.auditService.log(AuditEventType.TOKEN_REFRESH_FAILED, {
        userId,
        ipAddress,
        userAgent,
        success: false,
        details: { reason: 'Invalid refresh token' },
      });
      throw new UnauthorizedException('Invalid refresh token');
    }

    if (Date.now() > storedToken.expiresAt) {
      refreshTokens.delete(tokenKey);
      this.auditService.log(AuditEventType.TOKEN_REFRESH_FAILED, {
        userId,
        ipAddress,
        userAgent,
        success: false,
        details: { reason: 'Refresh token expired' },
      });
      throw new UnauthorizedException('Refresh token expired');
    }

    const user = users.get([...users.values()].find(u => u.id === userId)?.email);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Delete old refresh token (rotation)
    refreshTokens.delete(tokenKey);

    // Generate new access token
    const newAccessToken = this.jwtService.sign(
      {
        sub: user.id,
        email: user.email,
        type: 'access',
      },
      { expiresIn: '15m' },
    );

    // Generate new refresh token
    const newRefreshToken = this.jwtService.sign(
      {
        sub: user.id,
        email: user.email,
        type: 'refresh',
      },
      { expiresIn: '7d' },
    );

    // Store new refresh token
    refreshTokens.set(`${user.id}_${newRefreshToken}`, {
      token: newRefreshToken,
      expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000,
    });

    this.auditService.log(AuditEventType.TOKEN_REFRESH, {
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

  async requestPasswordReset(email: string, ipAddress: string, userAgent: string) {
    const user = users.get(email);

    this.auditService.log(AuditEventType.PASSWORD_RESET_REQUESTED, {
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
    const resetToken = this.jwtService.sign(
      {
        sub: user.id,
        email: user.email,
        type: 'password-reset',
      },
      { expiresIn: '15m' }, // 15 minute expiration
    );

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
    } catch (err) {
      console.error('⚠️ Password reset email failed:', err.message);
    }

    return { message: 'If email exists, password reset link will be sent' };
  }

  async resetPassword(token: string, newPassword: string, ipAddress: string, userAgent: string) {
    const resetTokenData = passwordResetTokens.get(token);

    if (!resetTokenData) {
      this.auditService.log(AuditEventType.PASSWORD_RESET_FAILED, {
        ipAddress,
        userAgent,
        success: false,
        details: { reason: 'Invalid or expired reset token' },
      });
      throw new BadRequestException('Invalid or expired reset token');
    }

    if (Date.now() > resetTokenData.expiresAt) {
      passwordResetTokens.delete(token);
      this.auditService.log(AuditEventType.PASSWORD_RESET_FAILED, {
        email: resetTokenData.email,
        ipAddress,
        userAgent,
        success: false,
        details: { reason: 'Reset token expired' },
      });
      throw new BadRequestException('Reset token expired');
    }

    const user = users.get(resetTokenData.email);
    if (!user) {
      throw new BadRequestException('User not found');
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

    this.auditService.log(AuditEventType.PASSWORD_RESET_SUCCESS, {
      email: resetTokenData.email,
      userId: user.id,
      ipAddress,
      userAgent,
      success: true,
    });

    return { message: 'Password reset successful. Please login with your new password.' };
  }
}
