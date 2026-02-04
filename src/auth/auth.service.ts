import { Injectable, BadRequestException, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { PrismaService } from '../prisma/prisma.service';
import { EmailService } from '../email/email.service';
import { AuditService, AuditEventType } from '../audit/audit.service';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private emailService: EmailService,
    private auditService: AuditService,
  ) {}

  private generateSecureToken(): string {
    return Array.from({ length: 32 }, () => 
      Math.random().toString(36).charAt(2)
    ).join('');
  }

  async register(email: string, password: string, ipAddress: string, userAgent: string) {
    // Check if user exists
    const existingUser = await this.prisma.user.findUnique({ where: { email } });
    
    if (existingUser) {
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

    // Create user in database
    const user = await this.prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        emailVerified: false,
      },
    });

    // Generate email verification token
    const verificationToken = this.generateSecureToken();
    await this.prisma.verificationToken.create({
      data: {
        token: verificationToken,
        email,
        type: 'EMAIL_VERIFICATION',
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
      },
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
      userId: user.id,
      email,
      ipAddress,
      userAgent,
      success: true,
    });

    this.auditService.log(AuditEventType.EMAIL_VERIFICATION_SENT, {
      userId: user.id,
      email,
      ipAddress,
      userAgent,
      success: true,
    });

    return { 
      message: 'Registration successful. Please check your email to verify your account.',
      userId: user.id,
      requiresVerification: true,
      testToken: verificationToken, // Remove in production
    };
  }

  async verifyEmail(token: string, ipAddress: string, userAgent: string) {
    const tokenData = await this.prisma.verificationToken.findUnique({
      where: { token },
    });

    if (!tokenData || tokenData.type !== 'EMAIL_VERIFICATION') {
      this.auditService.log(AuditEventType.EMAIL_VERIFICATION_FAILED, {
        ipAddress,
        userAgent,
        success: false,
        details: { reason: 'Invalid verification token' },
      });
      throw new BadRequestException('Invalid or expired verification link');
    }

    if (new Date() > tokenData.expiresAt) {
      await this.prisma.verificationToken.delete({ where: { token } });
      this.auditService.log(AuditEventType.EMAIL_VERIFICATION_FAILED, {
        email: tokenData.email,
        ipAddress,
        userAgent,
        success: false,
        details: { reason: 'Token expired' },
      });
      throw new BadRequestException('Verification link has expired. Please request a new one.');
    }

    // Update user as verified
    const user = await this.prisma.user.update({
      where: { email: tokenData.email },
      data: { emailVerified: true },
    });

    // Delete the token
    await this.prisma.verificationToken.delete({ where: { token } });

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
    const user = await this.prisma.user.findUnique({ where: { email } });

    // Always return success to prevent email enumeration
    if (!user) {
      return { message: 'If the email exists, a verification link will be sent.' };
    }

    if (user.emailVerified) {
      return { message: 'Email is already verified. You can log in.' };
    }

    // Delete any existing tokens for this email
    await this.prisma.verificationToken.deleteMany({
      where: { email, type: 'EMAIL_VERIFICATION' },
    });

    // Generate new verification token
    const verificationToken = this.generateSecureToken();
    await this.prisma.verificationToken.create({
      data: {
        token: verificationToken,
        email,
        type: 'EMAIL_VERIFICATION',
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
      },
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

  // Account lockout constants
  private readonly MAX_LOGIN_ATTEMPTS = 5;
  private readonly LOCKOUT_DURATION_MINUTES = 15;

  async login(email: string, password: string, ipAddress: string, userAgent: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });

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

    // Check if account is locked
    if (user.lockedUntil && new Date() < user.lockedUntil) {
      const remainingMinutes = Math.ceil((user.lockedUntil.getTime() - Date.now()) / 60000);
      this.auditService.log(AuditEventType.LOGIN_FAILED, {
        email,
        userId: user.id,
        ipAddress,
        userAgent,
        success: false,
        details: { reason: 'Account locked', remainingMinutes },
      });
      throw new UnauthorizedException(`Account is locked. Try again in ${remainingMinutes} minute(s).`);
    }

    // If lockout has expired, reset the counter
    if (user.lockedUntil && new Date() >= user.lockedUntil) {
      await this.prisma.user.update({
        where: { id: user.id },
        data: { failedLoginAttempts: 0, lockedUntil: null },
      });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      // Increment failed attempts
      const newFailedAttempts = user.failedLoginAttempts + 1;
      const shouldLock = newFailedAttempts >= this.MAX_LOGIN_ATTEMPTS;
      
      await this.prisma.user.update({
        where: { id: user.id },
        data: {
          failedLoginAttempts: newFailedAttempts,
          lockedUntil: shouldLock 
            ? new Date(Date.now() + this.LOCKOUT_DURATION_MINUTES * 60 * 1000)
            : null,
        },
      });

      if (shouldLock) {
        this.auditService.log(AuditEventType.ACCOUNT_LOCKED, {
          email,
          userId: user.id,
          ipAddress,
          userAgent,
          success: false,
          details: { reason: 'Too many failed attempts', attempts: newFailedAttempts },
        });
        throw new UnauthorizedException(`Account locked due to ${this.MAX_LOGIN_ATTEMPTS} failed attempts. Try again in ${this.LOCKOUT_DURATION_MINUTES} minutes.`);
      }

      this.auditService.log(AuditEventType.LOGIN_FAILED, {
        email,
        userId: user.id,
        ipAddress,
        userAgent,
        success: false,
        details: { 
          reason: 'Invalid password', 
          failedAttempts: newFailedAttempts,
          attemptsRemaining: this.MAX_LOGIN_ATTEMPTS - newFailedAttempts,
        },
      });
      
      const attemptsRemaining = this.MAX_LOGIN_ATTEMPTS - newFailedAttempts;
      throw new UnauthorizedException(`Invalid credentials. ${attemptsRemaining} attempt(s) remaining before account lockout.`);
    }

    // Successful password - reset failed attempts
    if (user.failedLoginAttempts > 0) {
      await this.prisma.user.update({
        where: { id: user.id },
        data: { failedLoginAttempts: 0, lockedUntil: null },
      });
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
    
    // Upsert 2FA code (replace if exists)
    await this.prisma.twoFactorCode.upsert({
      where: { email },
      update: {
        code,
        expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 minutes
      },
      create: {
        email,
        code,
        expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 minutes
      },
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
    const storedCode = await this.prisma.twoFactorCode.findUnique({ where: { email } });
    const user = await this.prisma.user.findUnique({ where: { email } });

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

    if (new Date() > storedCode.expiresAt) {
      await this.prisma.twoFactorCode.delete({ where: { email } });
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

    await this.prisma.twoFactorCode.delete({ where: { email } });

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

    // Store refresh token in database
    await this.prisma.refreshToken.create({
      data: {
        token: refreshToken,
        userId: user.id,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
      },
    });

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      user: { id: user.id, email: user.email },
    };
  }

  async getProfile(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, email: true, emailVerified: true, createdAt: true },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    return user;
  }

  async refreshAccessToken(userId: string, refreshToken: string, ipAddress: string, userAgent: string) {
    const storedToken = await this.prisma.refreshToken.findUnique({
      where: { token: refreshToken },
    });

    if (!storedToken || storedToken.userId !== userId) {
      this.auditService.log(AuditEventType.TOKEN_REFRESH_FAILED, {
        userId,
        ipAddress,
        userAgent,
        success: false,
        details: { reason: 'Invalid refresh token' },
      });
      throw new UnauthorizedException('Invalid refresh token');
    }

    if (new Date() > storedToken.expiresAt) {
      await this.prisma.refreshToken.delete({ where: { token: refreshToken } });
      throw new UnauthorizedException('Refresh token expired');
    }

    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Generate new access token
    const accessToken = this.jwtService.sign(
      {
        sub: user.id,
        email: user.email,
        type: 'access',
      },
      { expiresIn: '15m' },
    );

    this.auditService.log(AuditEventType.TOKEN_REFRESH, {
      userId,
      email: user.email,
      ipAddress,
      userAgent,
      success: true,
    });

    return { access_token: accessToken };
  }

  async requestPasswordReset(email: string, ipAddress: string, userAgent: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });

    // Always return success to prevent email enumeration
    this.auditService.log(AuditEventType.PASSWORD_RESET_REQUESTED, {
      email,
      userId: user?.id,
      ipAddress,
      userAgent,
      success: true,
    });

    if (!user) {
      return { message: 'If the email exists, a reset link will be sent.' };
    }

    // Delete any existing password reset tokens
    await this.prisma.verificationToken.deleteMany({
      where: { email, type: 'PASSWORD_RESET' },
    });

    // Generate reset token
    const resetToken = this.generateSecureToken();
    await this.prisma.verificationToken.create({
      data: {
        token: resetToken,
        email,
        type: 'PASSWORD_RESET',
        expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
      },
    });

    // Send reset email
    const resetLink = `http://localhost:3000?reset=${resetToken}`;
    try {
      await this.emailService.sendEmail({
        to: [email],
        subject: 'Password Reset Request',
        html: `
          <h2>Password Reset</h2>
          <p>Click the link below to reset your password:</p>
          <p><a href="${resetLink}" style="background: #667eea; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">Reset Password</a></p>
          <p>Or copy this link: ${resetLink}</p>
          <p>This link expires in 1 hour.</p>
          <p><strong>Test Token:</strong> ${resetToken}</p>
        `,
        text: `Reset your password: ${resetLink}\nTest Token: ${resetToken}`,
      });
    } catch (err) {
      console.error('⚠️ Email service error:', err.message);
    }

    return { 
      message: 'If the email exists, a reset link will be sent.',
      testToken: resetToken, // Remove in production
    };
  }

  async resetPassword(token: string, newPassword: string, ipAddress: string, userAgent: string) {
    const tokenData = await this.prisma.verificationToken.findUnique({
      where: { token },
    });

    if (!tokenData || tokenData.type !== 'PASSWORD_RESET') {
      this.auditService.log(AuditEventType.PASSWORD_RESET_FAILED, {
        ipAddress,
        userAgent,
        success: false,
        details: { reason: 'Invalid reset token' },
      });
      throw new BadRequestException('Invalid or expired reset token');
    }

    if (new Date() > tokenData.expiresAt) {
      await this.prisma.verificationToken.delete({ where: { token } });
      throw new BadRequestException('Reset token has expired. Please request a new one.');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update password
    const user = await this.prisma.user.update({
      where: { email: tokenData.email },
      data: { password: hashedPassword },
    });

    // Delete the token
    await this.prisma.verificationToken.delete({ where: { token } });

    // Revoke all refresh tokens for this user (force re-login)
    await this.prisma.refreshToken.deleteMany({
      where: { userId: user.id },
    });

    this.auditService.log(AuditEventType.PASSWORD_RESET_SUCCESS, {
      userId: user.id,
      email: tokenData.email,
      ipAddress,
      userAgent,
      success: true,
    });

    return { message: 'Password reset successful. Please login with your new password.' };
  }
}
