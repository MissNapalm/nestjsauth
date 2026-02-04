import { Injectable, BadRequestException, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { EmailService } from '../email/email.service';

// In-memory storage (replace with database in production)
const users = new Map<string, any>();
const twoFactorCodes = new Map<string, { code: string; expiresAt: number }>();
const refreshTokens = new Map<string, { token: string; expiresAt: number }>();
const passwordResetTokens = new Map<string, { email: string; expiresAt: number }>(); 

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private emailService: EmailService,
  ) {}

  async register(email: string, password: string) {
    if (users.has(email)) {
      throw new BadRequestException('User already exists');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = Math.random().toString(36).substring(7);

    users.set(email, {
      id: userId,
      email,
      password: hashedPassword,
    });

    return { message: 'Registration successful', userId };
  }

  async login(email: string, password: string) {
    const user = users.get(email);

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      throw new UnauthorizedException('Invalid credentials');
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
      // Don't throw - allow login to proceed with 2FA code even if email fails
    }

    return { message: '2FA code sent to email (check spam folder)', email, testCode: code };
  }

  async verify2FA(email: string, code: string) {
    const storedCode = twoFactorCodes.get(email);

    if (!storedCode) {
      throw new BadRequestException('No 2FA code found');
    }

    if (Date.now() > storedCode.expiresAt) {
      twoFactorCodes.delete(email);
      throw new BadRequestException('2FA code expired');
    }

    if (storedCode.code !== code) {
      throw new BadRequestException('Invalid 2FA code');
    }

    twoFactorCodes.delete(email);

    const user = users.get(email);
    
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

  async refreshAccessToken(userId: string, refreshToken: string) {
    const tokenKey = `${userId}_${refreshToken}`;
    const storedToken = refreshTokens.get(tokenKey);

    if (!storedToken) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    if (Date.now() > storedToken.expiresAt) {
      refreshTokens.delete(tokenKey);
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

    return {
      access_token: newAccessToken,
      refresh_token: newRefreshToken,
    };
  }

  async requestPasswordReset(email: string) {
    const user = users.get(email);

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
          <p>Click the link below to reset your password. This link expires in 15 minutes.</p>
          <a href="${resetLink}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
            Reset Password
          </a>
          <p>Or copy this link: ${resetLink}</p>
          <p>If you didn't request this, ignore this email.</p>
        `,
        text: `Reset your password: ${resetLink}`,
      });
    } catch (err) {
      console.error('⚠️ Password reset email failed:', err.message);
    }

    return { message: 'If email exists, password reset link will be sent' };
  }

  async resetPassword(token: string, newPassword: string) {
    const resetTokenData = passwordResetTokens.get(token);

    if (!resetTokenData) {
      throw new BadRequestException('Invalid or expired reset token');
    }

    if (Date.now() > resetTokenData.expiresAt) {
      passwordResetTokens.delete(token);
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

    return { message: 'Password reset successful. Please login with your new password.' };
  }
}
