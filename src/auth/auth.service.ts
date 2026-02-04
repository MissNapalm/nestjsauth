import { Injectable, BadRequestException, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { EmailService } from '../email/email.service';

// In-memory storage (replace with database in production)
const users = new Map<string, any>();
const twoFactorCodes = new Map<string, { code: string; expiresAt: number }>();

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
    await this.emailService.sendEmail({
      to: [email],
      subject: '2FA Verification Code',
      html: `<h2>Your 2FA Code</h2><p>Code: <strong>${code}</strong></p><p>Valid for 5 minutes.</p>`,
      text: `Your 2FA code is: ${code}`,
    });

    return { message: '2FA code sent to email', email };
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
    const token = this.jwtService.sign({
      sub: user.id,
      email: user.email,
    });

    return { access_token: token, user: { id: user.id, email: user.email } };
  }

  async getProfile(userId: string) {
    for (const user of users.values()) {
      if (user.id === userId) {
        return { id: user.id, email: user.email };
      }
    }
    throw new UnauthorizedException('User not found');
  }
}
