import { Controller, Post, Get, Body, UseGuards, Request, ValidationPipe } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Throttle } from '@nestjs/throttler';
import { AuthService } from './auth.service';
import { RegisterDto, LoginDto, Verify2FADto, RefreshTokenDto, RequestPasswordResetDto, ResetPasswordDto } from './auth.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Throttle({ default: { limit: 5, ttl: 60000 } }) // 5 requests per minute
  @Post('register')
  async register(@Body() body: RegisterDto) {
    return this.authService.register(body.email, body.password);
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } }) // 5 requests per minute
  @Post('login')
  async login(@Body() body: LoginDto) {
    return this.authService.login(body.email, body.password);
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } }) // 5 requests per minute
  @Post('verify-2fa')
  async verify2FA(@Body() body: Verify2FADto) {
    return this.authService.verify2FA(body.email, body.code);
  }

  @Throttle({ default: { limit: 10, ttl: 60000 } }) // 10 requests per minute (more lenient for refresh)
  @Post('refresh')
  async refreshToken(@Body() body: RefreshTokenDto, @Request() req) {
    // Get userId from the JWT payload in Authorization header
    // For now, we'll extract it from the refresh token itself
    try {
      const decoded = JSON.parse(Buffer.from(body.refresh_token.split('.')[1], 'base64').toString());
      return this.authService.refreshAccessToken(decoded.sub, body.refresh_token);
    } catch (err) {
      throw new Error('Invalid refresh token format');
    }
  }

  @Throttle({ default: { limit: 3, ttl: 60000 } }) // 3 requests per minute (strict rate limit)
  @Post('request-password-reset')
  async requestPasswordReset(@Body() body: RequestPasswordResetDto) {
    return this.authService.requestPasswordReset(body.email);
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } }) // 5 requests per minute
  @Post('reset-password')
  async resetPassword(@Body() body: ResetPasswordDto) {
    return this.authService.resetPassword(body.token, body.password);
  }

  @UseGuards(AuthGuard('jwt'))
  @Get('profile')
  async getProfile(@Request() req) {
    return this.authService.getProfile(req.user.userId);
  }
}
