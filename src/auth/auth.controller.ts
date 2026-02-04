import { Controller, Post, Get, Body, UseGuards, Request, Req } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Throttle } from '@nestjs/throttler';
import { AuthService } from './auth.service';
import { RegisterDto, LoginDto, Verify2FADto, RefreshTokenDto, RequestPasswordResetDto, ResetPasswordDto, VerifyEmailDto, ResendVerificationDto } from './auth.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  // Helper to extract client info for audit logging
  private getClientInfo(req: any): { ipAddress: string; userAgent: string } {
    const ipAddress = req.headers['x-forwarded-for']?.split(',')[0] || 
                      req.connection?.remoteAddress || 
                      req.ip || 
                      'unknown';
    const userAgent = req.headers['user-agent'] || 'unknown';
    return { ipAddress, userAgent };
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } }) // 5 requests per minute
  @Post('register')
  async register(@Body() body: RegisterDto, @Req() req: any) {
    const { ipAddress, userAgent } = this.getClientInfo(req);
    return this.authService.register(body.email, body.password, ipAddress, userAgent);
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } }) // 5 requests per minute
  @Post('verify-email')
  async verifyEmail(@Body() body: VerifyEmailDto, @Req() req: any) {
    const { ipAddress, userAgent } = this.getClientInfo(req);
    return this.authService.verifyEmail(body.token, ipAddress, userAgent);
  }

  @Throttle({ default: { limit: 3, ttl: 60000 } }) // 3 requests per minute (strict)
  @Post('resend-verification')
  async resendVerification(@Body() body: ResendVerificationDto, @Req() req: any) {
    const { ipAddress, userAgent } = this.getClientInfo(req);
    return this.authService.resendVerificationEmail(body.email, ipAddress, userAgent);
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } }) // 5 requests per minute
  @Post('login')
  async login(@Body() body: LoginDto, @Req() req: any) {
    const { ipAddress, userAgent } = this.getClientInfo(req);
    return this.authService.login(body.email, body.password, ipAddress, userAgent);
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } }) // 5 requests per minute
  @Post('verify-2fa')
  async verify2FA(@Body() body: Verify2FADto, @Req() req: any) {
    const { ipAddress, userAgent } = this.getClientInfo(req);
    return this.authService.verify2FA(body.email, body.code, ipAddress, userAgent);
  }

  @Throttle({ default: { limit: 10, ttl: 60000 } }) // 10 requests per minute (more lenient for refresh)
  @Post('refresh')
  async refreshToken(@Body() body: RefreshTokenDto, @Req() req: any) {
    const { ipAddress, userAgent } = this.getClientInfo(req);
    // Get userId from the JWT payload in Authorization header
    // For now, we'll extract it from the refresh token itself
    try {
      const decoded = JSON.parse(Buffer.from(body.refresh_token.split('.')[1], 'base64').toString());
      return this.authService.refreshAccessToken(decoded.sub, body.refresh_token, ipAddress, userAgent);
    } catch (err) {
      throw new Error('Invalid refresh token format');
    }
  }

  @Throttle({ default: { limit: 3, ttl: 60000 } }) // 3 requests per minute (strict rate limit)
  @Post('request-password-reset')
  async requestPasswordReset(@Body() body: RequestPasswordResetDto, @Req() req: any) {
    const { ipAddress, userAgent } = this.getClientInfo(req);
    return this.authService.requestPasswordReset(body.email, ipAddress, userAgent);
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } }) // 5 requests per minute
  @Post('reset-password')
  async resetPassword(@Body() body: ResetPasswordDto, @Req() req: any) {
    const { ipAddress, userAgent } = this.getClientInfo(req);
    return this.authService.resetPassword(body.token, body.password, ipAddress, userAgent);
  }

  @UseGuards(AuthGuard('jwt'))
  @Get('profile')
  async getProfile(@Request() req) {
    return this.authService.getProfile(req.user.userId);
  }
}
