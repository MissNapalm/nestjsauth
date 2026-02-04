import { Controller, Post, Get, Body, UseGuards, Request, ValidationPipe } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { RegisterDto, LoginDto, Verify2FADto } from './auth.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  async register(@Body(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true })) body: RegisterDto) {
    return this.authService.register(body.email, body.password);
  }

  @Post('login')
  async login(@Body(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true })) body: LoginDto) {
    return this.authService.login(body.email, body.password);
  }

  @Post('verify-2fa')
  async verify2FA(@Body(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true })) body: Verify2FADto) {
    return this.authService.verify2FA(body.email, body.code);
  }

  @UseGuards(AuthGuard('jwt'))
  @Get('profile')
  async getProfile(@Request() req) {
    return this.authService.getProfile(req.user.userId);
  }
}
