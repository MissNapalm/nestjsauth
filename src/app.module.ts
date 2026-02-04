import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ThrottlerModule } from '@nestjs/throttler';
import { AppController } from './app.controller';
import { AuthController } from './auth/auth.controller';
import { AuthService } from './auth/auth.service';
import { JwtStrategy } from './auth/jwt.strategy';
import { EmailService } from './email/email.service';
import { AuditService } from './audit/audit.service';
import { AuditController } from './audit/audit.controller';
import { PrismaModule } from './prisma/prisma.module';

@Module({
  imports: [
    PrismaModule,
    PassportModule,
    JwtModule.register({
      secret: process.env.JWT_SECRET,
      signOptions: { expiresIn: '1h' },
    }),
    // Rate limiting: 10 requests per 15 minutes
    ThrottlerModule.forRoot([
      {
        ttl: 900000, // 15 minutes in milliseconds
        limit: 10, // 10 requests per ttl
      },
    ]),
  ],
  controllers: [AppController, AuthController, AuditController],
  providers: [AuthService, JwtStrategy, EmailService, AuditService],
})
export class AppModule {}
