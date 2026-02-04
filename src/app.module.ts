import { Module, NestModule, MiddlewareConsumer } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import { AppController } from './app.controller';
import { AuthController } from './auth/auth.controller';
import { AuthService } from './auth/auth.service';
import { JwtStrategy } from './auth/jwt.strategy';
import { EmailService } from './email/email.service';
import { AuditService } from './audit/audit.service';
import { AuditController } from './audit/audit.controller';
import { PrismaModule } from './prisma/prisma.module';
import { CustomThrottlerGuard } from './guards/custom-throttler.guard';
import { RequestIdMiddleware } from './middleware/request-id.middleware';

@Module({
  imports: [
    PrismaModule,
    PassportModule,
    JwtModule.register({
      secret: process.env.JWT_SECRET,
      signOptions: { expiresIn: '1h' },
    }),
    // Rate limiting configuration
    // Multiple throttlers for different time windows
    ThrottlerModule.forRoot([
      {
        name: 'short',
        ttl: 1000,    // 1 second
        limit: 3,     // 3 requests per second (burst protection)
      },
      {
        name: 'medium',
        ttl: 60000,   // 1 minute
        limit: 20,    // 20 requests per minute
      },
      {
        name: 'long',
        ttl: 900000,  // 15 minutes
        limit: 100,   // 100 requests per 15 minutes
      },
    ]),
  ],
  controllers: [AppController, AuthController, AuditController],
  providers: [
    AuthService, 
    JwtStrategy, 
    EmailService, 
    AuditService,
    // Apply custom throttler guard globally
    {
      provide: APP_GUARD,
      useClass: CustomThrottlerGuard,
    },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    // Apply request ID middleware to all routes
    consumer.apply(RequestIdMiddleware).forRoutes('*');
  }
}
