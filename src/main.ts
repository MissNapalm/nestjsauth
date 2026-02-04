import * as dotenv from 'dotenv';

// Load environment variables from .env FIRST
dotenv.config();

import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import * as express from 'express';
import * as path from 'path';
import { PrismaClient } from '@prisma/client';

// Database reset function
async function resetDatabase() {
  const prisma = new PrismaClient();
  try {
    console.log('🗑️  Resetting database...');
    // Delete in order to respect foreign key constraints
    await prisma.auditLog.deleteMany();
    await prisma.refreshToken.deleteMany();
    await prisma.verificationToken.deleteMany();
    await prisma.twoFactorCode.deleteMany();
    await prisma.user.deleteMany();
    console.log('✅ Database reset complete');
  } catch (error) {
    console.error('❌ Database reset failed:', error.message);
  } finally {
    await prisma.$disconnect();
  }
}

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Security Headers Middleware (OWASP recommended)
  app.use((req, res, next) => {
    // Prevent clickjacking
    res.setHeader('X-Frame-Options', 'DENY');
    // Prevent MIME type sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');
    // Enable XSS filter in browsers
    res.setHeader('X-XSS-Protection', '1; mode=block');
    // Control referrer information
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    // Permissions policy (disable unnecessary features)
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    // Content Security Policy
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';");
    // Strict Transport Security (tells browsers to use HTTPS)
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
  });

  // Add global validation pipe
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: { enableImplicitConversion: true },
    }),
  );

  // CORS configuration - restrict to allowed origins
  app.enableCors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  });
  app.use(express.json({ limit: '1mb' }));

  // Serve static files
  const publicPath = path.join(__dirname, '..', 'public');
  app.use(express.static(publicPath));

  // Handle graceful shutdown and reset database
  const gracefulShutdown = async (signal: string) => {
    console.log(`\n📡 Received ${signal}. Shutting down gracefully...`);
    await app.close();
    await resetDatabase();
    process.exit(0);
  };

  // Listen for termination signals
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));   // Ctrl+C
  process.on('SIGTERM', () => gracefulShutdown('SIGTERM')); // kill command
  process.on('SIGHUP', () => gracefulShutdown('SIGHUP'));   // terminal closed

  await app.listen(3000);
  console.log(`🚀 Server running on http://localhost:3000`);
  console.log(`⚠️  Database will be reset when server stops`);
}
bootstrap();
