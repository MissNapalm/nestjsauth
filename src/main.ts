import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as express from 'express';
import * as path from 'path';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Enable CORS
  app.enableCors();

  // Serve static files (frontend)
  app.use(express.static(path.join(__dirname, '..', 'public')));

  // Enable JSON body parser with larger limit
  app.use(express.json({ limit: '1mb' }));

  await app.listen(3000);
  console.log(`🚀 Server running on http://localhost:3000`);
}
bootstrap();
