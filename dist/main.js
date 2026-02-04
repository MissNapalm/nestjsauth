"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const dotenv = __importStar(require("dotenv"));
// Load environment variables from .env FIRST
dotenv.config();
const core_1 = require("@nestjs/core");
const app_module_1 = require("./app.module");
const common_1 = require("@nestjs/common");
const express = __importStar(require("express"));
const path = __importStar(require("path"));
const client_1 = require("@prisma/client");
// Database reset function
async function resetDatabase() {
    const prisma = new client_1.PrismaClient();
    try {
        console.log('🗑️  Resetting database...');
        // Delete in order to respect foreign key constraints
        await prisma.auditLog.deleteMany();
        await prisma.refreshToken.deleteMany();
        await prisma.verificationToken.deleteMany();
        await prisma.twoFactorCode.deleteMany();
        await prisma.user.deleteMany();
        console.log('✅ Database reset complete');
    }
    catch (error) {
        console.error('❌ Database reset failed:', error.message);
    }
    finally {
        await prisma.$disconnect();
    }
}
async function bootstrap() {
    const app = await core_1.NestFactory.create(app_module_1.AppModule);
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
    app.useGlobalPipes(new common_1.ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
        transformOptions: { enableImplicitConversion: true },
    }));
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
    const gracefulShutdown = async (signal) => {
        console.log(`\n📡 Received ${signal}. Shutting down gracefully...`);
        await app.close();
        await resetDatabase();
        process.exit(0);
    };
    // Listen for termination signals
    process.on('SIGINT', () => gracefulShutdown('SIGINT')); // Ctrl+C
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM')); // kill command
    process.on('SIGHUP', () => gracefulShutdown('SIGHUP')); // terminal closed
    await app.listen(3000);
    console.log(`🚀 Server running on http://localhost:3000`);
    console.log(`⚠️  Database will be reset when server stops`);
}
bootstrap();
//# sourceMappingURL=main.js.map