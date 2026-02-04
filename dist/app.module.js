"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AppModule = void 0;
const common_1 = require("@nestjs/common");
const jwt_1 = require("@nestjs/jwt");
const passport_1 = require("@nestjs/passport");
const throttler_1 = require("@nestjs/throttler");
const app_controller_1 = require("./app.controller");
const auth_controller_1 = require("./auth/auth.controller");
const auth_service_1 = require("./auth/auth.service");
const jwt_strategy_1 = require("./auth/jwt.strategy");
const email_service_1 = require("./email/email.service");
const audit_service_1 = require("./audit/audit.service");
const audit_controller_1 = require("./audit/audit.controller");
const prisma_module_1 = require("./prisma/prisma.module");
let AppModule = class AppModule {
};
exports.AppModule = AppModule;
exports.AppModule = AppModule = __decorate([
    (0, common_1.Module)({
        imports: [
            prisma_module_1.PrismaModule,
            passport_1.PassportModule,
            jwt_1.JwtModule.register({
                secret: process.env.JWT_SECRET || 'super-secret-key',
                signOptions: { expiresIn: '1h' },
            }),
            // Rate limiting: 10 requests per 15 minutes
            throttler_1.ThrottlerModule.forRoot([
                {
                    ttl: 900000, // 15 minutes in milliseconds
                    limit: 10, // 10 requests per ttl
                },
            ]),
        ],
        controllers: [app_controller_1.AppController, auth_controller_1.AuthController, audit_controller_1.AuditController],
        providers: [auth_service_1.AuthService, jwt_strategy_1.JwtStrategy, email_service_1.EmailService, audit_service_1.AuditService],
    })
], AppModule);
//# sourceMappingURL=app.module.js.map