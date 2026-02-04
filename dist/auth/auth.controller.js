"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthController = void 0;
const common_1 = require("@nestjs/common");
const passport_1 = require("@nestjs/passport");
const throttler_1 = require("@nestjs/throttler");
const auth_service_1 = require("./auth.service");
const auth_dto_1 = require("./auth.dto");
let AuthController = class AuthController {
    constructor(authService) {
        this.authService = authService;
    }
    // Helper to extract client info for audit logging
    getClientInfo(req) {
        const ipAddress = req.headers['x-forwarded-for']?.split(',')[0] ||
            req.connection?.remoteAddress ||
            req.ip ||
            'unknown';
        const userAgent = req.headers['user-agent'] || 'unknown';
        return { ipAddress, userAgent };
    }
    async register(body, req) {
        const { ipAddress, userAgent } = this.getClientInfo(req);
        return this.authService.register(body.email, body.password, ipAddress, userAgent);
    }
    async verifyEmail(body, req) {
        const { ipAddress, userAgent } = this.getClientInfo(req);
        return this.authService.verifyEmail(body.token, ipAddress, userAgent);
    }
    async resendVerification(body, req) {
        const { ipAddress, userAgent } = this.getClientInfo(req);
        return this.authService.resendVerificationEmail(body.email, ipAddress, userAgent);
    }
    async login(body, req) {
        const { ipAddress, userAgent } = this.getClientInfo(req);
        return this.authService.login(body.email, body.password, ipAddress, userAgent);
    }
    async verify2FA(body, req) {
        const { ipAddress, userAgent } = this.getClientInfo(req);
        return this.authService.verify2FA(body.email, body.code, ipAddress, userAgent);
    }
    async refreshToken(body, req) {
        const { ipAddress, userAgent } = this.getClientInfo(req);
        // Get userId from the JWT payload in Authorization header
        // For now, we'll extract it from the refresh token itself
        try {
            const decoded = JSON.parse(Buffer.from(body.refresh_token.split('.')[1], 'base64').toString());
            return this.authService.refreshAccessToken(decoded.sub, body.refresh_token, ipAddress, userAgent);
        }
        catch (err) {
            throw new Error('Invalid refresh token format');
        }
    }
    async requestPasswordReset(body, req) {
        const { ipAddress, userAgent } = this.getClientInfo(req);
        return this.authService.requestPasswordReset(body.email, ipAddress, userAgent);
    }
    async resetPassword(body, req) {
        const { ipAddress, userAgent } = this.getClientInfo(req);
        return this.authService.resetPassword(body.token, body.password, ipAddress, userAgent);
    }
    async getProfile(req) {
        return this.authService.getProfile(req.user.userId);
    }
};
exports.AuthController = AuthController;
__decorate([
    (0, throttler_1.Throttle)({ default: { limit: 5, ttl: 60000 } }) // 5 requests per minute
    ,
    (0, common_1.Post)('register'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [auth_dto_1.RegisterDto, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "register", null);
__decorate([
    (0, throttler_1.Throttle)({ default: { limit: 5, ttl: 60000 } }) // 5 requests per minute
    ,
    (0, common_1.Post)('verify-email'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [auth_dto_1.VerifyEmailDto, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "verifyEmail", null);
__decorate([
    (0, throttler_1.Throttle)({ default: { limit: 3, ttl: 60000 } }) // 3 requests per minute (strict)
    ,
    (0, common_1.Post)('resend-verification'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [auth_dto_1.ResendVerificationDto, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "resendVerification", null);
__decorate([
    (0, throttler_1.Throttle)({ default: { limit: 5, ttl: 60000 } }) // 5 requests per minute
    ,
    (0, common_1.Post)('login'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [auth_dto_1.LoginDto, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "login", null);
__decorate([
    (0, throttler_1.Throttle)({ default: { limit: 5, ttl: 60000 } }) // 5 requests per minute
    ,
    (0, common_1.Post)('verify-2fa'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [auth_dto_1.Verify2FADto, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "verify2FA", null);
__decorate([
    (0, throttler_1.Throttle)({ default: { limit: 10, ttl: 60000 } }) // 10 requests per minute (more lenient for refresh)
    ,
    (0, common_1.Post)('refresh'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [auth_dto_1.RefreshTokenDto, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "refreshToken", null);
__decorate([
    (0, throttler_1.Throttle)({ default: { limit: 3, ttl: 60000 } }) // 3 requests per minute (strict rate limit)
    ,
    (0, common_1.Post)('request-password-reset'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [auth_dto_1.RequestPasswordResetDto, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "requestPasswordReset", null);
__decorate([
    (0, throttler_1.Throttle)({ default: { limit: 5, ttl: 60000 } }) // 5 requests per minute
    ,
    (0, common_1.Post)('reset-password'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [auth_dto_1.ResetPasswordDto, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "resetPassword", null);
__decorate([
    (0, common_1.UseGuards)((0, passport_1.AuthGuard)('jwt')),
    (0, common_1.Get)('profile'),
    __param(0, (0, common_1.Request)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "getProfile", null);
exports.AuthController = AuthController = __decorate([
    (0, common_1.Controller)('auth'),
    __metadata("design:paramtypes", [auth_service_1.AuthService])
], AuthController);
//# sourceMappingURL=auth.controller.js.map