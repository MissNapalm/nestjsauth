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
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
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
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthService = void 0;
const common_1 = require("@nestjs/common");
const jwt_1 = require("@nestjs/jwt");
const bcrypt = __importStar(require("bcryptjs"));
const email_service_1 = require("../email/email.service");
// In-memory storage (replace with database in production)
const users = new Map();
const twoFactorCodes = new Map();
const refreshTokens = new Map();
let AuthService = class AuthService {
    constructor(jwtService, emailService) {
        this.jwtService = jwtService;
        this.emailService = emailService;
    }
    async register(email, password) {
        if (users.has(email)) {
            throw new common_1.BadRequestException('User already exists');
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const userId = Math.random().toString(36).substring(7);
        users.set(email, {
            id: userId,
            email,
            password: hashedPassword,
        });
        return { message: 'Registration successful', userId };
    }
    async login(email, password) {
        const user = users.get(email);
        if (!user) {
            throw new common_1.UnauthorizedException('Invalid credentials');
        }
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            throw new common_1.UnauthorizedException('Invalid credentials');
        }
        // Generate 2FA code
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        twoFactorCodes.set(email, {
            code,
            expiresAt: Date.now() + 5 * 60 * 1000, // 5 minutes
        });
        // Send 2FA code via email
        try {
            const emailResult = await this.emailService.sendEmail({
                to: [email],
                subject: '2FA Verification Code',
                html: `<h2>Your 2FA Code</h2><p>Code: <strong>${code}</strong></p><p>Valid for 5 minutes.</p>`,
                text: `Your 2FA code is: ${code}`,
            });
            if (!emailResult.success) {
                console.warn('⚠️ Email failed to send, but 2FA code generated:', code);
            }
        }
        catch (err) {
            console.error('⚠️ Email service error:', err.message);
            // Don't throw - allow login to proceed with 2FA code even if email fails
        }
        return { message: '2FA code sent to email (check spam folder)', email, testCode: code };
    }
    async verify2FA(email, code) {
        const storedCode = twoFactorCodes.get(email);
        if (!storedCode) {
            throw new common_1.BadRequestException('No 2FA code found');
        }
        if (Date.now() > storedCode.expiresAt) {
            twoFactorCodes.delete(email);
            throw new common_1.BadRequestException('2FA code expired');
        }
        if (storedCode.code !== code) {
            throw new common_1.BadRequestException('Invalid 2FA code');
        }
        twoFactorCodes.delete(email);
        const user = users.get(email);
        // Generate access token (short-lived: 15 minutes)
        const accessToken = this.jwtService.sign({
            sub: user.id,
            email: user.email,
            type: 'access',
        }, { expiresIn: '15m' });
        // Generate refresh token (long-lived: 7 days)
        const refreshToken = this.jwtService.sign({
            sub: user.id,
            email: user.email,
            type: 'refresh',
        }, { expiresIn: '7d' });
        // Store refresh token
        refreshTokens.set(`${user.id}_${refreshToken}`, {
            token: refreshToken,
            expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000, // 7 days
        });
        return {
            access_token: accessToken,
            refresh_token: refreshToken,
            user: { id: user.id, email: user.email },
        };
    }
    async getProfile(userId) {
        for (const user of users.values()) {
            if (user.id === userId) {
                return { id: user.id, email: user.email };
            }
        }
        throw new common_1.UnauthorizedException('User not found');
    }
    async refreshAccessToken(userId, refreshToken) {
        const tokenKey = `${userId}_${refreshToken}`;
        const storedToken = refreshTokens.get(tokenKey);
        if (!storedToken) {
            throw new common_1.UnauthorizedException('Invalid refresh token');
        }
        if (Date.now() > storedToken.expiresAt) {
            refreshTokens.delete(tokenKey);
            throw new common_1.UnauthorizedException('Refresh token expired');
        }
        const user = users.get([...users.values()].find(u => u.id === userId)?.email);
        if (!user) {
            throw new common_1.UnauthorizedException('User not found');
        }
        // Delete old refresh token (rotation)
        refreshTokens.delete(tokenKey);
        // Generate new access token
        const newAccessToken = this.jwtService.sign({
            sub: user.id,
            email: user.email,
            type: 'access',
        }, { expiresIn: '15m' });
        // Generate new refresh token
        const newRefreshToken = this.jwtService.sign({
            sub: user.id,
            email: user.email,
            type: 'refresh',
        }, { expiresIn: '7d' });
        // Store new refresh token
        refreshTokens.set(`${user.id}_${newRefreshToken}`, {
            token: newRefreshToken,
            expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000,
        });
        return {
            access_token: newAccessToken,
            refresh_token: newRefreshToken,
        };
    }
};
exports.AuthService = AuthService;
exports.AuthService = AuthService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [jwt_1.JwtService,
        email_service_1.EmailService])
], AuthService);
//# sourceMappingURL=auth.service.js.map