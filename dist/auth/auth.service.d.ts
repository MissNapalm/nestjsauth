import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';
import { EmailService } from '../email/email.service';
import { AuditService } from '../audit/audit.service';
export declare class AuthService {
    private prisma;
    private jwtService;
    private emailService;
    private auditService;
    constructor(prisma: PrismaService, jwtService: JwtService, emailService: EmailService, auditService: AuditService);
    private generateSecureToken;
    private secureCompare;
    private addSecurityDelay;
    register(email: string, password: string, ipAddress: string, userAgent: string): Promise<{
        message: string;
        userId: string;
        requiresVerification: boolean;
        testToken: string;
    }>;
    verifyEmail(token: string, ipAddress: string, userAgent: string): Promise<{
        message: string;
        email: string;
    }>;
    resendVerificationEmail(email: string, ipAddress: string, userAgent: string): Promise<{
        message: string;
        testToken?: undefined;
    } | {
        message: string;
        testToken: string;
    }>;
    private readonly MAX_LOGIN_ATTEMPTS;
    private readonly LOCKOUT_DURATION_MINUTES;
    private readonly MAX_2FA_ATTEMPTS;
    login(email: string, password: string, ipAddress: string, userAgent: string): Promise<{
        message: string;
        email: string;
        testCode: string;
    }>;
    verify2FA(email: string, code: string, ipAddress: string, userAgent: string): Promise<{
        access_token: string;
        refresh_token: string;
        user: {
            id: string;
            email: string;
        };
    }>;
    getProfile(userId: string): Promise<{
        id: string;
        email: string;
        emailVerified: boolean;
        createdAt: Date;
    }>;
    refreshAccessToken(userId: string, refreshToken: string, ipAddress: string, userAgent: string): Promise<{
        access_token: string;
    }>;
    requestPasswordReset(email: string, ipAddress: string, userAgent: string): Promise<{
        message: string;
        testToken?: undefined;
    } | {
        message: string;
        testToken: string;
    }>;
    resetPassword(token: string, newPassword: string, ipAddress: string, userAgent: string): Promise<{
        message: string;
    }>;
}
//# sourceMappingURL=auth.service.d.ts.map