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
    register(email: string, password: string, ipAddress: string, userAgent: string): Promise<{
        message: string;
        userId: any;
        requiresVerification: boolean;
        testToken: string;
    }>;
    verifyEmail(token: string, ipAddress: string, userAgent: string): Promise<{
        message: string;
        email: any;
    }>;
    resendVerificationEmail(email: string, ipAddress: string, userAgent: string): Promise<{
        message: string;
        testToken?: undefined;
    } | {
        message: string;
        testToken: string;
    }>;
    login(email: string, password: string, ipAddress: string, userAgent: string): Promise<{
        message: string;
        email: string;
        testCode: string;
    }>;
    verify2FA(email: string, code: string, ipAddress: string, userAgent: string): Promise<{
        access_token: string;
        refresh_token: string;
        user: {
            id: any;
            email: any;
        };
    }>;
    getProfile(userId: string): Promise<any>;
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
//# sourceMappingURL=auth.service.new.d.ts.map