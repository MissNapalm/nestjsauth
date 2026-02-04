import { JwtService } from '@nestjs/jwt';
import { EmailService } from '../email/email.service';
import { AuditService } from '../audit/audit.service';
export declare class AuthService {
    private jwtService;
    private emailService;
    private auditService;
    constructor(jwtService: JwtService, emailService: EmailService, auditService: AuditService);
    register(email: string, password: string, ipAddress: string, userAgent: string): Promise<{
        message: string;
        userId: string;
        requiresVerification: boolean;
        testToken: string;
    }>;
    private generateSecureToken;
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
    getProfile(userId: string): Promise<{
        id: any;
        email: any;
    }>;
    refreshAccessToken(userId: string, refreshToken: string, ipAddress: string, userAgent: string): Promise<{
        access_token: string;
        refresh_token: string;
    }>;
    requestPasswordReset(email: string, ipAddress: string, userAgent: string): Promise<{
        message: string;
    }>;
    resetPassword(token: string, newPassword: string, ipAddress: string, userAgent: string): Promise<{
        message: string;
    }>;
}
//# sourceMappingURL=auth.service.d.ts.map