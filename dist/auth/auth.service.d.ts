import { JwtService } from '@nestjs/jwt';
import { EmailService } from '../email/email.service';
export declare class AuthService {
    private jwtService;
    private emailService;
    constructor(jwtService: JwtService, emailService: EmailService);
    register(email: string, password: string): Promise<{
        message: string;
        userId: string;
    }>;
    login(email: string, password: string): Promise<{
        message: string;
        email: string;
        testCode: string;
    }>;
    verify2FA(email: string, code: string): Promise<{
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
    refreshAccessToken(userId: string, refreshToken: string): Promise<{
        access_token: string;
        refresh_token: string;
    }>;
    requestPasswordReset(email: string): Promise<{
        message: string;
    }>;
    resetPassword(token: string, newPassword: string): Promise<{
        message: string;
    }>;
}
//# sourceMappingURL=auth.service.d.ts.map