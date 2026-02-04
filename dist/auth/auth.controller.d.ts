import { AuthService } from './auth.service';
import { RegisterDto, LoginDto, Verify2FADto, RefreshTokenDto, RequestPasswordResetDto, ResetPasswordDto, VerifyEmailDto, ResendVerificationDto } from './auth.dto';
export declare class AuthController {
    private authService;
    constructor(authService: AuthService);
    private getClientInfo;
    register(body: RegisterDto, req: any): Promise<{
        message: string;
        userId: string;
        requiresVerification: boolean;
        testToken: string;
    }>;
    verifyEmail(body: VerifyEmailDto, req: any): Promise<{
        message: string;
        email: string;
    }>;
    resendVerification(body: ResendVerificationDto, req: any): Promise<{
        message: string;
        testToken?: undefined;
    } | {
        message: string;
        testToken: string;
    }>;
    login(body: LoginDto, req: any): Promise<{
        message: string;
        email: string;
        testCode: string;
    }>;
    verify2FA(body: Verify2FADto, req: any): Promise<{
        access_token: string;
        refresh_token: string;
        user: {
            id: any;
            email: any;
        };
    }>;
    refreshToken(body: RefreshTokenDto, req: any): Promise<{
        access_token: string;
        refresh_token: string;
    }>;
    requestPasswordReset(body: RequestPasswordResetDto, req: any): Promise<{
        message: string;
    }>;
    resetPassword(body: ResetPasswordDto, req: any): Promise<{
        message: string;
    }>;
    getProfile(req: any): Promise<{
        id: any;
        email: any;
    }>;
}
//# sourceMappingURL=auth.controller.d.ts.map