import { AuthService } from './auth.service';
import { RegisterDto, LoginDto, Verify2FADto, RefreshTokenDto } from './auth.dto';
export declare class AuthController {
    private authService;
    constructor(authService: AuthService);
    register(body: RegisterDto): Promise<{
        message: string;
        userId: string;
    }>;
    login(body: LoginDto): Promise<{
        message: string;
        email: string;
        testCode: string;
    }>;
    verify2FA(body: Verify2FADto): Promise<{
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
    getProfile(req: any): Promise<{
        id: any;
        email: any;
    }>;
}
//# sourceMappingURL=auth.controller.d.ts.map