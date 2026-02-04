import { AuthService } from './auth.service';
export declare class AuthController {
    private authService;
    constructor(authService: AuthService);
    register(body: {
        email: string;
        password: string;
    }): Promise<{
        message: string;
        userId: string;
    }>;
    login(body: {
        email: string;
        password: string;
    }): Promise<{
        message: string;
        email: string;
        testCode: string;
    }>;
    verify2FA(body: {
        email: string;
        code: string;
    }): Promise<{
        access_token: string;
        user: {
            id: any;
            email: any;
        };
    }>;
    getProfile(req: any): Promise<{
        id: any;
        email: any;
    }>;
}
//# sourceMappingURL=auth.controller.d.ts.map