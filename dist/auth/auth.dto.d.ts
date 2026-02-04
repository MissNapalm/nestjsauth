export declare class RegisterDto {
    email: string;
    password: string;
}
export declare class LoginDto {
    email: string;
    password: string;
}
export declare class Verify2FADto {
    email: string;
    code: string;
}
export declare class RefreshTokenDto {
    refresh_token: string;
}
export declare class RequestPasswordResetDto {
    email: string;
}
export declare class ResetPasswordDto {
    token: string;
    password: string;
}
export declare class VerifyEmailDto {
    token: string;
}
export declare class ResendVerificationDto {
    email: string;
}
//# sourceMappingURL=auth.dto.d.ts.map