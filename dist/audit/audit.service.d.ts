export declare enum AuditEventType {
    REGISTER_SUCCESS = "REGISTER_SUCCESS",
    REGISTER_FAILED = "REGISTER_FAILED",
    LOGIN_ATTEMPT = "LOGIN_ATTEMPT",
    LOGIN_SUCCESS = "LOGIN_SUCCESS",
    LOGIN_FAILED = "LOGIN_FAILED",
    LOGOUT = "LOGOUT",
    EMAIL_VERIFICATION_SENT = "EMAIL_VERIFICATION_SENT",
    EMAIL_VERIFICATION_SUCCESS = "EMAIL_VERIFICATION_SUCCESS",
    EMAIL_VERIFICATION_FAILED = "EMAIL_VERIFICATION_FAILED",
    EMAIL_VERIFICATION_RESENT = "EMAIL_VERIFICATION_RESENT",
    TWO_FA_SENT = "2FA_SENT",
    TWO_FA_SUCCESS = "2FA_SUCCESS",
    TWO_FA_FAILED = "2FA_FAILED",
    TOKEN_REFRESH = "TOKEN_REFRESH",
    TOKEN_REFRESH_FAILED = "TOKEN_REFRESH_FAILED",
    TOKEN_REVOKED = "TOKEN_REVOKED",
    PASSWORD_RESET_REQUESTED = "PASSWORD_RESET_REQUESTED",
    PASSWORD_RESET_SUCCESS = "PASSWORD_RESET_SUCCESS",
    PASSWORD_RESET_FAILED = "PASSWORD_RESET_FAILED",
    PASSWORD_CHANGED = "PASSWORD_CHANGED",
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED",
    SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY",
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED",
    ACCOUNT_UNLOCKED = "ACCOUNT_UNLOCKED"
}
export interface AuditLog {
    id: string;
    timestamp: Date;
    eventType: AuditEventType;
    userId?: string;
    email?: string;
    ipAddress: string;
    userAgent: string;
    success: boolean;
    details?: Record<string, any>;
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
}
export declare class AuditService {
    private auditLogs;
    log(eventType: AuditEventType, data: {
        userId?: string;
        email?: string;
        ipAddress: string;
        userAgent: string;
        success: boolean;
        details?: Record<string, any>;
    }): AuditLog;
    private calculateRiskLevel;
    private alertSecurityTeam;
    private generateId;
    getLogs(filters?: {
        eventType?: AuditEventType;
        email?: string;
        userId?: string;
        startDate?: Date;
        endDate?: Date;
        riskLevel?: string;
        limit?: number;
    }): AuditLog[];
    getRecentFailedLogins(email: string, minutes?: number): number;
    getSecuritySummary(): {
        totalEvents: number;
        last24Hours: number;
        failedLogins: number;
        highRiskEvents: number;
        topEventTypes: {
            type: string;
            count: number;
        }[];
    };
}
//# sourceMappingURL=audit.service.d.ts.map