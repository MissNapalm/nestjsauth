import { AuditService, AuditEventType } from './audit.service';
export declare class AuditController {
    private auditService;
    constructor(auditService: AuditService);
    getLogs(eventType?: AuditEventType, email?: string, riskLevel?: string, limit?: string): import("./audit.service").AuditLog[];
    getSummary(): {
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
//# sourceMappingURL=audit.controller.d.ts.map