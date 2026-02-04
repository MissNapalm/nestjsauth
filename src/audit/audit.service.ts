import { Injectable } from '@nestjs/common';

export enum AuditEventType {
  // Authentication events
  REGISTER_SUCCESS = 'REGISTER_SUCCESS',
  REGISTER_FAILED = 'REGISTER_FAILED',
  LOGIN_ATTEMPT = 'LOGIN_ATTEMPT',
  LOGIN_SUCCESS = 'LOGIN_SUCCESS',
  LOGIN_FAILED = 'LOGIN_FAILED',
  LOGOUT = 'LOGOUT',
  
  // Email verification events
  EMAIL_VERIFICATION_SENT = 'EMAIL_VERIFICATION_SENT',
  EMAIL_VERIFICATION_SUCCESS = 'EMAIL_VERIFICATION_SUCCESS',
  EMAIL_VERIFICATION_FAILED = 'EMAIL_VERIFICATION_FAILED',
  EMAIL_VERIFICATION_RESENT = 'EMAIL_VERIFICATION_RESENT',
  
  // 2FA events
  TWO_FA_SENT = '2FA_SENT',
  TWO_FA_SUCCESS = '2FA_SUCCESS',
  TWO_FA_FAILED = '2FA_FAILED',
  
  // Token events
  TOKEN_REFRESH = 'TOKEN_REFRESH',
  TOKEN_REFRESH_FAILED = 'TOKEN_REFRESH_FAILED',
  TOKEN_REVOKED = 'TOKEN_REVOKED',
  
  // Password events
  PASSWORD_RESET_REQUESTED = 'PASSWORD_RESET_REQUESTED',
  PASSWORD_RESET_SUCCESS = 'PASSWORD_RESET_SUCCESS',
  PASSWORD_RESET_FAILED = 'PASSWORD_RESET_FAILED',
  PASSWORD_CHANGED = 'PASSWORD_CHANGED',
  
  // Security events
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  SUSPICIOUS_ACTIVITY = 'SUSPICIOUS_ACTIVITY',
  ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',
  ACCOUNT_UNLOCKED = 'ACCOUNT_UNLOCKED',
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

@Injectable()
export class AuditService {
  // In-memory storage (use database in production)
  private auditLogs: AuditLog[] = [];

  log(
    eventType: AuditEventType,
    data: {
      userId?: string;
      email?: string;
      ipAddress: string;
      userAgent: string;
      success: boolean;
      details?: Record<string, any>;
    },
  ): AuditLog {
    const riskLevel = this.calculateRiskLevel(eventType, data.success);
    
    const log: AuditLog = {
      id: this.generateId(),
      timestamp: new Date(),
      eventType,
      userId: data.userId,
      email: data.email,
      ipAddress: data.ipAddress,
      userAgent: data.userAgent,
      success: data.success,
      details: data.details,
      riskLevel,
    };

    this.auditLogs.push(log);
    
    // Console output for demo (use proper logging service in production)
    const emoji = data.success ? '✅' : '❌';
    const riskEmoji = riskLevel === 'critical' ? '🚨' : riskLevel === 'high' ? '⚠️' : '';
    console.log(
      `${emoji} ${riskEmoji} [AUDIT] ${eventType} | ${data.email || 'unknown'} | ${data.ipAddress} | ${data.success ? 'SUCCESS' : 'FAILED'}`,
    );

    // Alert on high-risk events
    if (riskLevel === 'critical' || riskLevel === 'high') {
      this.alertSecurityTeam(log);
    }

    return log;
  }

  private calculateRiskLevel(
    eventType: AuditEventType,
    success: boolean,
  ): 'low' | 'medium' | 'high' | 'critical' {
    // Failed security events are higher risk
    if (!success) {
      switch (eventType) {
        case AuditEventType.LOGIN_FAILED:
        case AuditEventType.TWO_FA_FAILED:
          return 'medium';
        case AuditEventType.PASSWORD_RESET_FAILED:
        case AuditEventType.TOKEN_REFRESH_FAILED:
          return 'high';
        case AuditEventType.RATE_LIMIT_EXCEEDED:
        case AuditEventType.SUSPICIOUS_ACTIVITY:
          return 'critical';
        default:
          return 'medium';
      }
    }

    // Successful sensitive operations
    switch (eventType) {
      case AuditEventType.PASSWORD_RESET_SUCCESS:
      case AuditEventType.PASSWORD_CHANGED:
      case AuditEventType.ACCOUNT_UNLOCKED:
        return 'medium';
      case AuditEventType.ACCOUNT_LOCKED:
        return 'high';
      default:
        return 'low';
    }
  }

  private alertSecurityTeam(log: AuditLog): void {
    // In production: send to Slack, PagerDuty, email, etc.
    console.log(`🚨 [SECURITY ALERT] ${log.eventType} - Risk: ${log.riskLevel.toUpperCase()}`);
    console.log(`   Email: ${log.email || 'N/A'}`);
    console.log(`   IP: ${log.ipAddress}`);
    console.log(`   Time: ${log.timestamp.toISOString()}`);
  }

  private generateId(): string {
    return `audit_${Date.now()}_${Math.random().toString(36).substring(7)}`;
  }

  // Query methods for viewing logs
  getLogs(filters?: {
    eventType?: AuditEventType;
    email?: string;
    userId?: string;
    startDate?: Date;
    endDate?: Date;
    riskLevel?: string;
    limit?: number;
  }): AuditLog[] {
    let logs = [...this.auditLogs];

    if (filters?.eventType) {
      logs = logs.filter((l) => l.eventType === filters.eventType);
    }
    if (filters?.email) {
      logs = logs.filter((l) => l.email === filters.email);
    }
    if (filters?.userId) {
      logs = logs.filter((l) => l.userId === filters.userId);
    }
    if (filters?.startDate) {
      logs = logs.filter((l) => l.timestamp >= filters.startDate!);
    }
    if (filters?.endDate) {
      logs = logs.filter((l) => l.timestamp <= filters.endDate!);
    }
    if (filters?.riskLevel) {
      logs = logs.filter((l) => l.riskLevel === filters.riskLevel);
    }

    // Sort by timestamp descending (newest first)
    logs.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    if (filters?.limit) {
      logs = logs.slice(0, filters.limit);
    }

    return logs;
  }

  // Get failed login attempts for an email (for account lockout logic)
  getRecentFailedLogins(email: string, minutes: number = 15): number {
    const cutoff = new Date(Date.now() - minutes * 60 * 1000);
    return this.auditLogs.filter(
      (l) =>
        l.email === email &&
        l.eventType === AuditEventType.LOGIN_FAILED &&
        l.timestamp >= cutoff,
    ).length;
  }

  // Get security summary
  getSecuritySummary(): {
    totalEvents: number;
    last24Hours: number;
    failedLogins: number;
    highRiskEvents: number;
    topEventTypes: { type: string; count: number }[];
  } {
    const now = new Date();
    const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);

    const last24Hours = this.auditLogs.filter((l) => l.timestamp >= yesterday);
    const failedLogins = this.auditLogs.filter(
      (l) => l.eventType === AuditEventType.LOGIN_FAILED,
    );
    const highRisk = this.auditLogs.filter(
      (l) => l.riskLevel === 'high' || l.riskLevel === 'critical',
    );

    // Count event types
    const typeCounts = new Map<string, number>();
    this.auditLogs.forEach((l) => {
      typeCounts.set(l.eventType, (typeCounts.get(l.eventType) || 0) + 1);
    });

    const topEventTypes = Array.from(typeCounts.entries())
      .map(([type, count]) => ({ type, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    return {
      totalEvents: this.auditLogs.length,
      last24Hours: last24Hours.length,
      failedLogins: failedLogins.length,
      highRiskEvents: highRisk.length,
      topEventTypes,
    };
  }
}
