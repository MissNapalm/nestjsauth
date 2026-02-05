import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuditService, AuditEventType } from './audit.service';

@Controller('audit')
export class AuditController {
  constructor(private auditService: AuditService) {}

  @Get('logs')
  // WARNING: This endpoint is open for development only. Remove before production!
  getLogs(
    @Query('eventType') eventType?: AuditEventType,
    @Query('email') email?: string,
    @Query('riskLevel') riskLevel?: string,
    @Query('limit') limit?: string,
  ) {
    return this.auditService.getLogs({
      eventType,
      email,
      riskLevel,
      limit: limit ? parseInt(limit, 10) : 50,
    });
  }

  // Get security summary dashboard
  @UseGuards(AuthGuard('jwt'))
  @Get('summary')
  getSummary() {
    return this.auditService.getSecuritySummary();
  }
}
