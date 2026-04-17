import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuditService, AuditEventType } from './audit.service';
import { RolesGuard } from '../guards/roles.guard';
import { Roles } from '../decorators/roles.decorator';

@Controller('audit')
export class AuditController {
  constructor(private auditService: AuditService) {}

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles('ADMIN')
  @Get('logs')
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

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles('ADMIN')
  @Get('summary')
  getSummary() {
    return this.auditService.getSecuritySummary();
  }
}
