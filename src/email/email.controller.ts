import { Controller, Post, Body } from '@nestjs/common';
import { EmailService } from './email.service';

@Controller('email')
export class EmailController {
  constructor(private readonly emailService: EmailService) {}

  @Post('send')
  async sendEmail(
    @Body()
    body: {
      to: string[];
      subject: string;
      html: string;
      text?: string;
    },
  ) {
    return this.emailService.sendEmail(body);
  }

  @Post('welcome')
  async sendWelcome(@Body() body: { email: string }) {
    return this.emailService.sendWelcomeEmail(body.email);
  }
}
