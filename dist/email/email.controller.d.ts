import { EmailService } from './email.service';
export declare class EmailController {
    private readonly emailService;
    constructor(emailService: EmailService);
    sendEmail(body: {
        to: string[];
        subject: string;
        html: string;
        text?: string;
    }): Promise<any>;
    sendWelcome(body: {
        email: string;
    }): Promise<any>;
}
//# sourceMappingURL=email.controller.d.ts.map