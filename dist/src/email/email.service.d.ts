interface SendEmailDto {
    to: string[];
    subject: string;
    html: string;
    text?: string;
}
export declare class EmailService {
    private transporter;
    constructor();
    sendEmail(data: SendEmailDto): Promise<any>;
    sendWelcomeEmail(recipientEmail: string): Promise<any>;
}
export {};
//# sourceMappingURL=email.service.d.ts.map