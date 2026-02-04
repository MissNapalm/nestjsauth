# NestJS Email Sender with Mailtrap

Simple NestJS project with email sending via Mailtrap SMTP service (perfect for testing).

## Setup Instructions

### 1. Get a Mailtrap Account
- Go to https://mailtrap.io and sign up (free account available)
- Create a new Inbox (or use the default "Demo Inbox")

### 2. Get Your SMTP Credentials

1. In Mailtrap dashboard, click on your inbox
2. Go to **Integrations** tab → select **Nodemailer**
3. Copy these values:
   - **Host** (e.g., `sandbox.smtp.mailtrap.io`)
   - **Port** (usually `587` for TLS or `2525`)
   - **Username** (your Mailtrap user)
   - **Password** (your Mailtrap password)

### 3. Configure .env File

Edit `.env` in the project root:
```env
MAILTRAP_HOST=sandbox.smtp.mailtrap.io
MAILTRAP_PORT=587
MAILTRAP_USER=your_mailtrap_username
MAILTRAP_PASS=your_mailtrap_password
SENDER_EMAIL=noreply@example.com
```

### 4. Install and Run

```bash
npm install
npm run send-email
```

This will send emails to both `captainaptos1@gmail.com` and `cybersecsarah99@gmail.com` (they'll all appear in your Mailtrap inbox since it's a test sandbox).

### 5. View Emails

Visit https://mailtrap.io/inboxes to see all sent emails in your Mailtrap inbox.

## Why Mailtrap?

✅ No email verification needed - test with any email address  
✅ Free tier with sandbox  
✅ View all sent emails in one place  
✅ Perfect for development and testing  
✅ No risk of actually sending emails to real addresses  

## Project Structure

- `.env` - Mailtrap SMTP credentials
- `send-email.ts` - Script to send emails
- `src/main.ts` - NestJS application entry
- `src/app.module.ts` - NestJS module
- `src/app.module.ts` - NestJS module
