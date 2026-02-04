# 🔐 NestAuth

A production-ready, secure authentication system built with NestJS, featuring JWT tokens, two-factor authentication, account lockout, and comprehensive audit logging.

![NestJS](https://img.shields.io/badge/NestJS-10.0-red?style=flat-square&logo=nestjs)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-blue?style=flat-square&logo=postgresql)
![Prisma](https://img.shields.io/badge/Prisma-5.22-2D3748?style=flat-square&logo=prisma)
![TypeScript](https://img.shields.io/badge/TypeScript-5.0-3178C6?style=flat-square&logo=typescript)

## ✨ Features

### 🔑 Authentication
- **User Registration** with email and password validation
- **User Login** with JWT access tokens (15-minute expiry)
- **Refresh Tokens** (7-day expiry) for seamless session renewal
- **Password Reset** via email with secure time-limited tokens
- **Email Verification** on registration with verification links
- **Two-Factor Authentication (2FA)** with time-based codes

### 🛡️ Security Features
- **Account Lockout** - Locks account for 15 minutes after 5 failed login attempts
- **Password Hashing** with bcrypt (10 salt rounds)
- **Rate Limiting** with @nestjs/throttler to prevent brute force attacks
- **OWASP Security Headers** via Helmet (XSS protection, clickjacking prevention, CSP)
- **JWT Token Validation** with passport-jwt strategy

### 🗄️ Database
- **PostgreSQL** database with Prisma ORM
- **Database Migrations** for schema versioning
- **Relational Models** - Users, RefreshTokens, VerificationTokens, TwoFactorCodes, AuditLogs

### � Audit & Monitoring
- **Comprehensive Audit Logging** - Tracks all security events
- **Logged Events**: LOGIN, LOGOUT, REGISTER, FAILED_LOGIN, PASSWORD_RESET, ACCOUNT_LOCKED, 2FA_ENABLED
- **Audit API** - Query audit logs by user or action type

### 📧 Email
- **Nodemailer Integration** for transactional emails
- **Email Verification** with secure tokens
- **Password Reset Emails** with expiring links

### 🎨 Frontend
- **Built-in UI** with login, register, and dashboard views
- **Dark/Light Mode** toggle with persistent preference
- **Responsive Design** for mobile and desktop

## � API Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/auth/register` | Register new user | ❌ |
| POST | `/auth/login` | Login with credentials | ❌ |
| POST | `/auth/refresh` | Refresh access token | ❌ |
| POST | `/auth/logout` | Invalidate refresh token | ✅ |
| POST | `/auth/request-password-reset` | Request password reset email | ❌ |
| POST | `/auth/reset-password` | Reset password with token | ❌ |
| GET | `/auth/verify-email` | Verify email address | ❌ |
| POST | `/auth/setup-2fa` | Enable two-factor auth | ✅ |
| POST | `/auth/verify-2fa` | Verify 2FA code | ✅ |
| GET | `/auth/profile` | Get user profile | ✅ |
| GET | `/audit` | Get audit logs | ✅ |

## 🛡️ Security Protections

| Attack Type | Protection |
|-------------|------------|
| Brute Force | Rate limiting + Account lockout |
| Credential Stuffing | Account lockout after 5 attempts |
| XSS | Content-Security-Policy headers |
| Clickjacking | X-Frame-Options header |
| Token Replay | Short-lived JWTs + refresh rotation |
| Password Exposure | bcrypt hashing (10 rounds) |
| Session Hijacking | HTTP-only cookies, secure tokens |

## 🛠️ Tech Stack

- **[NestJS 10](https://nestjs.com/)** - Progressive Node.js framework
- **[Prisma 5](https://www.prisma.io/)** - Next-generation ORM
- **[PostgreSQL](https://www.postgresql.org/)** - Relational database
- **[Passport.js](http://www.passportjs.org/)** - Authentication middleware
- **[JWT](https://jwt.io/)** - Token-based authentication
- **[bcryptjs](https://github.com/dcodeIO/bcrypt.js)** - Password hashing
- **[Nodemailer](https://nodemailer.com/)** - Email sending
- **[Helmet](https://helmetjs.github.io/)** - Security headers

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/MissNapalm/nestjsauth.git
cd nestjsauth

# Install dependencies
npm install

# Set up environment variables
cp .env.example .env
# Edit .env with your database and email credentials

# Run database migrations
npx prisma migrate dev

# Start the development server
npm run dev
```

## ⚙️ Environment Variables

```env
# Database
DATABASE_URL="postgresql://user:password@localhost:5432/nestauth"

# JWT
JWT_SECRET="your-super-secret-jwt-key"

# Email (optional - for email verification & password reset)
EMAIL_HOST="smtp.gmail.com"
EMAIL_PORT=587
EMAIL_USER="your-email@gmail.com"
EMAIL_PASS="your-app-password"
```

## 📁 Project Structure

```
nestauth/
├── prisma/
│   ├── schema.prisma      # Database schema
│   └── migrations/        # Database migrations
├── public/
│   └── index.html         # Frontend UI
├── src/
│   ├── auth/              # Authentication module
│   │   ├── auth.controller.ts
│   │   ├── auth.service.ts
│   │   ├── auth.dto.ts
│   │   └── jwt.strategy.ts
│   ├── audit/             # Audit logging module
│   ├── email/             # Email service module
│   ├── prisma/            # Prisma database module
│   ├── app.module.ts
│   └── main.ts
└── package.json
```

## 🔐 How Authentication Works

1. **Register**: User creates account → Email verification sent
2. **Verify Email**: User clicks verification link
3. **Login**: User enters credentials → 2FA code sent (if enabled)
4. **2FA Verify**: User enters code → JWT access token + refresh token issued
5. **Access Protected Routes**: Use access token in Authorization header
6. **Token Refresh**: When access token expires, use refresh token to get new one
7. **Logout**: Refresh token is invalidated

## 🧪 Testing

```bash
# Run unit tests
npm run test

# Run e2e tests
npm run test:e2e
```

## 📄 License

MIT License - feel free to use this project for learning or production.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

