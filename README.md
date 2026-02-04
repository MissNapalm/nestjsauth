
# 🔐 NestAuth: Enterprise-Grade Secure Authentication for Node.js

A showcase of advanced security engineering, built with NestJS, Prisma, and PostgreSQL. This project demonstrates how to build a modern authentication system with 40+ security features, real pentesting, and professional code structure.

---

## 🚀 Why This Project Stands Out

- **Security-First Design:** Implements industry best practices and OWASP recommendations throughout.
- **Comprehensive Feature Set:** JWT, 2FA, email verification, password reset, account lockout, rate limiting, audit logging, and more.
- **Real Pentesting:** Vulnerabilities were actively tested, discovered, and remediated. Audit logs prove the process.
- **Modular, Scalable Code:** Follows professional backend architecture for maintainability and extensibility.
- **Production-Ready:** All critical endpoints protected, secrets managed, and error handling hardened.

---

## 🛡️ Security Features (40+)

- JWT authentication (access & refresh tokens)
- Two-factor authentication (2FA) via email
- Email verification required before login
- Password reset with secure, expiring tokens
- Passwords hashed with bcryptjs (10 rounds)
- Account lockout after 5 failed login attempts (15 min lock)
- Multi-tier rate limiting (3/sec, 20/min, 100/15min)
- Custom IP-based throttler guard (proxy-aware)
- CORS restricted to allowed origins
- Security headers (OWASP recommended)
- Request ID middleware for distributed tracing
- Audit logging for all auth events
- Mass assignment protection on DTOs
- SQL injection protection (Prisma ORM)
- XSS protection (input sanitization)
- JWT secret loaded from environment variable
- Password reset tokens are cryptographically secure
- Timing attack protection on login (dummy bcrypt hash)
- Brute force protection for 2FA
- User enumeration prevention (timing & error messages)
- Email enumeration prevention
- Password minimum length (6 chars, needs complexity improvement)
- Automatic database reset on shutdown (dev only)
- Audit endpoints protected with JWT guard
- No JWT alg:none vulnerability
- All endpoints return generic error messages
- No password in logs or responses
- No stack traces in production errors
- Secure cookie flags (if cookies used)
- No sensitive data in JWT payload
- No user info in URL/query params
- No open CORS wildcards
- No HTTP parameter pollution
- No insecure redirects
- No user-supplied HTML rendered
- No plaintext password storage
- No default admin accounts
- No hardcoded secrets in codebase
- No excessive error detail in responses
- No unprotected admin/audit endpoints

---

## 🧪 Pentesting & Remediation

- Mass assignment
- SQL injection
- XSS
- User enumeration (timing)
- Account lockout
- JWT alg:none
- Password reset token attacks
- Security headers
- CORS
- Password strength

**All vulnerabilities found were fixed and retested.**

---

## 🗄️ Tech Stack

- **NestJS 10** (TypeScript, modular architecture)
- **Prisma 5** (ORM, migrations)
- **PostgreSQL** (relational database)
- **Passport.js** (authentication middleware)
- **JWT** (token-based authentication)
- **bcryptjs** (password hashing)
- **Nodemailer** (email delivery)
- **Helmet** (security headers)

---

## 📁 Project Structure

```
nestauth/
├── prisma/         # Database schema & migrations
├── public/         # Frontend UI
├── src/
│   ├── auth/       # Authentication logic
│   ├── audit/      # Audit logging
│   ├── email/      # Email service
│   ├── guards/     # Custom guards
│   ├── middleware/ # Request ID, etc.
│   ├── prisma/     # DB integration
│   └── utils/      # Utility functions
├── package.json
└── README.md
```

---

## ✨ Key Features & Endpoints

| Method | Endpoint                        | Description                        | Auth Required |
|--------|----------------------------------|------------------------------------|---------------|
| POST   | `/auth/register`                | Register new user                  | ❌            |
| POST   | `/auth/login`                   | Login with credentials             | ❌            |
| POST   | `/auth/refresh`                 | Refresh access token               | ❌            |
| POST   | `/auth/logout`                  | Invalidate refresh token           | ✅            |
| POST   | `/auth/request-password-reset`  | Request password reset email       | ❌            |
| POST   | `/auth/reset-password`          | Reset password with token          | ❌            |
| GET    | `/auth/verify-email`            | Verify email address               | ❌            |
| POST   | `/auth/setup-2fa`               | Enable two-factor auth             | ✅            |
| POST   | `/auth/verify-2fa`              | Verify 2FA code                    | ✅            |
| GET    | `/auth/profile`                 | Get user profile                   | ✅            |
| GET    | `/audit/logs`                   | Get audit logs                     | ✅            |
| GET    | `/audit/summary`                | Security dashboard                 | ✅            |

---

## ⚡ Quickstart

```bash
# Clone the repository
$ git clone https://github.com/MissNapalm/nestjsauth.git
$ cd nestjsauth

# Install dependencies
$ npm install

# Set up environment variables
$ cp .env.example .env
# Edit .env with your database and email credentials

# Run database migrations
$ npx prisma migrate dev

# Start the development server
$ npm run dev
```

---

## 🧑‍💻 For Security Engineers & Recruiters

- All code is modular, readable, and follows professional standards.
- Audit logs and pentest results are available for review.
- Every feature is implemented with security in mind, not just as a checklist.
- This project is ideal for demonstrating hands-on security engineering in Node.js/NestJS.

---

## 📄 License

MIT License - use, learn, and contribute!

---

## 🤝 Contributing

Pull requests and feedback are welcome!
| GET | `/audit` | Get audit logs | ✅ |


## 🛡️ Security Features

This project implements 40+ security features, including:

- JWT authentication (access & refresh tokens)
- 2FA (two-factor authentication) via email
- Email verification required before login
- Password reset with secure, expiring tokens
- Passwords hashed with bcryptjs (10 rounds)
- Account lockout after 5 failed login attempts (15 min lock)
- Multi-tier rate limiting (3/sec, 20/min, 100/15min)
- Custom IP-based throttler guard (proxy-aware)
- CORS restricted to allowed origins
- Security headers (OWASP recommended)
- Request ID middleware for distributed tracing
- Audit logging for all auth events
- Mass assignment protection on DTOs
- SQL injection protection (Prisma ORM)
- XSS protection (input sanitization)
- JWT secret loaded from environment variable
- Password reset tokens are cryptographically secure
- Timing attack protection on login (dummy bcrypt hash)
- Brute force protection for 2FA
- User enumeration prevention (timing & error messages)
- Email enumeration prevention
- Password minimum length (6 chars, needs complexity improvement)
- Automatic database reset on shutdown (dev only)
- Audit endpoints protected with JWT guard
- No JWT alg:none vulnerability
- All endpoints return generic error messages
- No password in logs or responses
- No stack traces in production errors
- Secure cookie flags (if cookies used)
- No sensitive data in JWT payload
- No user info in URL/query params
- No open CORS wildcards
- No HTTP parameter pollution
- No insecure redirects
- No user-supplied HTML rendered
- No plaintext password storage
- No default admin accounts
- No hardcoded secrets in codebase
- No excessive error detail in responses
- No unprotected admin/audit endpoints

### 🧪 Pentesting & Remediation

This project was pentested for:
- Mass assignment
- SQL injection
- XSS
- User enumeration (timing)
- Account lockout
- JWT alg:none
- Password reset token attacks
- Security headers
- CORS
- Password strength

All vulnerabilities found were fixed and retested. See `/audit/logs` for a full audit trail.

---

> **Portfolio Note:**
> This project demonstrates practical, hands-on security engineering. All features were implemented, pentested, and remediated as you would in a real-world environment. See the code and audit logs for details.

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

