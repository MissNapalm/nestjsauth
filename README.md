# 🔐 NestAuth

**Defense in Depth Authentication System**  
*A production-ready authentication API demonstrating modern security engineering practices*

---

## 📋 Overview

NestAuth is a comprehensive authentication system built to showcase professional security engineering practices in a Node.js environment. This project demonstrates the complete lifecycle of secure software development, from architecture design through penetration testing and remediation.

**Key Highlights:**
- ✅ 40+ security controls implementing OWASP best practices
- ✅ Complete authentication flow with JWT, 2FA, and email verification
- ✅ Role-based access control (ADMIN / USER) with JWT-embedded roles
- ✅ Real-world penetration testing with documented remediation
- ✅ Production-ready architecture with comprehensive audit logging
- ✅ Modular, maintainable code following enterprise patterns

---

## 🎯 Purpose

This project was developed as a portfolio piece to demonstrate:

- Practical application of secure coding practices
- Ability to identify and remediate security vulnerabilities
- Professional-grade code organization and documentation
- Real-world security engineering experience

---

## 🏗️ Architecture

### Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Framework** | NestJS 10 | Modular TypeScript framework |
| **Database** | PostgreSQL + Prisma ORM | Type-safe database operations |
| **Authentication** | Passport.js + JWT | Industry-standard auth middleware |
| **Authorization** | Custom RolesGuard + Decorator | Role-based access control |
| **Security** | Helmet + Custom Guards | Multi-layered protection |
| **Email** | Nodemailer | Transactional email delivery |
| **Hashing** | argon2id | Secure password storage (OWASP recommended) |

### Project Structure

```
nestauth/
├── src/
│   ├── auth/           # Authentication logic & strategies
│   ├── audit/          # Security audit logging (ADMIN only)
│   ├── decorators/     # @Roles decorator
│   ├── email/          # Email verification & notifications
│   ├── guards/         # RolesGuard, custom throttler
│   ├── middleware/     # Request processing & tracing
│   ├── prisma/         # Database integration
│   └── utils/          # Shared utilities
├── prisma/
│   ├── schema.prisma   # Database schema
│   └── migrations/     # Version-controlled migrations
└── public/
    └── index.html      # Demo UI
```

---

## 🔐 Security Implementation

### Core Security Features

This project implements a comprehensive set of security controls, organized as follows:

#### Authentication & Authorization
- JWT-based authentication (access & refresh tokens)
- Two-factor authentication (2FA) via email
- Mandatory email verification before account activation
- Secure password reset flow with expiring, cryptographically secure tokens
- Password complexity enforcement (6+ chars, relaxed for testing)
- Role-based access control — `USER` and `ADMIN` roles stored in the database and embedded in JWT payloads; sensitive endpoints enforced by `RolesGuard` + `@Roles()` decorator

#### Cryptographic Security
- Argon2id password hashing (OWASP 2024 parameters: 19 MiB memory, 2 iterations — memory-hard, GPU/ASIC resistant)
- Cryptographically secure random tokens for password reset
- JWT secrets loaded from environment variables (no hardcoded secrets)
- No plaintext password storage
- No sensitive data in JWT payloads

#### Data Protection
- No user information in URL parameters
- No passwords in logs or API responses
- Secure cookie flags (when applicable)
- Automatic database reset on shutdown (development only)

#### Attack Prevention & Hardening
- Account lockout after 5 failed login attempts (15-minute duration)
- Multi-tier rate limiting (3 req/sec, 20 req/min, 100 req/15min)
- Proxy-aware IP-based throttling
- Brute force protection on 2FA endpoints
- User enumeration prevention (timing and error message hardening)
- Email enumeration prevention
- SQL injection prevention (Prisma ORM parameterization)
- XSS protection (input sanitization)
- Mass assignment protection (DTO whitelisting)
- CORS restricted to allowed origins

#### Security Headers & Error Handling
- OWASP-recommended HTTP security headers (via Helmet)
- No JWT algorithm confusion vulnerability (alg:none)
- Generic error messages (no information leakage)
- No stack traces in production

#### Monitoring, Logging & Auditing
- Request ID middleware for distributed tracing
- Comprehensive audit logging for all authentication events
- Security event alerting (e.g., high-risk actions)
- Audit endpoints restricted to `ADMIN` role

#### Secure Development Practices
- Modular guards and middleware for extensibility
- Penetration tested against OWASP Top 10
- Documented remediation for all discovered vulnerabilities
- Security-focused code reviews and documentation

---

## 🧪 Penetration Testing & Remediation

This project underwent systematic security testing covering common vulnerability classes:

### Vulnerabilities Tested

| Attack Vector | Status | Remediation |
|--------------|--------|-------------|
| Mass Assignment | ✅ Fixed | Implemented DTO validation with whitelisting |
| SQL Injection | ✅ Fixed | Enforced parameterized queries via Prisma ORM |
| XSS (Cross-Site Scripting) | ✅ Fixed | Input sanitization on all user-provided data |
| User Enumeration (Timing) | ✅ Fixed | Constant-time comparisons and dummy operations |
| User Enumeration (Error Messages) | ✅ Fixed | Generic responses for all auth failures |
| Account Lockout Bypass | ✅ Fixed | Server-side lockout tracking per user |
| JWT Algorithm Confusion | ✅ Fixed | Enforced HS256 with strict validation |
| Password Reset Token Attacks | ✅ Fixed | Cryptographically secure tokens with expiration |
| Missing Security Headers | ✅ Fixed | Implemented Helmet with OWASP recommendations |
| CORS Misconfiguration | ✅ Fixed | Restricted to specific allowed origins |
| Broken Access Control (Audit Logs) | ✅ Fixed | ADMIN-only RolesGuard on all audit endpoints |
| Weak Password Policy | ⚠️ Partial | 6-char minimum enforced (complexity pending) |

---

## 🚀 API Endpoints

### Public Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/register` | Create new user account |
| `POST` | `/auth/login` | Authenticate user credentials |
| `POST` | `/auth/refresh` | Refresh access token |
| `POST` | `/auth/request-password-reset` | Request password reset email |
| `POST` | `/auth/reset-password` | Reset password with token |
| `GET` | `/auth/verify-email` | Verify email address |

### Protected Endpoints (Requires JWT)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/logout` | Invalidate refresh token |
| `POST` | `/auth/setup-2fa` | Enable two-factor authentication |
| `POST` | `/auth/verify-2fa` | Verify 2FA code |
| `GET` | `/auth/profile` | Retrieve user profile |

### Admin Endpoints (Requires JWT + ADMIN role)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/audit/logs` | Query audit logs (filter by `eventType`, `email`, `riskLevel`, `limit`) |
| `GET` | `/audit/summary` | View security event dashboard |

---

## 👤 Roles

Users are assigned either the `USER` or `ADMIN` role at registration (default: `USER`). The role is stored in the database and embedded in the JWT payload. The `RolesGuard` reads the role from the token and enforces access on protected routes via the `@Roles()` decorator.

To promote a user to admin, update their record directly in the database:

```sql
UPDATE users SET role = 'ADMIN' WHERE email = 'your@email.com';
```

---

## 📑 Audit Logs

Audit logs are available via the `/audit/logs` endpoint and require an `ADMIN` JWT. You can filter by `eventType`, `email`, `riskLevel`, and `limit` (default: 50).

---

## ⚙️ Installation & Setup

It's mostly just cloning and filling in a `.env` — shouldn't take more than a few minutes.

**Prerequisites:** Node.js 18+, PostgreSQL 14+, npm

```bash
# Clone and install
git clone https://github.com/MissNapalm/nestjsauth.git
cd nestjsauth
npm install

# Set up environment variables
cp .env.example .env
```

Open `.env` and fill in your database URL, a JWT secret, and optionally your email credentials:

```env
DATABASE_URL="postgresql://your_user:your_password@localhost:5432/nestauth"
JWT_SECRET="your-strong-random-secret"

# Optional — only needed for email verification & password reset
EMAIL_HOST="smtp.gmail.com"
EMAIL_PORT=587
EMAIL_USER="your-email@gmail.com"
EMAIL_PASS="your-app-specific-password"
```

Then create the database, run migrations, and start the server:

```bash
# In psql
CREATE DATABASE nestauth;

# Back in your terminal
npx prisma migrate dev
npm run dev
```

API will be live at `http://localhost:3000`. That's it!

> **Security Note:** Never commit your `.env` file. Use strong, randomly generated values for production.

---

## 🔄 Authentication Flow

```
1. Registration
   └─> User submits email/password
       └─> Email verification sent
           └─> User clicks verification link
               └─> Account activated (role: USER)

2. Login
   └─> User submits credentials
       └─> Server validates & checks lockout
           └─> 2FA code sent (if enabled)
               └─> User enters 2FA code
                   └─> JWT issued with role embedded

3. Authenticated Requests
   └─> Client sends JWT in Authorization header
       └─> JwtStrategy validates token & extracts role
           └─> RolesGuard enforces role requirements
               └─> Protected resource accessed

4. Token Refresh
   └─> Access token expires
       └─> Client sends refresh token
           └─> New access token issued

5. Logout
   └─> Refresh token invalidated
```

---

## 📊 Key Metrics

- **Security Controls**: 40+ implemented features
- **Test Coverage**: Pentested against 11 common attack vectors
- **Lines of Code**: ~2,500 (TypeScript)
- **Database Migrations**: Version-controlled schema evolution
- **Audit Events**: Complete authentication lifecycle tracking

---

## 🎓 Learning Outcomes

This project demonstrates proficiency in:

- Secure software development lifecycle (SSDLC)
- OWASP Top 10 vulnerability prevention
- Authentication and authorization patterns
- Role-based access control design
- Cryptographic best practices
- Defensive programming techniques
- Security testing and remediation
- Professional code organization and documentation

---

## 🔮 Future Enhancements

- [ ] Enhanced password complexity requirements (uppercase, numbers, special chars)
- [ ] OAuth2/OpenID Connect integration (Google, GitHub)
- [ ] Hardware token support (WebAuthn/FIDO2)
- [ ] Session management dashboard
- [ ] IP-based risk scoring
- [ ] Advanced audit analytics and anomaly detection
- [ ] Comprehensive API documentation (Swagger/OpenAPI)
- [ ] Docker containerization
- [ ] Kubernetes deployment manifests

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Acknowledgments

Built with industry best practices and inspired by real-world security requirements. This project is designed for educational and portfolio purposes, demonstrating production-ready authentication architecture suitable for enterprise applications.

---

**⭐ If you found this project helpful for learning secure authentication practices, please consider giving it a star!**
