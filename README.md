# 🔐 NestAuth

**Defense in Depth Authentication System**  
*A production-ready authentication API demonstrating modern security engineering practices*

---

## 📋 Overview

NestAuth is a comprehensive authentication system built to showcase professional security engineering practices in a Node.js environment. This project demonstrates the complete lifecycle of secure software development, from architecture design through penetration testing and remediation.

**Key Highlights:**
- ✅ 40+ security controls implementing OWASP best practices
- ✅ Complete authentication flow with JWT, 2FA, and email verification
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
| **Security** | Helmet + Custom Guards | Multi-layered protection |
| **Email** | Nodemailer | Transactional email delivery |
| **Hashing** | bcryptjs | Secure password storage |

### Project Structure

```
nestauth/
├── src/
│   ├── auth/           # Authentication logic & strategies
│   ├── audit/          # Security audit logging
│   ├── email/          # Email verification & notifications
│   ├── guards/         # Custom security guards
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
- Role-based access control for sensitive endpoints (e.g., audit logs)

#### Cryptographic Security
- bcrypt password hashing (10 rounds)
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
- Full audit trail available via `/audit/logs` endpoint (open for development only)

#### Secure Development Practices
- Modular guards and middleware for extensibility
- Penetration tested against OWASP Top 10
- Documented remediation for all discovered vulnerabilities
- Security-focused code reviews and documentation

---


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
| JWT Algorithm Confusion | ✅ Fixed | Enforced RS256/HS256 with strict validation |
| Password Reset Token Attacks | ✅ Fixed | Cryptographically secure tokens with expiration |
| Missing Security Headers | ✅ Fixed | Implemented Helmet with OWASP recommendations |
| CORS Misconfiguration | ✅ Fixed | Restricted to specific allowed origins |
| Weak Password Policy | ⚠️ Partial | 6-char minimum enforced (complexity pending) |
> **Note:** Password complexity requirements are intentionally relaxed (6-character minimum) for testing and demo purposes. Enforce a stronger policy before production.

**Documentation**: Full audit trail available via `/audit/logs` endpoint

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
| `GET` | `/audit/logs` | Access audit logs <br> <sub>Open for development only. Remove public access before production.</sub> |

### Protected Endpoints (Requires JWT)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/logout` | Invalidate refresh token |
| `POST` | `/auth/setup-2fa` | Enable two-factor authentication |
| `POST` | `/auth/verify-2fa` | Verify 2FA code |
| `GET` | `/auth/profile` | Retrieve user profile |
| `GET` | `/audit/summary` | View security dashboard |

---

## 📑 Audit Logs

Audit logs are available via the `/audit/logs` endpoint.

> **Note:** For development ease, this endpoint is currently open and does not require authentication. Remove this in production for security.

You can filter logs by `eventType`, `email`, `riskLevel`, and `limit` (default: 50).
 Installation & Setup

⚠️ This project requires full manual setup. There is no hosted demo — you'll need to configure your own database, JWT secret, and (optionally) email credentials locally.

Prerequisites

Node.js 18+
PostgreSQL 14+
npm

1. Clone & Install
bashgit clone https://github.com/MissNapalm/nestjsauth.git
cd nestjsauth
npm install
2. Configure Environment Variables
bashcp .env.example .env
Then open .env and fill in:
envDATABASE_URL="postgresql://your_user:your_password@localhost:5432/nestauth"
JWT_SECRET="your-strong-random-secret"

# Optional — required for email verification & password reset
EMAIL_HOST="smtp.gmail.com"
EMAIL_PORT=587
EMAIL_USER="your-email@gmail.com"
EMAIL_PASS="your-app-specific-password"
3. Set Up PostgreSQL
Create the database manually before running migrations:
sqlCREATE DATABASE nestauth;
4. Run Migrations & Start
bashnpx prisma migrate dev
npm run dev
The API will be available at http://localhost:3000.
```

### Configuration

Create a `.env` file with the following variables:

```env
# Database Connection
DATABASE_URL="postgresql://user:password@localhost:5432/nestauth"

# JWT Configuration (use a strong, random secret)
JWT_SECRET="your-cryptographically-secure-secret-key"

# Email Configuration (optional - required for verification & password reset)
EMAIL_HOST="smtp.gmail.com"
EMAIL_PORT=587
EMAIL_USER="your-email@gmail.com"
EMAIL_PASS="your-app-specific-password"
```

**Security Note**: Never commit the `.env` file to version control. Use strong, randomly generated values for production deployments.

---

## 🔄 Authentication Flow

```
1. Registration
   └─> User submits email/password
       └─> Email verification sent
           └─> User clicks verification link
               └─> Account activated

2. Login
   └─> User submits credentials
       └─> Server validates & checks lockout
           └─> 2FA code sent (if enabled)
               └─> User enters 2FA code
                   └─> JWT tokens issued

3. Authenticated Requests
   └─> Client sends access token in Authorization header
       └─> Server validates JWT
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
- **Test Coverage**: Pentested against 10 common attack vectors
- **Lines of Code**: ~2,500 (TypeScript)
- **Database Migrations**: Version-controlled schema evolution
- **Audit Events**: Complete authentication lifecycle tracking

---

## 🎓 Learning Outcomes

This project demonstrates proficiency in:

- Secure software development lifecycle (SSDLC)
- OWASP Top 10 vulnerability prevention
- Authentication and authorization patterns
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
