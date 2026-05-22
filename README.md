# 🔐 NestAuth

**A defense-in-depth authentication API built with NestJS, PostgreSQL, and Argon2id.**

NestAuth is a production-style authentication system designed to demonstrate modern security engineering — not just a working login flow, but a hardened one. Every control is implemented deliberately, tested against real attack vectors, and documented so the reasoning is as visible as the code.

---

## 📋 Overview

NestAuth implements the full authentication lifecycle — registration, email verification, login, 2FA, password reset, refresh, logout, and role-based authorization — with security controls layered across authentication, cryptography, transport, input validation, rate limiting, and auditing.

**Highlights:**

- Argon2id password hashing using OWASP 2024 parameters (19 MiB memory, t=2)
- JWT access + refresh token flow with role embedded in payload and re-validated server-side
- Email-based two-factor authentication
- Role-based access control via custom `RolesGuard` and `@Roles()` decorator
- Multi-tier rate limiting and per-user account lockout
- Comprehensive audit logging, admin-only access to logs
- Pentested against applicable OWASP Top 10 categories with documented remediation

---

## 🏗️ Architecture

### Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| Framework | NestJS 10 | Modular TypeScript framework |
| Database | PostgreSQL + Prisma ORM | Type-safe, parameterized queries |
| Authentication | Passport.js + JWT (HS256) | Standard auth middleware |
| Authorization | Custom `RolesGuard` + `@Roles()` decorator | Role-based access control |
| Hashing | argon2id | Memory-hard password storage |
| Headers | Helmet | OWASP-recommended HTTP headers |
| Email | Nodemailer | Verification & 2FA delivery |

### Project Structure

```
nestauth/
├── src/
│   ├── auth/           # Authentication logic & strategies
│   ├── audit/          # Audit logging (ADMIN only)
│   ├── decorators/     # @Roles decorator
│   ├── email/          # Email verification & notifications
│   ├── guards/         # RolesGuard, custom throttler
│   ├── middleware/     # Request tracing
│   ├── prisma/         # Database integration
│   └── utils/          # Shared utilities
├── prisma/
│   ├── schema.prisma
│   └── migrations/
└── public/
    └── index.html      # Demo UI
```

---

## 🔐 Security Controls

Controls are grouped by category. Within each category, the goal is depth — multiple independent mechanisms so a single bypass doesn't cascade.

### Authentication & Authorization

- JWT-based authentication with separate access and refresh tokens
- Email-based two-factor authentication
- Mandatory email verification before account activation
- Password reset via cryptographically secure, expiring tokens
- Account lockout after 5 failed login attempts (15-minute duration)
- Brute-force protection on 2FA endpoints
- RBAC with `USER` / `ADMIN` roles stored in DB and embedded in JWTs, enforced server-side

### Cryptography

- Argon2id hashing with OWASP 2024 parameters (19 MiB, t=2, p=1) — memory-hard, GPU/ASIC resistant
- HS256 JWTs with strict algorithm validation (no `alg:none` confusion)
- Cryptographically secure random tokens (`crypto.randomBytes`) for all reset and verification flows
- Secrets loaded from environment variables; no hardcoded keys

### Input Validation & Injection Prevention

- DTO whitelisting via `class-validator` to prevent mass assignment
- All database access through Prisma's parameterized queries
- Input sanitization on user-provided fields to mitigate XSS
- Strict typing throughout the request lifecycle

### Rate Limiting & Abuse Prevention

- Tiered rate limits: 3 req/sec, 20 req/min, 100 req/15min
- Proxy-aware IP resolution for accurate throttling behind load balancers
- Per-user lockout independent of IP-based throttling

### Information Disclosure Prevention

- Constant-time comparisons and dummy operations to harden against timing-based user enumeration
- Generic error messages for all authentication failures
- No sensitive data in URLs, logs, or JWT payloads
- No stack traces returned in production responses

### Transport & Headers

- Helmet with OWASP-recommended HTTP security headers
- CORS restricted to allowed origins
- Secure cookie flags where applicable

### Audit & Observability

- Request ID middleware for distributed tracing
- Audit logging for every authentication event with risk classification
- Audit endpoints gated behind `ADMIN` role via `RolesGuard`
- Security event summaries for high-risk actions

---

## 🧪 Penetration Testing & Remediation

NestAuth was tested against the OWASP Top 10 categories applicable to its attack surface (authentication, authorization, cryptography, injection, input validation, security misconfiguration). Each finding was remediated and documented.

| Attack Vector | Status | Remediation |
|---|---|---|
| Mass Assignment | ✅ Fixed | DTO validation with explicit whitelisting |
| SQL Injection | ✅ Fixed | Parameterized queries via Prisma ORM |
| XSS | ✅ Fixed | Input sanitization on all user-supplied data |
| User Enumeration (timing) | ✅ Fixed | Constant-time comparisons + dummy operations |
| User Enumeration (errors) | ✅ Fixed | Generic responses across all auth failures |
| Account Lockout Bypass | ✅ Fixed | Server-side per-user lockout tracking |
| JWT Algorithm Confusion | ✅ Fixed | HS256 enforced with strict validation |
| Password Reset Token Attacks | ✅ Fixed | Cryptographically secure tokens with expiration |
| Missing Security Headers | ✅ Fixed | Helmet configured with OWASP defaults |
| CORS Misconfiguration | ✅ Fixed | Restricted to explicit origin allowlist |
| Broken Access Control (audit logs) | ✅ Fixed | `RolesGuard` enforces `ADMIN` on all audit routes |

---

## 🚀 API Endpoints

### Public

| Method | Endpoint | Description |
|---|---|---|
| POST | `/auth/register` | Create new user account |
| POST | `/auth/login` | Authenticate credentials |
| POST | `/auth/refresh` | Refresh access token |
| POST | `/auth/request-password-reset` | Request password reset email |
| POST | `/auth/reset-password` | Reset password with token |
| GET | `/auth/verify-email` | Verify email address |

### Protected (JWT required)

| Method | Endpoint | Description |
|---|---|---|
| POST | `/auth/logout` | Invalidate refresh token |
| POST | `/auth/setup-2fa` | Enable two-factor authentication |
| POST | `/auth/verify-2fa` | Verify 2FA code |
| GET | `/auth/profile` | Retrieve user profile |

### Admin (JWT + `ADMIN` role)

| Method | Endpoint | Description |
|---|---|---|
| GET | `/audit/logs` | Query audit logs (filter by eventType, email, riskLevel, limit) |
| GET | `/audit/summary` | View security event dashboard |

---

## 👤 Roles

Users are assigned `USER` or `ADMIN` at registration (default: `USER`). The role is stored in the database and embedded in the JWT payload. `RolesGuard` reads the role from the token and enforces access via the `@Roles()` decorator.

To promote a user to admin:

```sql
UPDATE users SET role = 'ADMIN' WHERE email = 'your@email.com';
```

---

## 📑 Audit Logs

Audit logs are available at `/audit/logs` and require an `ADMIN` JWT. Filterable by `eventType`, `email`, `riskLevel`, and `limit` (default: 50).

---

## ⚙️ Installation

**Prerequisites:** Node.js 18+, PostgreSQL 14+, npm

```bash
# Clone and install
git clone https://github.com/MissNapalm/nestjsauth.git
cd nestjsauth
npm install

# Configure environment
cp .env.example .env
```

Edit `.env`:

```env
DATABASE_URL="postgresql://your_user:your_password@localhost:5432/nestauth"
JWT_SECRET="your-strong-random-secret"

# Optional — required for email verification & password reset
EMAIL_HOST="smtp.gmail.com"
EMAIL_PORT=587
EMAIL_USER="your-email@gmail.com"
EMAIL_PASS="your-app-specific-password"
```

Then:

```bash
# In psql
CREATE DATABASE nestauth;

# Back in your terminal
npx prisma migrate dev
npm run dev
```

API will be live at `http://localhost:3000`.

> **Security Note:** Never commit your `.env`. Use strong, randomly generated values for production. The development database reset behavior is gated by `NODE_ENV` and will not run outside development.

---

## 🔄 Authentication Flow

```
1. Registration
   └─> User submits email/password
       └─> Verification email sent
           └─> User clicks link → account activated (role: USER)

2. Login
   └─> Credentials validated, lockout checked
       └─> 2FA code sent (if enabled)
           └─> JWT issued with embedded role

3. Authenticated Requests
   └─> JWT validated by JwtStrategy
       └─> Role extracted, RolesGuard enforces access

4. Token Refresh
   └─> Access token expires
       └─> Refresh token exchanged for new access token

5. Logout
   └─> Refresh token invalidated
```

---

## 🎓 What This Project Demonstrates

- Secure software development lifecycle (SSDLC) practices
- Authentication and authorization design at production quality
- Cryptographic correctness (algorithm choice, parameter selection, secret handling)
- Defensive programming against real-world attack classes
- Security testing and remediation as an integrated part of development
- Modular, maintainable architecture following enterprise NestJS patterns

---

## 🔮 Roadmap

- [ ] Refresh token rotation (single-use refresh tokens)
- [ ] NIST 800-63B aligned password policy (length-first, breach-list check via HIBP k-anonymity)
- [ ] OAuth2 / OpenID Connect (Google, GitHub)
- [ ] WebAuthn / FIDO2 hardware token support
- [ ] Session management dashboard
- [ ] IP-based risk scoring and anomaly detection
- [ ] OpenAPI / Swagger documentation
- [ ] Docker + Kubernetes deployment manifests

---

## 📄 License

MIT — see `LICENSE`.

---

## 🤝 Acknowledgments

Built as a portfolio piece to demonstrate production-grade authentication architecture. Inspired by real-world security engineering requirements.

⭐ If this helped you think about secure authentication, consider giving it a star.
