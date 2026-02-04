# NestJS Authentication with Email 2FA

A complete authentication system portfolio project built with NestJS featuring user registration, login, and two-factor authentication via email.

## 🎯 Features

- ✅ User Registration with password hashing (bcryptjs)
- ✅ User Login with email/password validation
- ✅ Two-Factor Authentication (2FA) via email
- ✅ JWT-based authorization
- ✅ Protected routes with JWT guards
- ✅ Clean, modern frontend UI
- ✅ RESTful API design
- ✅ CORS enabled

## 🚀 Tech Stack

**Backend:**
- NestJS 10
- JWT Authentication (@nestjs/jwt, @nestjs/passport)
- bcryptjs for password hashing
- Nodemailer for email (Gmail SMTP)
- TypeScript

**Frontend:**
- HTML5
- CSS3
- Vanilla JavaScript
- Responsive design

## 📋 Prerequisites

- Node.js (v18+)
- npm
- Gmail account with App Password (for 2FA emails)

## 🔧 Setup

1. **Install dependencies**
   ```bash
   npm install
   ```

2. **Configure environment variables** (`.env`)
   ```env
   GMAIL_USER=your_gmail@gmail.com
   GMAIL_PASS=your_16_char_app_password
   SENDER_EMAIL=your_gmail@gmail.com
   JWT_SECRET=your-super-secret-jwt-key
   ```

3. **Get Gmail App Password**
   - Go to https://myaccount.google.com/security
   - Enable 2-Step Verification
   - Generate App Password for Mail
   - Paste in `.env`

4. **Run the server**
   ```bash
   npm run dev
   ```

5. **Access the application**
   - Open http://localhost:3000 in your browser

## 📡 API Endpoints

### Authentication

**POST `/auth/register`**
- Register a new user
- Body: `{ "email": "user@example.com", "password": "password123" }`

**POST `/auth/login`**
- Login user and send 2FA code
- Body: `{ "email": "user@example.com", "password": "password123" }`
- Response: 2FA code sent to email

**POST `/auth/verify-2fa`**
- Verify 2FA code and get JWT token
- Body: `{ "email": "user@example.com", "code": "123456" }`
- Response: `{ "access_token": "jwt_token", "user": {...} }`

**GET `/auth/profile`**
- Get logged-in user profile
- Headers: `Authorization: Bearer <jwt_token>`

## 🔐 How 2FA Works

1. User enters email and password → `/auth/login`
2. 6-digit code is generated and sent via email
3. Code is valid for 5 minutes
4. User enters code → `/auth/verify-2fa`
5. JWT token is issued upon verification
6. Token can be used to access protected routes

## 📁 Project Structure

```
src/
├── auth/
│   ├── auth.controller.ts   # API endpoints
│   ├── auth.service.ts      # Business logic
│   └── jwt.strategy.ts      # JWT strategy
├── email/
│   └── email.service.ts     # Email sending
├── app.module.ts            # Main module
└── main.ts                  # Entry point

public/
└── index.html              # Frontend UI
```

## 🧪 Testing the Application

1. **Register**: Create account with email and password
2. **Login**: Enter credentials, receive 2FA code in email
3. **Verify**: Enter the code you received
4. **Profile**: View your authenticated user info
5. **Logout**: Clear session and token

## 📝 Notes

- Users are stored in-memory (resets on server restart)
- For production, replace with a real database (MongoDB, PostgreSQL, etc.)
- Update `JWT_SECRET` to a strong random string in production
- Implement rate limiting for security
- Add email verification during registration

## 🎓 Portfolio Value

This project demonstrates:
- ✅ Full-stack development (backend + frontend)
- ✅ Security best practices (password hashing, JWT)
- ✅ RESTful API design
- ✅ Email integration
- ✅ Error handling
- ✅ Clean code architecture
- ✅ TypeScript proficiency

## 🚀 Future Enhancements

- [ ] Database integration (MongoDB/PostgreSQL)
- [ ] Email verification during signup
- [ ] Password reset flow
- [ ] Refresh token rotation
- [ ] Rate limiting
- [ ] TOTP/Authenticator app support
- [ ] Refresh token mechanism
- [ ] User roles and permissions

## 📄 License

MIT
