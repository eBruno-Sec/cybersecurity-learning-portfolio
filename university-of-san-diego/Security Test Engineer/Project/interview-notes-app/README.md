# Interview Notes Application

## Project Overview

A secure web application designed for interviewers to organize and manage candidate notes during job interviews. Built as part of CYBR-510 coursework focusing on secure web application development lifecycle, threat modeling, and penetration testing.

**Course:** CYBR-510 - Secure Web App Lifecycle with SpecKit  
**Author:** Zabre  
**Institution:** University of San Diego

---

## Features

### Core Functionality
- **User Authentication**: Secure registration and login system with password hashing
- **Interview Notes Management**: Create, read, update, and delete interview notes
- **Role-Based Access Control (RBAC)**: Separate permissions for regular users and administrators
- **Admin Dashboard**: View all system users and interview notes across the organization

### Security Features
- Bcrypt password hashing (10 salt rounds)
- Session-based authentication
- SQL injection prevention via parameterized queries
- XSS protection through EJS template auto-escaping
- Input validation on all forms
- Role-based authorization checks

---

## Technology Stack

- **Backend**: Node.js with Express framework
- **Database**: SQLite (file-based database)
- **Template Engine**: EJS (Embedded JavaScript)
- **Authentication**: bcryptjs for password hashing, express-session for session management
- **Port**: localhost:3000

---

## Installation & Setup

### Prerequisites
- Node.js (v14 or higher)
- npm (Node Package Manager)
- Git (optional, for version control)

### Installation Steps

1. **Clone the repository**
```bash
git clone https://github.com/YOUR_USERNAME/interview-notes-app.git
cd interview-notes-app
```

2. **Install dependencies**
```bash
npm install
```

3. **Start the application**
```bash
node server.js
```

4. **Access the application**
- Open your browser and navigate to: `http://localhost:3000`
- Default admin credentials:
  - Username: `admin`
  - Password: `admin123`

---

## Project Structure

```
interview-notes-app/
├── node_modules/          # Dependencies (auto-generated)
├── public/                # Static assets (CSS, images)
├── routes/
│   ├── auth.js           # Authentication routes
│   ├── notes.js          # Notes CRUD operations
│   └── admin.js          # Admin-only routes
├── views/
│   ├── login.ejs         # Login page
│   ├── register.ejs      # Registration page
│   ├── notes.ejs         # View user's notes
│   ├── create-note.ejs   # Create new note
│   ├── edit-note.ejs     # Edit existing note
│   ├── admin-users.ejs   # Admin: view all users
│   └── admin-notes.ejs   # Admin: view all notes
├── database.js           # SQLite database setup
├── server.js             # Express server entry point
├── interview-notes.speckit  # Application specification (YAML)
├── interview_notes.db    # SQLite database file
├── package.json          # Project dependencies
└── README.md            # This file
```

---

## Database Schema

### Users Table
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| username | TEXT | Unique username |
| password_hash | TEXT | Bcrypt hashed password |
| role | TEXT | User role ('regular' or 'admin') |

### Interview Notes Table
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| candidate_name | TEXT | Name of interview candidate |
| position | TEXT | Job position/title |
| interview_date | TEXT | Date of interview |
| notes | TEXT | Interview notes content |
| user_id | INTEGER | Foreign key to users table |
| created_at | DATETIME | Timestamp of creation |

---

## Risk Assessment

### Identified Security Risks

#### High Risk
1. **Default Admin Credentials**
   - **Risk**: Hardcoded admin account with predictable credentials
   - **Impact**: Unauthorized admin access if not changed
   - **Mitigation**: Force password change on first login (recommended enhancement)

2. **Session Hijacking**
   - **Risk**: Session tokens could be intercepted
   - **Impact**: Account takeover
   - **Mitigation**: Implement HTTPS in production, use secure cookie flags

3. **SQL Injection** (Mitigated)
   - **Risk**: Malicious SQL queries via user input
   - **Impact**: Database compromise, data theft
   - **Mitigation**: ✅ Parameterized queries implemented throughout application

#### Medium Risk
1. **Brute Force Attacks**
   - **Risk**: Unlimited login attempts
   - **Impact**: Account compromise through password guessing
   - **Mitigation**: Implement rate limiting and account lockout (future enhancement)

2. **Cross-Site Scripting (XSS)** (Mitigated)
   - **Risk**: Malicious scripts in user input
   - **Impact**: Session theft, unauthorized actions
   - **Mitigation**: ✅ EJS auto-escapes HTML output

3. **Insecure Direct Object References (IDOR)**
   - **Risk**: Users accessing notes via ID manipulation
   - **Impact**: Unauthorized data access
   - **Mitigation**: ✅ Authorization checks on all note operations

#### Low Risk
1. **Information Disclosure**
   - **Risk**: Verbose error messages in production
   - **Impact**: Attacker gains system information
   - **Mitigation**: Generic error messages, proper logging

2. **Denial of Service (DoS)**
   - **Risk**: Resource exhaustion via large file uploads or excessive requests
   - **Impact**: Service unavailability
   - **Mitigation**: Implement request size limits and rate limiting (future enhancement)

---

## Threat Model

### STRIDE Analysis

#### Spoofing Identity
- **Threat**: Attacker impersonates legitimate user
- **Controls**: Password hashing, session management
- **Testing**: Verify bcrypt implementation, test session timeout

#### Tampering with Data
- **Threat**: Unauthorized modification of interview notes
- **Controls**: Role-based access control, authorization checks
- **Testing**: Attempt to edit other users' notes, test admin-only routes

#### Repudiation
- **Threat**: User denies creating or modifying notes
- **Controls**: User ID tracking on all notes, timestamps
- **Testing**: Verify user_id association, check created_at field

#### Information Disclosure
- **Threat**: Unauthorized access to sensitive interview data
- **Controls**: RBAC, session-based authentication
- **Testing**: Access notes without authentication, test privilege escalation

#### Denial of Service
- **Threat**: Service disruption through resource exhaustion
- **Controls**: Currently minimal
- **Testing**: Load testing, large payload testing (Part 3)

#### Elevation of Privilege
- **Threat**: Regular user gains admin access
- **Controls**: Role checks on admin routes, session role validation
- **Testing**: Attempt to access /admin/* routes as regular user

---

## Penetration Testing Scope

### Testing Objectives (CYBR-510 Parts 2-4)

1. **Authentication Testing**
   - Password strength requirements
   - Session management security
   - Logout functionality
   - Concurrent session handling

2. **Authorization Testing**
   - RBAC enforcement on all routes
   - Horizontal privilege escalation (accessing other users' notes)
   - Vertical privilege escalation (regular user → admin)

3. **Input Validation Testing**
   - SQL injection attempts
   - XSS payload injection
   - Command injection attempts
   - Path traversal attempts

4. **Business Logic Testing**
   - Note creation/edit/delete workflows
   - Admin functionality constraints
   - Data integrity validation

5. **OWASP Top 10 Coverage**
   - A01:2021 – Broken Access Control
   - A02:2021 – Cryptographic Failures
   - A03:2021 – Injection
   - A04:2021 – Insecure Design
   - A05:2021 – Security Misconfiguration
   - A07:2021 – Identification and Authentication Failures

### Test Tools
- Manual testing via browser and Postman
- Static analysis: ESLint, npm audit
- Automated security scanning (planned)
- LLM-generated attack payloads (extra credit)

---

## API Routes

### Public Routes
- `GET /` - Redirects to login
- `GET /auth/login` - Login page
- `GET /auth/register` - Registration page
- `POST /auth/register` - Create new account
- `POST /auth/login` - Authenticate user
- `POST /auth/logout` - End session

### Protected Routes (Authentication Required)
- `GET /notes` - View own interview notes
- `GET /notes/create` - Create note form
- `POST /notes/create` - Save new note
- `GET /notes/edit/:id` - Edit note form
- `POST /notes/edit/:id` - Update note
- `POST /notes/delete/:id` - Delete note

### Admin-Only Routes
- `GET /admin/users` - View all system users
- `GET /admin/notes` - View all interview notes

---

## Security Considerations

### Implemented Controls
✅ Password hashing with bcrypt  
✅ Parameterized SQL queries  
✅ Session-based authentication  
✅ Role-based access control  
✅ XSS protection via EJS escaping  
✅ Input validation on forms  

### Future Enhancements
- [ ] HTTPS/TLS encryption
- [ ] Rate limiting on authentication endpoints
- [ ] Account lockout after failed login attempts
- [ ] Password complexity requirements
- [ ] Multi-factor authentication (MFA)
- [ ] Audit logging for all actions
- [ ] CSRF token protection
- [ ] Security headers (Helmet.js)
- [ ] Input sanitization library
- [ ] Password change enforcement for default admin

---

## Known Limitations

1. **Development Environment**: Currently configured for local development only
2. **Default Admin**: Hardcoded admin credentials should be changed in production
3. **No HTTPS**: Production deployment requires SSL/TLS configuration
4. **Limited Logging**: Minimal audit trail for security events
5. **No Rate Limiting**: Vulnerable to brute force and DoS attacks
6. **SQLite Database**: Not suitable for high-concurrency production use

---

## Assignment Deliverables

### Part 1: Build Web App ✅
- [x] SpecKit specification file
- [x] Working web application
- [x] Screenshots of functionality
- [x] GitHub repository

### Part 2: LLM-Generated Test Plan (Upcoming)
- [ ] Test cases from ChatGPT/Claude
- [ ] LLM Review Notes
- [ ] OWASP Top 10 negative tests

### Part 3: Test Execution (Upcoming)
- [ ] Test results and screenshots
- [ ] Bug documentation
- [ ] Security control bypass testing

### Part 4: Static Code Analysis (Upcoming)
- [ ] Tool output analysis
- [ ] False positive identification
- [ ] Security principle mapping

### Part 5: Final Presentation (Upcoming)
- [ ] Slide deck summary
- [ ] 5-7 minute class presentation

---

## Contributing

This is an academic project for CYBR-510. Contributions are not accepted as this represents individual coursework.

---

## License

This project is submitted as coursework for University of San Diego CYBR-510. All rights reserved.

---

## Acknowledgments

- **Course Instructor**: CYBR-510 Faculty
- **Framework**: SpecKit methodology
- **Security Standards**: OWASP Top 10, STRIDE threat modeling
- **Development**: Node.js and Express.js communities

---

## Contact

**Student**: Zabre  
**Course**: CYBR-510 - Secure Web App Lifecycle  
**Institution**: University of San Diego

---

## Version History

- **v1.0.0** (Current) - Initial release with all Part 1 requirements met
  - User authentication system
  - Interview notes CRUD functionality
  - Admin dashboard
  - Role-based access control
  - Edit and delete capabilities
