# Scholarship Application System

## Overview

A Flask-based web application for managing scholarship applications with secure data handling and role-based access.

## Key Features

### For Applicants:
- Secure account registration
- Scholarship application submission
- Encrypted personal data storage
- Application status tracking

### For Administrators:
- Dashboard with application metrics
- Applicant shortlisting
- View/remove shortlisted candidates
- Secure admin account management

### Security Features
- Non-shortlisted applicant's data are encrypted to prevent data leak and admin's personal bias
- AES-256 encryption for sensitive data
- HMAC data integrity verification
- Password hashing with bcrypt
- Role-based access control

## Installation

1. **Prerequisites:**
   - Python 3.8+
   - MySQL database

2. **Setup:**
Set up and activate python virtual environment
- python -m venv venv
- venv\Scripts\activate
Install requirement
- pip install -r requirements.txt

3. **Database:**
- Create MySQL database named 'scholarap'
- Configure connection in `website/config.py`
- Initialize tables:
  ```
  flask shell
  >>> db.create_all()
  >>> exit()
  ```
4. **Create Admin**
- python create_admin.py

##Security Features (Cryptography Focus)
1. Data Confidentiality

    AES-256 Encryption (via Fernet)

        Personal data (NRIC, email, address) encrypted at rest using PBKDF2-HMAC-SHA256 key derivation

        100,000 iterations for key stretching (NIST-recommended)

        Configurable salt value (ENCRYPTION_SALT) prevents rainbow table attacks

        Keys never stored - derived dynamically using ENCRYPTION_KEY

2. Data Integrity

    HMAC-SHA256 Verification

        All encrypted data bundles include HMAC tags

        Prevents tampering via:
        python

        hmac.compare_digest(stored_hmac, generated_hmac)

        Field concatenation with | delimiter to prevent type confusion attacks

3. Authentication

    Password Security

        Werkzeug's generate_password_hash() using PBKDF2-HMAC-SHA256

        Configurable work factor (default 600,000 iterations)

        Per-password salts prevent identical hashes for same passwords

    Admin Safeguards

        CLI-based admin creation with master password (MAIN_ADMIN_PASSWORD)

        Hardened credential storage:
        python

        password_hash=generate_password_hash(password)

4. Session Security

    Flask-Login Protections

        Session tokens with SECRET_KEY signing

        CSRF protection via Flask-WTF (implicit in form submissions)

        Forced re-authentication for sensitive operations

5. Cryptographic Best Practices

    Key Management

        Encryption keys stored in config (not code) with fallback to env vars

        Separation of encryption key (ENCRYPTION_KEY) and salt (ENCRYPTION_SALT)

6. Attack Mitigations
Threat	                 Countermeasure
SQL Injection	    SQLAlchemy parameterized queries
Brute Force	      Password hashing (PBKDF2)
Data Tampering	  HMAC verification
Key Compromise	  Config-based key rotation capability
Padding Oracle	  Fernet's built-in HMAC
