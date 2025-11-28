# Sociovia User Management System

## Overview

Sociovia is a Flask-based user management system designed for business networking and onboarding. The application implements a comprehensive user registration flow with email verification, admin review processes, and approval workflows. Users sign up with business information, verify their email addresses, undergo admin review, and receive approval or rejection notifications. The system includes both user-facing registration pages and administrative interfaces for managing user applications.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Web Framework Architecture
- **Flask Framework**: Core web application using Flask with SQLAlchemy for database operations
- **Template Engine**: Jinja2 templating with Bootstrap 5 for responsive UI components
- **Session Management**: Flask sessions with secure cookie-based authentication
- **Middleware**: ProxyFix middleware for handling proxy headers in deployment environments

### Authentication & Authorization System
- **Password Security**: Werkzeug password hashing for secure credential storage
- **Token-Based Actions**: URLSafeTimedSerializer (itsdangerous) for secure email verification codes and admin action tokens
- **Multi-Role Access**: Separate authentication flows for regular users and administrators with role-based permissions
- **Session Security**: Configurable session secrets with environment variable support

### Database Design
- **SQLAlchemy ORM**: Database abstraction layer with declarative base models
- **User Model**: Comprehensive user data including business information, verification status, and approval workflow states
- **Admin Model**: Administrative users with superadmin capabilities
- **Audit Trail**: Complete action logging system for tracking user status changes and administrative actions
- **Status Workflow**: Multi-stage user status tracking (pending_verification → under_review → approved/rejected)

### Email Communication System
- **SMTP Integration**: Configurable SMTP settings for transactional email delivery
- **Template System**: File-based email templates with variable substitution
- **Verification Workflow**: Time-limited verification codes with automatic expiration
- **Admin Notifications**: Automated notifications to administrators for review queue management
- **User Status Updates**: Approval and rejection email notifications with personalized messaging

### Security Architecture
- **Input Validation**: Email validation using email-validator library with comprehensive form validation
- **Password Requirements**: Configurable password strength requirements
- **Token Expiration**: Time-limited tokens for email verification and admin actions
- **Rate Limiting**: Built-in protection against code resend abuse
- **Environment Variables**: Secure configuration management for sensitive data

## External Dependencies

### Core Framework Dependencies
- **Flask**: Primary web application framework
- **SQLAlchemy**: Database ORM and query builder
- **Werkzeug**: Security utilities for password hashing and request handling

### Email & Communication
- **SMTP Server**: Configurable email delivery (Gmail, custom SMTP servers)
- **email-validator**: Email format validation and domain verification

### Security Libraries
- **itsdangerous**: Cryptographic signing for secure tokens and verification codes
- **python-dotenv**: Environment variable management for configuration

### Frontend Technologies
- **Bootstrap 5**: Responsive CSS framework with dark theme support
- **Font Awesome**: Icon library for user interface elements
- **Custom CSS**: Application-specific styling and branding

### Development & Deployment
- **SQLite**: Default development database (configurable for production databases)
- **Environment Configuration**: Flexible configuration system supporting development and production environments
- **Logging**: Built-in Python logging for debugging and monitoring