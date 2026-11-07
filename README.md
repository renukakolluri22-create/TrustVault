# TrustVault – Secure Document Sharing System

## About the Project

TrustVault is a secure document management and sharing web application developed using Python Flask. It allows users to upload, organise, search, download, update and securely share documents.

The application uses role-based access control and document-level permissions to protect private files.

## Technologies Used

- Python
- Flask
- Flask-SQLAlchemy
- Flask-Login
- Flask-WTF
- SQLite
- HTML
- CSS
- JavaScript
- Pytest

## User Roles

- **Admin:** Can access the administration dashboard and manage application-level information.
- **Owner:** Can upload, manage, update, delete and share their documents.
- **Viewer:** Can access documents shared with them according to their assigned permissions.

## Main Features

1. User registration and login.
2. Role-based access control.
3. Document upload and download.
4. Document categories.
5. Document search and filtering.
6. Read and edit permissions.
7. Secure document sharing and permission revocation.
8. Document version history.
9. Audit logs for document activities.
10. Admin dashboard.
11. File type and file size validation.
12. Security testing using Pytest.

## Installation

1. Clone or download the project.
2. Open the project folder in VS Code.
3. Open the terminal.
4. Install the required packages:

```bash
py -m pip install -r requirements.txt
```

## Run the Application

Run the following command from the TrustVault project folder:

```bash
py app.py
```

Open the local Flask address shown in the terminal in your browser.

## Run Automated Tests

Run all tests using:

```bash
py -m pytest -v
```

## Security Testing

The project includes automated tests for authentication, document permissions, unauthorized access, file validation and admin dashboard access.

**Latest test result:** 16 tests passed.

## Project Goal

The goal of TrustVault is to provide a secure and simple platform for document management, controlled sharing and activity tracking.