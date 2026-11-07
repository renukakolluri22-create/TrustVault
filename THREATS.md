# TrustVault – Security Threats and Protection

## 1. Unauthorized Access

🔴 **THREAT:** A user may try to access another user's private documents.

🟢 **PROTECTION:** TrustVault checks the logged-in user's identity and document ownership or permissions before allowing access.

## 2. Unauthorized Downloads

🔴 **THREAT:** Users may try to download documents without permission.

🟢 **PROTECTION:** The download route checks ownership and sharing permissions before sending a file.

## 3. Unauthorized Document Updates

🔴 **THREAT:** A user with read-only access may try to modify a document.

🟢 **PROTECTION:** Only owners, admins and users with edit permission can update documents.

## 4. Unauthorized Deletion

🔴 **THREAT:** A user may try to delete another user's document.

🟢 **PROTECTION:** The application checks document ownership or admin role before deletion.

## 5. Unauthorized Sharing

🔴 **THREAT:** A user may try to share a document they do not own.

🟢 **PROTECTION:** Only the document owner can grant or revoke sharing permissions.

## 6. Malicious File Uploads

🔴 **THREAT:** Users may upload unsupported file types.

🟢 **PROTECTION:** TrustVault validates file extensions and limits uploads to 10 MB.

## 7. Session and Authentication Risks

🔴 **THREAT:** Unauthenticated users may try to access protected pages.

🟢 **PROTECTION:** Flask-Login protects routes that require authentication.

## 8. Unauthorized Admin Access

🔴 **THREAT:** Owners or viewers may try to access the Admin Dashboard.

🟢 **PROTECTION:** The application checks the user's role on the server before displaying the dashboard.

## 9. Revoked Permissions

🔴 **THREAT:** A user may try to access a document after their permission has been revoked.

🟢 **PROTECTION:** The application checks current permissions before allowing document access.

## 10. Missing Security Records

🔴 **THREAT:** Unauthorized attempts or document activities may go unrecorded.

🟢 **PROTECTION:** TrustVault maintains audit logs for important document activities and refused access attempts.

## Conclusion

TrustVault uses authentication, role-based access control, document-level permissions, file validation and audit logging to improve document security.