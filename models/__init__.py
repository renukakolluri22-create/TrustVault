
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="viewer")

    def __repr__(self):
        return self.email


class Document(db.Model):
    __tablename__ = "documents"

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), unique=True, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    category = db.Column(db.String(100), nullable=True)

    owner = db.relationship("User", backref="documents")



class DocumentPermission(db.Model):
    __tablename__ = "document_permissions"

    id = db.Column(db.Integer, primary_key=True)

    document_id = db.Column(
        db.Integer,
        db.ForeignKey("documents.id"),
        nullable=False
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )

    permission = db.Column(
        db.String(10),
        nullable=False
    )

    granted_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    __table_args__ = (
        db.UniqueConstraint(
            "document_id",
            "user_id",
            name="unique_document_user_permission"
        ),
    )

    document = db.relationship(
        "Document",
        backref="permissions"
    )

    user = db.relationship(
        "User",
        backref="shared_permissions"
    )

class DocumentVersion(db.Model):
    __tablename__ = "document_versions"

    id = db.Column(db.Integer, primary_key=True)

    document_id = db.Column(
        db.Integer,
        db.ForeignKey("documents.id"),
        nullable=False
    )

    updated_by = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )

    stored_filename = db.Column(
        db.String(255),
        nullable=False
    )
    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )
    document = db.relationship("Document", backref="versions")
    user = db.relationship("User")
class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=True
    )

    document_id = db.Column(
        db.Integer,
        db.ForeignKey("documents.id"),
        nullable=True
    )
    document_name = db.Column(db.String(255), nullable=True)
    action = db.Column(db.String(50), nullable=False)

    details = db.Column(db.String(255))

    timestamp = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    user = db.relationship("User")
    document = db.relationship("Document")    