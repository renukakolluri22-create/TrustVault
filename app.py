
import os
import uuid
import click
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, abort, send_from_directory
)
from sqlalchemy import or_

from flask_login import (
    LoginManager, login_user, login_required,
    logout_user, current_user
)

from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from models import db, User, Document, DocumentPermission, DocumentVersion, AuditLog
from config import Config


app = Flask(__name__)
app.config.from_object(Config)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "uploads")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

db.init_app(app)
csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "txt"}


def allowed_file(filename):
    if not filename:
        return False

    if "." not in filename:
        return False

    extension = filename.rsplit(".", 1)[1].lower()

    return extension in ALLOWED_EXTENSIONS
def log_activity(action, document=None, details=None):
    log = AuditLog(
    user_id=current_user.id if current_user.is_authenticated else None,
    document_id=document.id if document else None,
    document_name=document.filename if document else None,
    action=action,
    details=details
)

    db.session.add(log)
    db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "")

        if not name or not email or not password:
            flash("Please fill in all fields.")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must contain at least 8 characters.")
            return redirect(url_for("register"))

        if role not in ["owner", "viewer"]:
            flash("Invalid user role.")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("This email is already registered.")
            return redirect(url_for("register"))

        new_user = User(
            name=name,
            email=email,
            password=generate_password_hash(password),
            role=role
        )

        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful. Please log in.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash("Welcome to TrustVault!")

            if user.role == "admin":
                return redirect(url_for("admin_dashboard"))
            else:
                return redirect(url_for("dashboard"))

        flash("Invalid email or password.")

    return render_template("login.html")




@app.route("/dashboard")
@login_required
def dashboard():

    search = request.args.get("search", "").strip()
    category = request.args.get("category", "").strip()
    owner_search = request.args.get("owner_search", "").strip()
    upload_date = request.args.get("upload_date", "").strip()
    print("Selected upload date:", upload_date)
    documents_query = Document.query.filter_by(
        owner_id=current_user.id
    )

    shared_query = (
        Document.query
        .join(
            DocumentPermission,
            Document.id == DocumentPermission.document_id
        )
        .filter(
            DocumentPermission.user_id == current_user.id
        )
    )

    # Search by document name
    if search:
        documents_query = documents_query.filter(
            Document.filename.ilike(f"%{search}%")
        )

        shared_query = shared_query.filter(
            Document.filename.ilike(f"%{search}%")
        )

    # Search by category
    if category:
        documents_query = documents_query.filter(
            Document.category == category
        )

        shared_query = shared_query.filter(
            Document.category == category
        )
        # Search by document owner
    if owner_search:
        documents_query = documents_query.join(
            User, Document.owner_id == User.id
        ).filter(
            User.name.ilike(f"%{owner_search}%")
        )

        shared_query = shared_query.join(
            User, Document.owner_id == User.id
        ).filter(
            User.name.ilike(f"%{owner_search}%")
        )    
        if upload_date:
            try:
                selected_date = datetime.strptime(
                    upload_date, "%Y-%m-%d"
                ).date()

                start_date = datetime.combine(
                    selected_date, datetime.min.time()
                )

                end_date = start_date + timedelta(days=1)

                documents_query = documents_query.filter(
                    Document.uploaded_at >= start_date,
                    Document.uploaded_at < end_date
                )

                shared_query = shared_query.filter(
                    Document.uploaded_at >= start_date,
                    Document.uploaded_at < end_date
                )

            except ValueError:
                flash("Invalid date format. Please select a valid date.")
                upload_date = ""

    documents = documents_query.order_by(
        Document.uploaded_at.desc()
    ).all()

    shared_documents = shared_query.order_by(
        Document.uploaded_at.desc()
    ).all()

    return render_template(
        "dashboard.html",
        documents=documents,
        shared_documents=shared_documents,
        search=search,
        category=category,
        owner_search=owner_search,
        upload_date=upload_date
    )
@app.route("/admin-dashboard")
@login_required
def admin_dashboard():

    if current_user.role != "admin":
        log_activity(
            "ACCESS_DENIED",
            None,
            f"Unauthorized admin dashboard access attempt by {current_user.email}"
        )
        abort(403)

    users = User.query.order_by(User.id.desc()).all()

    documents = Document.query.order_by(
        Document.uploaded_at.desc()
    ).all()

    permissions = DocumentPermission.query.all()

    audit_logs = AuditLog.query.order_by(
        AuditLog.timestamp.desc()
    ).all()

    return render_template(
        "admin_dashboard.html",
        users=users,
        documents=documents,
        permissions=permissions,
        audit_logs=audit_logs
    )
@app.route("/upload", methods=["POST"])
@login_required
def upload_document():

    if current_user.role not in ["owner", "admin"]:
        log_activity(
            "ACCESS_DENIED",
            None,
            f"Unauthorized upload attempt by {current_user.email}"
        )
        abort(403)

    uploaded_file = request.files.get("document")

    if not uploaded_file or uploaded_file.filename == "":
        flash("Please select a document.")
        return redirect(url_for("dashboard"))

    original_filename = secure_filename(uploaded_file.filename)

    if not original_filename or not allowed_file(original_filename):
        flash("Only PDF, DOC, DOCX and TXT files are allowed.")
        return redirect(url_for("dashboard"))

    category = request.form.get("category", "").strip()

    if not category:
        category = "Uncategorized"

    if len(category) > 100:
        flash("Category must not exceed 100 characters.")
        return redirect(url_for("dashboard"))

    stored_filename = str(uuid.uuid4()) + os.path.splitext(original_filename)[1].lower()

    uploaded_file.save(
        os.path.join(app.config["UPLOAD_FOLDER"], stored_filename)
    )

    document = Document(
        filename=original_filename,
        stored_filename=stored_filename,
        owner_id=current_user.id,
        category=category
    )

    db.session.add(document)
    db.session.commit()

    log_activity(
        "UPLOAD",
        document,
        "Document uploaded successfully"
    )

    flash("Document uploaded successfully!")
    return redirect(url_for("dashboard"))

@app.route("/download/<int:document_id>")
@login_required
def download_document(document_id):

    document = db.session.get(Document, document_id)

    if document is None:
        abort(404)

    # Allow only the owner or admin directly
    if document.owner_id != current_user.id and current_user.role != "admin":

        permission = DocumentPermission.query.filter_by(
            document_id=document.id,
            user_id=current_user.id
        ).first()

        # Deny access if the user has no sharing permission
        if permission is None:
            log_activity(
                "ACCESS_DENIED",
                document,
                "Unauthorized download attempt"
            )
            abort(403)

    log_activity(
        "DOWNLOAD",
        document,
        "Document downloaded successfully"
    )

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        document.stored_filename,
        as_attachment=True,
        download_name=document.filename
    )


@app.route("/update/<int:document_id>", methods=["POST"])
@login_required
def update_document(document_id):

    document = db.session.get(Document, document_id)

    if document is None:
        log_activity(
            "ACCESS_DENIED",
            None,
            f"User {current_user.email} tried to update missing document {document_id}"
        )
        abort(404)

    # Check whether user is Owner or Admin
    if document.owner_id == current_user.id or current_user.role == "admin":
        pass
    else:
        permission = DocumentPermission.query.filter_by(
            document_id=document.id,
            user_id=current_user.id
        ).first()

        if permission is None or permission.permission != "edit":
            log_activity(
                "ACCESS_DENIED",
                document,
                f"Unauthorized update attempt by {current_user.email}"
            )
            abort(403)

    uploaded_file = request.files.get("document")

    if not uploaded_file or uploaded_file.filename == "":
        flash("Please select an updated document.")
        return redirect(url_for("dashboard"))

    original_filename = secure_filename(uploaded_file.filename)

    if not original_filename or not allowed_file(original_filename):
        flash("Only PDF, DOC, DOCX and TXT files are allowed.")
        return redirect(url_for("dashboard"))

    # Save the previous version in history
    old_version = DocumentVersion(
        document_id=document.id,
        updated_by=current_user.id,
        stored_filename=document.stored_filename
    )

    db.session.add(old_version)

    # Save the updated file separately
    new_stored_filename = (
        str(uuid.uuid4()) +
        os.path.splitext(original_filename)[1].lower()
    )

    uploaded_file.save(
        os.path.join(
            app.config["UPLOAD_FOLDER"],
            new_stored_filename
        )
    )

    document.stored_filename = new_stored_filename
    document.filename = original_filename

    db.session.commit()

    log_activity(
        "UPDATE",
        document,
        "Document updated successfully"
    )

    flash("Document updated successfully!")

    return redirect(url_for("dashboard"))

@app.route("/delete/<int:document_id>", methods=["POST"])
@login_required
def delete_document(document_id):

    document = db.session.get(Document, document_id)

    if document is None:
        log_activity(
            "ACCESS_DENIED",
            None,
            f"User {current_user.email} tried to delete missing document {document_id}"
        )
        abort(404)

    # Only Owner or Admin can delete
    if document.owner_id != current_user.id and current_user.role != "admin":
        log_activity(
            "ACCESS_DENIED",
            document,
            f"Unauthorized delete attempt by {current_user.email}"
        )
        abort(403)

    filename = document.filename
    stored_filename = document.stored_filename

    # Record deletion in audit activity
    log_activity(
        "DELETE",
        document,
        f"Document {filename} deleted successfully"
    )

    # Delete sharing permission records
    DocumentPermission.query.filter_by(
        document_id=document.id
    ).delete(synchronize_session=False)

    # Delete document version history
    DocumentVersion.query.filter_by(
        document_id=document.id
    ).delete(synchronize_session=False)

    # Preserve audit records but disconnect them from deleted document
    AuditLog.query.filter_by(
        document_id=document.id
    ).update(
        {AuditLog.document_id: None},
        synchronize_session=False
    )

    # Delete document from database
    db.session.delete(document)
    db.session.commit()

    # Delete physical file after database commit
    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        stored_filename
    )

    if os.path.exists(file_path):
        os.remove(file_path)

    flash("Document deleted successfully!")

    return redirect(url_for("dashboard"))

@app.route("/share/<int:document_id>", methods=["POST"])
@login_required
def share_document(document_id):

    document = db.session.get(Document, document_id)

    if document is None:
        abort(404)

    if document.owner_id != current_user.id:
        log_activity(
            "ACCESS_DENIED",
            document,
            f"Unauthorized share attempt by {current_user.email}"
        )
        abort(403)

    email = request.form.get("email", "").strip().lower()
    permission_type = request.form.get("permission", "")

    if permission_type not in ["read", "edit"]:
        flash("Invalid permission selected.")
        return redirect(url_for("dashboard"))

    user = User.query.filter_by(email=email).first()

    if user is None:
        flash("This user is not registered.")
        return redirect(url_for("dashboard"))

    if user.id == current_user.id:
        flash("You cannot share a document with yourself.")
        return redirect(url_for("dashboard"))

    existing_permission = DocumentPermission.query.filter_by(
        document_id=document.id,
        user_id=user.id
    ).first()

    if existing_permission:
        existing_permission.permission = permission_type
        flash("User permission updated successfully.")
    else:
        new_permission = DocumentPermission(
            document_id=document.id,
            user_id=user.id,
            permission=permission_type
        )
        db.session.add(new_permission)
        flash("Document shared successfully.")

    db.session.commit()

    log_activity(
        "SHARE",
        document,
        f"Shared with {user.email} using {permission_type} permission"
    )

    return redirect(url_for("dashboard"))


@app.route("/revoke/<int:permission_id>", methods=["POST"])
@login_required
def revoke_permission(permission_id):

    permission = db.session.get(
        DocumentPermission, permission_id
    )

    if permission is None:
        abort(404)

    if permission.document.owner_id != current_user.id:
        log_activity(
            "ACCESS_DENIED",
            permission.document,
            f"Unauthorized revoke attempt by {current_user.email}"
        )
        abort(403)

    document = permission.document
    shared_user_email = permission.user.email

    db.session.delete(permission)
    db.session.commit()

    log_activity(
        "REVOKE",
        document,
        f"Access revoked for {shared_user_email}"
    )
    flash("Document access revoked successfully.")
    return redirect(url_for("dashboard"))


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("You have logged out successfully.")
    return redirect(url_for("login"))


@app.cli.command("create-admin")
def create_admin():

    email = click.prompt("Enter administrator email").strip().lower()
    name = click.prompt("Enter administrator name")
    password = click.prompt(
        "Enter administrator password",
        hide_input=True
    )

    if len(password) < 8:
        click.echo("Password must contain at least 8 characters.")
        return

    if User.query.filter_by(email=email).first():
        click.echo("This email is already registered.")
        return

    admin = User(
        name=name,
        email=email,
        password=generate_password_hash(password),
        role="admin"
    )

    db.session.add(admin)
    db.session.commit()

    click.echo("Administrator account created successfully!")


@app.errorhandler(413)
def file_too_large(error):
    return "File is too large. Maximum size is 10 MB.", 413


if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(debug=False)