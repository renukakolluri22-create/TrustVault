import os
from io import BytesIO
import pytest
from flask import g
os.environ["TRUSTVAULT_DATABASE_URI"] = "sqlite:///:memory:"

from app import app
from models import db, User, Document, DocumentPermission, AuditLog


@pytest.fixture
def client(tmp_path):
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["UPLOAD_FOLDER"] = str(tmp_path)

    with app.app_context():
        db.create_all()

        yield app.test_client(use_cookies=True)

        db.session.remove()
        db.drop_all()


def test_dashboard_requires_login(client):
    response = client.get("/dashboard")
    assert response.status_code == 302


def test_download_requires_login(client):
    response = client.get("/download/1")
    assert response.status_code == 302


def test_user_cannot_download_another_users_private_document(client):
    owner = User(
        name="Owner",
        email="owner@test.com",
        password="test123",
        role="viewer"
    )

    other_user = User(
        name="Other User",
        email="other@test.com",
        password="test123",
        role="viewer"
    )

    db.session.add_all([owner, other_user])
    db.session.commit()

    document = Document(
        filename="private.txt",
        stored_filename="private_file.txt",
        owner_id=owner.id
    )

    db.session.add(document)
    db.session.commit()

    with client.session_transaction() as session:
        session["_user_id"] = str(other_user.id)
        session["_fresh"] = True

    g.pop("_login_user", None)

    response = client.get(f"/download/{document.id}")

    assert response.status_code == 403

def test_revoked_user_cannot_download_document(client):
    owner = User(
        name="Owner",
        email="owner2@test.com",
        password="test123",
        role="viewer"
    )

    shared_user = User(
        name="Shared User",
        email="shared@test.com",
        password="test123",
        role="viewer"
    )

    db.session.add_all([owner, shared_user])
    db.session.commit()

    document = Document(
        filename="shared.txt",
        stored_filename="shared_file.txt",
        owner_id=owner.id
    )

    db.session.add(document)
    db.session.commit()

    with open(
        os.path.join(app.config["UPLOAD_FOLDER"], document.stored_filename),
        "w"
    ) as file:
        file.write("This is a test document.")

    permission = DocumentPermission(
        document_id=document.id,
        user_id=shared_user.id,
        permission="read"
    )

    db.session.add(permission)
    db.session.commit()

    permission_id = permission.id
    document_id = document.id

    # Owner logs in and revokes access
    with client.session_transaction() as session:
        session["_user_id"] = str(owner.id)
        session["_fresh"] = True

    response = client.post(f"/revoke/{permission_id}")

    assert response.status_code == 302
    assert db.session.get(DocumentPermission, permission_id) is None
    assert db.session.get(Document, document_id) is not None

    # Log in as the user whose access was revoked
    with client.session_transaction() as session:
        session["_user_id"] = str(shared_user.id)
        session["_fresh"] = True

    g.pop("_login_user", None)

    response = client.get(f"/download/{document_id}")

    assert response.status_code == 403
def test_owner_can_delete_document_and_audit_is_saved(client):

    owner = User(
        name="Owner",
        email="delete@test.com",
        password="test123",
        role="owner"
    )

    db.session.add(owner)
    db.session.commit()

    document = Document(
        filename="delete_test.txt",
        stored_filename="delete_test_file.txt",
        owner_id=owner.id
    )

    db.session.add(document)
    db.session.commit()

    document_id = document.id

    # Create the physical test file
    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        document.stored_filename
    )

    with open(file_path, "w") as file:
        file.write("Test document")

    # Log in as the owner
    with client.session_transaction() as session:
        session["_user_id"] = str(owner.id)
        session["_fresh"] = True

    g.pop("_login_user", None)

    # Delete the document
    response = client.post(f"/delete/{document_id}")

    assert response.status_code == 302

    # Check database deletion
    assert db.session.get(Document, document_id) is None

    # Check physical file deletion
    assert not os.path.exists(file_path)

    # Check audit log
    audit = AuditLog.query.filter_by(
        action="DELETE"
    ).first()

    assert audit is not None
    assert audit.details == "Document delete_test.txt deleted successfully"
    assert audit.document_id is None
def test_user_cannot_delete_another_users_document(client):

    owner = User(
        name="Owner",
        email="owner_delete@test.com",
        password="test123",
        role="owner"
    )

    other_user = User(
        name="Other User",
        email="other_delete@test.com",
        password="test123",
        role="viewer"
    )

    db.session.add_all([owner, other_user])
    db.session.commit()

    document = Document(
        filename="private.txt",
        stored_filename="private_file.txt",
        owner_id=owner.id
    )

    db.session.add(document)
    db.session.commit()

    document_id = document.id

    # Log in as another user
    with client.session_transaction() as session:
        session["_user_id"] = str(other_user.id)
        session["_fresh"] = True

    g.pop("_login_user", None)

    # Try to delete the owner's document
    response = client.post(f"/delete/{document_id}")

    assert response.status_code == 403

    # Document must still exist
    assert db.session.get(Document, document_id) is not None

    # ACCESS_DENIED must be recorded
    audit = AuditLog.query.filter_by(
        action="ACCESS_DENIED",
        document_id=document_id
    ).first()

    assert audit is not None
def test_unsupported_file_extension_is_rejected():

    assert app.config["MAX_CONTENT_LENGTH"] == 10 * 1024 * 1024

    assert not app.config.get("TESTING", False) is False or True    
def test_unsupported_file_extension_is_rejected(client):

    owner = User(
        name="Owner",
        email="upload_test@test.com",
        password="test123",
        role="owner"
    )

    db.session.add(owner)
    db.session.commit()

    # Log in as owner
    with client.session_transaction() as session:
        session["_user_id"] = str(owner.id)
        session["_fresh"] = True

    g.pop("_login_user", None)

    # Try uploading an unsupported file
    response = client.post(
        "/upload",
        data={
            "document": (
                BytesIO(b"This is a test"),
                "virus.exe"
            )
        },
        content_type="multipart/form-data"
    )

    assert response.status_code == 302

    # Unsupported file must not be saved
    assert Document.query.count() == 0    
def test_file_larger_than_10mb_is_rejected(client):

    owner = User(
        name="Owner",
        email="large_file@test.com",
        password="test123",
        role="owner"
    )

    db.session.add(owner)
    db.session.commit()

    with client.session_transaction() as session:
        session["_user_id"] = str(owner.id)
        session["_fresh"] = True

    g.pop("_login_user", None)

    large_file = BytesIO(b"A" * (10 * 1024 * 1024 + 1))

    response = client.post(
        "/upload",
        data={
            "document": (large_file, "large.txt")
        },
        content_type="multipart/form-data"
    )

    assert response.status_code == 413
    assert Document.query.count() == 0    
def test_viewer_cannot_upload_document(client):

    viewer = User(
        name="Viewer",
        email="viewer_upload@test.com",
        password="test123",
        role="viewer"
    )

    db.session.add(viewer)
    db.session.commit()

    with client.session_transaction() as session:
        session["_user_id"] = str(viewer.id)
        session["_fresh"] = True

    g.pop("_login_user", None)

    response = client.post(
        "/upload",
        data={
            "document": (
                BytesIO(b"Test content"),
                "test.txt"
            )
        },
        content_type="multipart/form-data"
    )

    assert response.status_code == 403
    assert Document.query.count() == 0  
    audit = AuditLog.query.filter_by(
        action="ACCESS_DENIED"
    ).first()

    assert audit is not None
    assert "Unauthorized upload attempt" in audit.details  
def test_viewer_cannot_share_another_users_document(client):

    owner = User(
        name="Owner",
        email="share_owner@test.com",
        password="test123",
        role="owner"
    )

    viewer = User(
        name="Viewer",
        email="share_viewer@test.com",
        password="test123",
        role="viewer"
    )

    recipient = User(
        name="Recipient",
        email="recipient@test.com",
        password="test123",
        role="viewer"
    )

    db.session.add_all([owner, viewer, recipient])
    db.session.commit()

    document = Document(
        filename="private.txt",
        stored_filename="private_share.txt",
        owner_id=owner.id
    )

    db.session.add(document)
    db.session.commit()

    with client.session_transaction() as session:
        session["_user_id"] = str(viewer.id)
        session["_fresh"] = True

    g.pop("_login_user", None)

    response = client.post(
        f"/share/{document.id}",
        data={
            "email": recipient.email,
            "permission": "read"
        }
    )
     
    assert response.status_code == 403

    permission = DocumentPermission.query.filter_by(
        document_id=document.id,
        user_id=recipient.id
    ).first()

    assert permission is None    
    audit = AuditLog.query.filter_by(
        action="ACCESS_DENIED",
        document_id=document.id
    ).first()

    assert audit is not None
    assert "Unauthorized share attempt" in audit.details
def test_edit_permission_user_can_update_document(client):

    owner = User(
        name="Owner",
        email="edit_owner@test.com",
        password="test123",
        role="owner"
    )

    viewer = User(
        name="Viewer",
        email="edit_viewer@test.com",
        password="test123",
        role="viewer"
    )

    db.session.add_all([owner, viewer])
    db.session.commit()

    document = Document(
        filename="old.txt",
        stored_filename="old.txt",
        owner_id=owner.id
    )

    db.session.add(document)
    db.session.commit()

    permission = DocumentPermission(
        document_id=document.id,
        user_id=viewer.id,
        permission="edit"
    )

    db.session.add(permission)
    db.session.commit()

    with client.session_transaction() as session:
        session["_user_id"] = str(viewer.id)
        session["_fresh"] = True

    response = client.post(
        f"/update/{document.id}",
        data={
            "document": (BytesIO(b"Updated content"), "edited.txt")
        },
        content_type="multipart/form-data"
    )

    assert response.status_code == 302

    updated_document = db.session.get(Document, document.id)

    assert updated_document.filename == "edited.txt"

    audit = AuditLog.query.filter_by(
        action="UPDATE",
        document_id=document.id
    ).first()

    assert audit is not None    
def test_read_permission_user_cannot_update_document(client):

    owner = User(
        name="Owner",
        email="read_owner@test.com",
        password="test123",
        role="owner"
    )

    viewer = User(
        name="Viewer",
        email="read_viewer@test.com",
        password="test123",
        role="viewer"
    )

    db.session.add_all([owner, viewer])
    db.session.commit()

    document = Document(
        filename="read_test.txt",
        stored_filename="read_test.txt",
        owner_id=owner.id
    )

    db.session.add(document)
    db.session.commit()

    permission = DocumentPermission(
        document_id=document.id,
        user_id=viewer.id,
        permission="read"
    )

    db.session.add(permission)
    db.session.commit()

    with client.session_transaction() as session:
        session["_user_id"] = str(viewer.id)
        session["_fresh"] = True

    response = client.post(
        f"/update/{document.id}",
        data={}
    )

    assert response.status_code == 403    
def test_user_without_permission_cannot_view_shared_document(client):

    owner = User(
        name="Owner",
        email="view_owner@test.com",
        password="test123",
        role="owner"
    )

    viewer = User(
        name="Viewer",
        email="view_viewer@test.com",
        password="test123",
        role="viewer"
    )

    db.session.add_all([owner, viewer])
    db.session.commit()

    document = Document(
        filename="private.txt",
        stored_filename="private_view.txt",
        owner_id=owner.id
    )

    db.session.add(document)
    db.session.commit()

    with client.session_transaction() as session:
        session["_user_id"] = str(viewer.id)
        session["_fresh"] = True

    response = client.get(f"/download/{document.id}")

    assert response.status_code == 403  
    audit = AuditLog.query.filter_by(
        action="ACCESS_DENIED",
        document_id=document.id
    ).first()

    assert audit is not None
    assert "Unauthorized download attempt" in audit.details 
def test_viewer_cannot_access_admin_dashboard(client):

    viewer = User(
        name="Viewer",
        email="admin_test@test.com",
        password="test123",
        role="viewer"
    )

    db.session.add(viewer)
    db.session.commit()

    with client.session_transaction() as session:
        session["_user_id"] = str(viewer.id)
        session["_fresh"] = True

    response = client.get("/admin-dashboard")

    assert response.status_code == 403    
    audit = AuditLog.query.filter_by(
        action="ACCESS_DENIED"
    ).first()

    assert audit is not None
    assert "Unauthorized admin dashboard access attempt" in audit.details
def test_owner_cannot_access_admin_dashboard(client):

    owner = User(
        name="Owner",
        email="owner_admin_test@test.com",
        password="test123",
        role="owner"
    )

    db.session.add(owner)
    db.session.commit()

    with client.session_transaction() as session:
        session["_user_id"] = str(owner.id)
        session["_fresh"] = True

    response = client.get("/admin-dashboard")

    assert response.status_code == 403 
    audit = AuditLog.query.filter_by(
        action="ACCESS_DENIED"
    ).first()

    assert audit is not None
    assert "Unauthorized admin dashboard access attempt" in audit.details   
def test_admin_can_access_admin_dashboard(client):

    admin = User(
        name="Admin",
        email="admin_access@test.com",
        password="test123",
        role="admin"
    )

    db.session.add(admin)
    db.session.commit()

    with client.session_transaction() as session:
        session["_user_id"] = str(admin.id)
        session["_fresh"] = True
        g.pop("_login_user", None)
    response = client.get("/admin-dashboard")

    assert response.status_code == 200    
def test_user_cannot_revoke_another_users_permission(client):

    owner = User(
        name="Owner",
        email="revoke_owner@test.com",
        password="test123",
        role="owner"
    )

    viewer = User(
        name="Viewer",
        email="revoke_viewer@test.com",
        password="test123",
        role="viewer"
    )

    db.session.add_all([owner, viewer])
    db.session.commit()

    document = Document(
        filename="shared.txt",
        stored_filename="shared_revoke.txt",
        owner_id=owner.id
    )

    db.session.add(document)
    db.session.commit()

    permission = DocumentPermission(
        document_id=document.id,
        user_id=viewer.id,
        permission="read"
    )

    db.session.add(permission)
    db.session.commit()

    with client.session_transaction() as session:
        session["_user_id"] = str(viewer.id)
        session["_fresh"] = True

    response = client.post(f"/revoke/{permission.id}")

    assert response.status_code == 403

    audit = AuditLog.query.filter_by(
        action="ACCESS_DENIED",
        document_id=document.id
    ).first()

    assert audit is not None
    assert "Unauthorized revoke attempt" in audit.details    
