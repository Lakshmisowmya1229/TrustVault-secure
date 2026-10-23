import io
import os
import tempfile
import importlib

# Isolate each test run in a temporary database and file directory.
_tmp = tempfile.TemporaryDirectory()
os.environ["TRUSTVAULT_DB"] = os.path.join(_tmp.name, "test.db")
os.environ["TRUSTVAULT_STORAGE"] = os.path.join(_tmp.name, "files")
os.environ["TRUSTVAULT_SECRET"] = "test-secret-key-at-least-32-characters"
import main
from fastapi.testclient import TestClient

client = TestClient(main.app)
main.init_db()


def token(username, password):
    response = client.post("/token", data={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def auth(t):
    return {"Authorization": f"Bearer {t}"}


def setup_function():
    # App startup seeds development users; TestClient startup runs on initial client use.
    pass


def test_cross_user_cannot_read_download_edit_or_delete():
    owner = token("owner", "Owner-ChangeMe-123!")
    viewer = token("viewer", "Viewer-ChangeMe-123!")
    uploaded = client.post(
        "/documents",
        headers=auth(owner),
        files={"file": ("secret.txt", b"salary details", "text/plain")},
        data={"category": "HR"},
    )
    assert uploaded.status_code == 200, uploaded.text
    doc_id = uploaded.json()["id"]

    assert client.get(f"/documents/{doc_id}", headers=auth(viewer)).status_code == 404
    assert client.get(f"/documents/{doc_id}/download", headers=auth(viewer)).status_code == 404
    assert client.patch(f"/documents/{doc_id}", headers=auth(viewer),
                        json={"category": "Changed"}).status_code == 404
    assert client.delete(f"/documents/{doc_id}", headers=auth(viewer)).status_code == 404


def test_grant_then_revoke_takes_effect():
    owner = token("owner", "Owner-ChangeMe-123!")
    viewer = token("viewer", "Viewer-ChangeMe-123!")
    uploaded = client.post(
        "/documents", headers=auth(owner),
        files={"file": ("contract.txt", b"confidential", "text/plain")},
        data={"category": "Contracts"},
    )
    doc_id = uploaded.json()["id"]

    grant = client.post(f"/documents/{doc_id}/grants", headers=auth(owner),
                        json={"username": "viewer", "permission": "read"})
    assert grant.status_code == 200
    assert client.get(f"/documents/{doc_id}/download", headers=auth(viewer)).status_code == 200

    revoked = client.delete(f"/documents/{doc_id}/grants/viewer", headers=auth(owner))
    assert revoked.status_code == 200
    assert client.get(f"/documents/{doc_id}/download", headers=auth(viewer)).status_code == 404


def test_viewer_cannot_grant_access_or_view_admin_audit():
    viewer = token("viewer", "Viewer-ChangeMe-123!")
    assert client.get("/admin/audit", headers=auth(viewer)).status_code == 403


def test_disallowed_file_extension_is_rejected():
    owner = token("owner", "Owner-ChangeMe-123!")
    response = client.post(
        "/documents", headers=auth(owner),
        files={"file": ("malware.exe", b"nope", "application/octet-stream")},
        data={"category": "General"},
    )
    assert response.status_code == 400
