from app import app


def test_dashboard_requires_login():
    app.config["TESTING"] = True

    with app.test_client() as client:
        response = client.get("/dashboard")

        assert response.status_code == 302