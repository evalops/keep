import pytest

from app.main import app


@pytest.fixture
def client():
    """Create a test client for the Flask app."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_health_endpoint(client):
    """Test the health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200

    json_data = response.get_json()
    assert json_data is not None
    assert json_data["status"] == "ok"


def test_index_endpoint_without_headers(client):
    """Test the index endpoint without client headers."""
    response = client.get("/")
    assert response.status_code == 200

    text = response.get_data(as_text=True)
    assert "Hello from keep protected app!" in text
    assert "Client cert subject: unknown" in text
    assert "Device ID: unknown" in text


def test_index_endpoint_with_client_subject(client):
    """Test the index endpoint with X-Client-Subject header."""
    headers = {"X-Client-Subject": "Subject=CN=user@example.com,O=Company"}
    response = client.get("/", headers=headers)
    assert response.status_code == 200

    text = response.get_data(as_text=True)
    assert "Client cert subject: CN=user@example.com,O=Company" in text


def test_index_endpoint_with_device_id(client):
    """Test the index endpoint with X-Device-ID header."""
    headers = {"X-Device-ID": "laptop-001"}
    response = client.get("/", headers=headers)
    assert response.status_code == 200

    text = response.get_data(as_text=True)
    assert "Device ID: laptop-001" in text


def test_index_endpoint_with_all_headers(client):
    """Test the index endpoint with all client headers."""
    headers = {
        "X-Client-Subject": "Subject=CN=admin@company.com,O=Company,OU=IT",
        "X-Device-ID": "workstation-123",
    }
    response = client.get("/", headers=headers)
    assert response.status_code == 200

    text = response.get_data(as_text=True)
    assert "Hello from keep protected app!" in text
    assert "Client cert subject: CN=admin@company.com,O=Company,OU=IT" in text
    assert "Device ID: workstation-123" in text


def test_step_up_endpoint(client):
    """Test the step-up authentication endpoint."""
    response = client.post("/step-up")
    assert response.status_code == 202

    json_data = response.get_json()
    assert json_data is not None
    assert json_data["status"] == "step-up required"


def test_step_up_endpoint_wrong_method(client):
    """Test step-up endpoint rejects non-POST methods."""
    response = client.get("/step-up")
    assert response.status_code == 405  # Method Not Allowed


def test_nonexistent_endpoint(client):
    """Test that non-existent endpoints return 404."""
    response = client.get("/nonexistent")
    assert response.status_code == 404


def test_client_subject_prefix_removal(client):
    """Test that Subject= prefix is properly removed from client subject."""
    headers = {"X-Client-Subject": "Subject=CN=test@example.com"}
    response = client.get("/", headers=headers)
    assert response.status_code == 200

    text = response.get_data(as_text=True)
    # Should not contain the "Subject=" prefix
    assert "Client cert subject: CN=test@example.com" in text
    assert "Subject=CN=test@example.com" not in text


def test_client_subject_without_prefix(client):
    """Test client subject header without Subject= prefix."""
    headers = {"X-Client-Subject": "CN=test@example.com"}
    response = client.get("/", headers=headers)
    assert response.status_code == 200

    text = response.get_data(as_text=True)
    assert "Client cert subject: CN=test@example.com" in text


def test_empty_headers(client):
    """Test behavior with empty but present headers."""
    headers = {"X-Client-Subject": "", "X-Device-ID": ""}
    response = client.get("/", headers=headers)
    assert response.status_code == 200

    text = response.get_data(as_text=True)
    # Empty headers should fall back to "unknown"
    assert "Client cert subject: unknown" in text
    assert "Device ID: unknown" in text
