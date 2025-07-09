import pytest
from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_home_route_redirects_to_login(client):
    """Ensure /home redirects to login when not authenticated."""
    response = client.get('/home', follow_redirects=False)
    assert response.status_code == 302  # Redirect
    assert '/login' in response.headers['Location']

def test_register_missing_fields(client):
    response = client.post('/register', data={
        'name': '',
        'email': '',
        'password': '',
        'confirm_password': ''
    }, follow_redirects=True)
    assert b"All fields are required" in response.data

def test_register_password_mismatch(client):
    response = client.post('/register', data={
        'name': 'Test User',
        'email': 'test@example.com',
        'password': 'password123',
        'confirm_password': 'password321'
    }, follow_redirects=True)
    assert b"Passwords do not match" in response.data