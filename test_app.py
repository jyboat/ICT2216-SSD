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