import pytest
from flask import url_for, session
from app.models import User

def test_register_success(client, app):
    """Test successful user registration."""
    response = client.post(url_for('register'), data={
        'username': 'newuser',
        'email': 'newuser@example.com',
        'password': 'newpassword'
    }, follow_redirects=True)
    assert response.status_code == 200 # Should redirect to profile
    assert b'User Profile' in response.data # Check if profile page is loaded
    with app.app_context():
        user = User.query.filter_by(username='newuser').first()
        assert user is not None
        assert user.email == 'newuser@example.com'

def test_register_duplicate_username(client, app):
    """Test registration with a duplicate username."""
    # First, create a user that will cause the duplicate
    with app.app_context():
        existing_user = User(username='existinguser', email='exists@example.com')
        existing_user.set_password('password')
        from app import db
        db.session.add(existing_user)
        db.session.commit()

    response = client.post(url_for('register'), data={
        'username': 'existinguser',
        'email': 'newemail@example.com',
        'password': 'password'
    }, follow_redirects=True)
    assert response.status_code == 200 # Stays on register page or redirects with flash
    assert b'Username already taken' in response.data
    with app.app_context():
        assert User.query.filter_by(email='newemail@example.com').first() is None

def test_register_duplicate_email(client, app):
    """Test registration with a duplicate email."""
    with app.app_context(): # Ensure user exists for duplicate email check
        user = User.query.filter_by(username='testdev').first() # from conftest
        assert user is not None
        
    response = client.post(url_for('register'), data={
        'username': 'anotheruser',
        'email': 'dev@example.com', # Duplicate of testdev's email
        'password': 'password'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Email address already registered' in response.data
    with app.app_context():
        assert User.query.filter_by(username='anotheruser').first() is None

def test_login_success(client, app):
    """Test successful login."""
    # Uses 'testuser' created in conftest.py
    response = client.post(url_for('login'), data={
        'username': 'testuser',
        'password': 'testpassword'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'User Profile' in response.data # Should redirect to profile
    assert b'Welcome back, testuser!' in response.data # Flash message
    with client: # Use client as context manager to access session
        assert session.get('_user_id') == str(User.query.filter_by(username='testuser').first().id)

def test_login_incorrect_password(client):
    """Test login with an incorrect password."""
    response = client.post(url_for('login'), data={
        'username': 'testuser',
        'password': 'wrongpassword'
    }, follow_redirects=True)
    assert response.status_code == 200 # Stays on login page
    assert b'Invalid username or password' in response.data
    with client:
        assert '_user_id' not in session

def test_login_nonexistent_user(client):
    """Test login with a non-existent username."""
    response = client.post(url_for('login'), data={
        'username': 'nouser',
        'password': 'password'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Invalid username or password' in response.data
    with client:
        assert '_user_id' not in session

def test_logout(developer_client, app): # Using developer_client fixture which logs in a user
    """Test logout functionality."""
    # developer_client is already logged in
    with developer_client:
        response = developer_client.get(url_for('logout'), follow_redirects=True)
        assert response.status_code == 200
        assert b'You have been logged out.' in response.data
        assert b'Welcome to the QACMF Admin Interface' in response.data # Back to index
        assert '_user_id' not in session

def test_profile_access_without_login(client):
    """Test accessing @login_required route /profile without login."""
    response = client.get(url_for('profile'), follow_redirects=True)
    assert response.status_code == 200 # Redirects to login
    assert b'Sign In' in response.data # Login page content
    assert b'Please log in to access this page.' in response.data # Flash message

def test_profile_access_with_login(developer_client): # developer_client is already logged in
    """Test accessing @login_required route /profile with login."""
    response = developer_client.get(url_for('profile'))
    assert response.status_code == 200
    assert b'User Profile' in response.data
    assert b'Username: testdev' in response.data
