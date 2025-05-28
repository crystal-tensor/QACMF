import pytest
import os
from app import app as main_app, db as main_db
from app.models import User, Role, Permission
from app.init_db import create_initial_roles_permissions, create_super_admin # Assuming these can be used

@pytest.fixture(scope='session')
def app():
    """Session-wide test Flask application."""
    # Configure for testing
    main_app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", # Use in-memory SQLite for tests
        "WTF_CSRF_ENABLED": False, # Disable CSRF for simpler form testing in unit tests
        "LOGIN_DISABLED": False, # Ensure login is not globally disabled
        "SERVER_NAME": "localhost.test" # Required for url_for to work without active request context
    })

    with main_app.app_context():
        main_db.create_all() # Create database tables

        # Populate initial roles and permissions
        create_initial_roles_permissions()
        # Create a super_admin user
        create_super_admin() # This uses a fixed username 'crystal-tensor' and password 'changeme'
        
        # Create other test users and assign roles
        # Developer User
        dev_role = Role.query.filter_by(name='developer').first()
        if dev_role:
            dev_user = User(username='testdev', email='dev@example.com')
            dev_user.set_password('testpassword')
            dev_user.roles.append(dev_role)
            main_db.session.add(dev_user)
        
        # Non-Admin User (no specific roles other than potentially a default if implemented)
        # Or a user with a role that lacks specific permissions for testing
        no_perm_user = User(username='testuser', email='user@example.com')
        no_perm_user.set_password('testpassword')
        main_db.session.add(no_perm_user)

        main_db.session.commit()

        yield main_app

        main_db.session.remove()
        main_db.drop_all()

@pytest.fixture(scope='function') # Changed to function scope for client
def client(app):
    """A test client for the app."""
    return app.test_client()

@pytest.fixture(scope='function')
def db(app):
    """Session-wide test database."""
    # The database is already created and populated by the 'app' fixture.
    # This fixture can be used to get a direct db session if needed for more complex manipulations,
    # but often direct client interaction is preferred for integration tests.
    # For function scope, if we need to clean up between tests, we'd do it here.
    # However, with in-memory SQLite, function-scoped app fixture might be better
    # if tests interfere with each other's data. For now, 'app' is session-scoped.
    
    # If we need to ensure a clean state for each test function using the db:
    # with app.app_context():
    #     # Clean up specific tables or reset state as needed before each test
    #     # For example, deleting all users except the initial ones, etc.
    #     # This is complex, so often re-creating the app or db per test (function scope for app fixture)
    #     # is simpler if tests modify data in conflicting ways.
    #     pass

    return main_db

# Fixture to log in a user
@pytest.fixture(scope='function')
def login_user_client(client):
    def _login_user(username, password):
        response = client.post('/login', data=dict(
            username=username,
            password=password
        ), follow_redirects=True)
        assert response.status_code == 200 # Should redirect to profile or index
        return client # Return the client now logged in
    return _login_user

@pytest.fixture(scope='function')
def super_admin_client(login_user_client):
    """A test client logged in as the super_admin user."""
    return login_user_client(username='crystal-tensor', password='changeme')

@pytest.fixture(scope='function')
def developer_client(login_user_client):
    """A test client logged in as the testdev user."""
    return login_user_client(username='testdev', password='testpassword')

@pytest.fixture(scope='function')
def regular_user_client(login_user_client):
    """A test client logged in as testuser (no special permissions)."""
    return login_user_client(username='testuser', password='testpassword')
