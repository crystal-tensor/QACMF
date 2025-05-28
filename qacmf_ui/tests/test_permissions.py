import pytest
from flask import url_for

# Example routes from the application to test permissions
# These might need to be adjusted if the actual routes are different
# or if specific setup is needed for them to be accessible.

# For @permission_required('submit_algorithms')
# Assuming '/algorithms/submit' is the route for submitting algorithms (GET for the form page)
SUBMIT_ALGORITHM_URL = '/algorithms/submit' 
# An actual route that uses @permission_required('submit_algorithms') from routes.py
# is '/algorithms/submit'. The other example route '/submit_algorithm' was removed.

# For @role_required('super_admin')
# Assuming '/admin/users' is a route only accessible to super_admins
ADMIN_USERS_URL = '/admin/users'

def test_access_submit_algorithm_with_permission(developer_client):
    """
    Test accessing the algorithm submission page (GET request)
    with a user who has 'submit_algorithms' permission (developer_client).
    """
    response = developer_client.get(SUBMIT_ALGORITHM_URL)
    assert response.status_code == 200 # Expect to see the submission form
    assert b"Submit New Algorithm" in response.data

def test_access_submit_algorithm_without_permission(regular_user_client):
    """
    Test accessing the algorithm submission page (GET request)
    with a user who does NOT have 'submit_algorithms' permission (regular_user_client).
    The 'testuser' (regular_user_client) from conftest.py does not have this permission.
    """
    response = regular_user_client.get(SUBMIT_ALGORITHM_URL)
    assert response.status_code == 403 # Expect Forbidden

def test_access_admin_users_with_super_admin_role(super_admin_client):
    """
    Test accessing an admin page with a user who has 'super_admin' role.
    """
    response = super_admin_client.get(ADMIN_USERS_URL)
    assert response.status_code == 200 # Expect to see the admin users list
    assert b"Manage Users" in response.data

def test_access_admin_users_without_super_admin_role(developer_client):
    """
    Test accessing an admin page with a user who does NOT have 'super_admin' role.
    (e.g., a developer).
    """
    response = developer_client.get(ADMIN_USERS_URL)
    assert response.status_code == 403 # Expect Forbidden

def test_access_admin_users_with_regular_user(regular_user_client):
    """
    Test accessing an admin page with a regular user.
    """
    response = regular_user_client.get(ADMIN_USERS_URL)
    assert response.status_code == 403 # Expect Forbidden

# You can add more tests here for other permissions and roles if needed.
# For example, testing the 'approve_algorithms' permission for the '/admin/algorithms/list' route.

MANAGE_ALGORITHMS_URL = '/admin/algorithms/list'

def test_access_manage_algorithms_with_permission(super_admin_client, app):
    """
    Test accessing algorithm management with a user who has 'approve_algorithms' permission.
    The 'super_admin' role (created in conftest.py via init_db) has this permission.
    """
    response = super_admin_client.get(MANAGE_ALGORITHMS_URL)
    assert response.status_code == 200
    assert b"Manage Submitted Algorithms" in response.data

def test_access_manage_algorithms_without_permission(developer_client, app):
    """
    Test accessing algorithm management with a user who lacks 'approve_algorithms' permission.
    The 'developer' role (created in conftest.py via init_db) does not have this permission.
    """
    response = developer_client.get(MANAGE_ALGORITHMS_URL)
    assert response.status_code == 403
