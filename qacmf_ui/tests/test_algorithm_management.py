import pytest
from flask import url_for, current_app
from app.models import SubmittedAlgorithm, DeployedAlgorithm, User
import os
from werkzeug.utils import secure_filename

@pytest.fixture
def setup_submitted_algorithm(db, app):
    """Fixture to create a sample submitted algorithm for testing management actions."""
    with app.app_context():
        developer = User.query.filter_by(username='testdev').first()
        if not developer: # Should exist from conftest
            developer = User(username='testdev_mgm', email='dev_mgm@example.com')
            developer.set_password('password')
            db.session.add(developer)
            db.session.commit()

        algorithm = SubmittedAlgorithm(
            name="Test Algo for Management",
            description="An algorithm to test approval and deployment.",
            version="1.0.0",
            developer_id=developer.id,
            config_file_content="config content",
            api_spec_content="api spec content",
            plugin_file_content=b"plugin binary content",
            plugin_filename="plugin_test.py",
            status="pending_review"
        )
        db.session.add(algorithm)
        db.session.commit()
        return algorithm

def test_list_algorithms_as_super_admin(super_admin_client, setup_submitted_algorithm):
    """Test accessing the list of submitted algorithms as super_admin."""
    response = super_admin_client.get(url_for('admin_list_algorithms'))
    assert response.status_code == 200
    assert b"Manage Submitted Algorithms" in response.data
    assert b"Test Algo for Management" in response.data # Check if our test algo is listed

def test_approve_algorithm(super_admin_client, setup_submitted_algorithm, app):
    """Test approving a submitted algorithm."""
    algorithm_id = setup_submitted_algorithm.id
    
    # Mock the directory creation and file writing
    # This part can be tricky if current_app.root_path is not what's expected during tests
    # For now, assume the path logic in the route is correct and focus on DB state
    # and that the 'qacmf_ui/approved_plugins' directory exists relative to the app's root
    
    # Construct the expected path for cleanup if file is created
    # approved_plugins_dir = os.path.join(current_app.root_path, '..', 'approved_plugins')
    # if not os.path.exists(approved_plugins_dir):
    #     os.makedirs(approved_plugins_dir)
    # expected_plugin_path = os.path.join(approved_plugins_dir, secure_filename(setup_submitted_algorithm.plugin_filename))


    response = super_admin_client.post(url_for('admin_set_algorithm_status', algorithm_id=algorithm_id), data={
        'status': 'approved'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'Algorithm "Test Algo for Management" approved and plugin file saved.' in response.data

    with app.app_context():
        updated_algorithm = SubmittedAlgorithm.query.get(algorithm_id)
        assert updated_algorithm.status == 'approved'
        assert updated_algorithm.approved_plugin_path is not None
        # Check if the file was "saved" (mocked or actually, depending on test setup)
        # For now, just check the DB field.
        # If actual file saving is tested, ensure cleanup:
        # if os.path.exists(expected_plugin_path):
        #     os.remove(expected_plugin_path)
        
        # Verify the path stored is relative as implemented
        assert updated_algorithm.approved_plugin_path == os.path.join('approved_plugins', secure_filename(setup_submitted_algorithm.plugin_filename))


def test_reject_algorithm(super_admin_client, setup_submitted_algorithm, app):
    """Test rejecting a submitted algorithm."""
    algorithm_id = setup_submitted_algorithm.id
    response = super_admin_client.post(url_for('admin_set_algorithm_status', algorithm_id=algorithm_id), data={
        'status': 'rejected'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'Algorithm "Test Algo for Management" has been rejected.' in response.data

    with app.app_context():
        updated_algorithm = SubmittedAlgorithm.query.get(algorithm_id)
        assert updated_algorithm.status == 'rejected'
        assert updated_algorithm.approved_plugin_path is None

def test_deploy_approved_algorithm(super_admin_client, setup_submitted_algorithm, app):
    """Test deploying an approved algorithm."""
    algorithm_id = setup_submitted_algorithm.id
    # First, approve the algorithm
    with app.app_context():
        alg = SubmittedAlgorithm.query.get(algorithm_id)
        alg.status = 'approved'
        # Simulate file saving from approval step for this test
        alg.approved_plugin_path = os.path.join('approved_plugins', secure_filename(alg.plugin_filename))
        db.session.commit()

    response = super_admin_client.post(url_for('admin_deploy_algorithm', algorithm_id=algorithm_id), data={
        'business_context': 'Test Deployment Context',
        'config_override': '{"new_param": "override_value"}'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'Algorithm "Test Algo for Management" (v1.0.0) has been marked for deployment.' in response.data

    with app.app_context():
        deployment = DeployedAlgorithm.query.filter_by(submitted_algorithm_id=algorithm_id).first()
        assert deployment is not None
        assert deployment.business_context == 'Test Deployment Context'
        assert deployment.config_override == '{"new_param": "override_value"}'
        assert deployment.status == 'active'

def test_deploy_algorithm_not_approved(super_admin_client, setup_submitted_algorithm, app):
    """Test deploying an algorithm that is not yet approved."""
    algorithm_id = setup_submitted_algorithm.id # Status is 'pending_review' by default
    response = super_admin_client.post(url_for('admin_deploy_algorithm', algorithm_id=algorithm_id), data={
        'business_context': 'Test Deployment Context'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'Algorithm "Test Algo for Management" must be approved before it can be deployed.' in response.data
    with app.app_context():
        assert DeployedAlgorithm.query.filter_by(submitted_algorithm_id=algorithm_id).first() is None

def test_deploy_algorithm_approved_no_path(super_admin_client, setup_submitted_algorithm, app):
    """Test deploying an algorithm that is approved but has no plugin path (should not happen in normal flow)."""
    algorithm_id = setup_submitted_algorithm.id
    with app.app_context():
        alg = SubmittedAlgorithm.query.get(algorithm_id)
        alg.status = 'approved'
        alg.approved_plugin_path = None # Explicitly set to None for this test case
        db.session.commit()

    response = super_admin_client.post(url_for('admin_deploy_algorithm', algorithm_id=algorithm_id), data={}, follow_redirects=True)
    assert response.status_code == 200
    assert b'Approved plugin path not found for algorithm "Test Algo for Management". Cannot deploy.' in response.data
    with app.app_context():
        assert DeployedAlgorithm.query.filter_by(submitted_algorithm_id=algorithm_id).first() is None

def test_list_deployed_algorithms(super_admin_client, setup_submitted_algorithm, app):
    """Test viewing the list of deployed algorithms."""
    # First, approve and deploy an algorithm to ensure there's something to list
    with app.app_context():
        alg = SubmittedAlgorithm.query.get(setup_submitted_algorithm.id)
        alg.status = 'approved'
        alg.approved_plugin_path = os.path.join('approved_plugins', secure_filename(alg.plugin_filename))
        db.session.commit()
        
        deployment = DeployedAlgorithm(
            submitted_algorithm_id=alg.id,
            business_context="Production",
            status='active'
        )
        db.session.add(deployment)
        db.session.commit()

    response = super_admin_client.get(url_for('admin_list_deployed_algorithms'))
    assert response.status_code == 200
    assert b"View Deployed Algorithms" in response.data
    assert b"Test Algo for Management" in response.data # Name of the deployed algorithm
    assert b"Production" in response.data # Business context
    assert b"active" in response.data # Status
