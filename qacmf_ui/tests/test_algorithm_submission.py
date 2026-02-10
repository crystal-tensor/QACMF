import pytest
from flask import url_for
from app.models import SubmittedAlgorithm, User
from werkzeug.datastructures import FileStorage
import io

@pytest.fixture
def mock_files():
    """Fixture to create mock FileStorage objects for uploads."""
    return {
        'config_file': FileStorage(
            stream=io.BytesIO(b'{"param": "value"}'),
            filename='config.json',
            content_type='application/json'
        ),
        'api_spec_file': FileStorage(
            stream=io.BytesIO(b'API specification content'),
            filename='api_spec.txt',
            content_type='text/plain'
        ),
        'plugin_file': FileStorage(
            stream=io.BytesIO(b'Python plugin code'),
            filename='plugin.py',
            content_type='application/octet-stream' # or 'text/x-python'
        )
    }

def test_submit_algorithm_success(developer_client, app, mock_files):
    """Test successful algorithm submission."""
    response = developer_client.post(url_for('submit_algorithm'), data={
        'name': 'Test Algorithm',
        'description': 'A test algorithm submission.',
        'version': '1.0.0',
        **mock_files # Add files to the form data
    }, content_type='multipart/form-data', follow_redirects=True)

    assert response.status_code == 200 # Should redirect to profile
    assert b'User Profile' in response.data # Check profile page
    assert b'Algorithm submitted successfully for review!' in response.data # Flash message

    with app.app_context():
        algorithm = SubmittedAlgorithm.query.filter_by(name='Test Algorithm').first()
        assert algorithm is not None
        assert algorithm.version == '1.0.0'
        assert algorithm.description == 'A test algorithm submission.'
        assert algorithm.developer.username == 'testdev' # From developer_client
        assert algorithm.config_file_content == '{"param": "value"}'
        assert algorithm.api_spec_content == 'API specification content'
        assert algorithm.plugin_file_content == b'Python plugin code'
        assert algorithm.plugin_filename == 'plugin.py'
        assert algorithm.status == 'pending_review'

def test_submit_algorithm_missing_text_field(developer_client, mock_files):
    """Test algorithm submission with a missing text field (e.g., name)."""
    response = developer_client.post(url_for('submit_algorithm'), data={
        # 'name': 'Test Algorithm', # Name is missing
        'description': 'A test algorithm submission.',
        'version': '1.0.0',
        **mock_files
    }, content_type='multipart/form-data', follow_redirects=True)

    assert response.status_code == 200 # Stays on submission page
    assert b'Submit New Algorithm' in response.data # Still on the submission page
    assert b'Error: Missing required text field: name' in response.data # Flash message for missing name

def test_submit_algorithm_missing_file_field(developer_client):
    """Test algorithm submission with a missing file (e.g., plugin_file)."""
    # Create partial mock files, missing plugin_file
    partial_mock_files = {
        'config_file': FileStorage(io.BytesIO(b'config'), 'c.json'),
        'api_spec_file': FileStorage(io.BytesIO(b'api'), 'a.txt'),
        # 'plugin_file': missing
    }
    response = developer_client.post(url_for('submit_algorithm'), data={
        'name': 'Test Algorithm Files',
        'description': 'A test algorithm submission with missing file.',
        'version': '1.0.1',
        **partial_mock_files
    }, content_type='multipart/form-data', follow_redirects=True)

    assert response.status_code == 200 # Stays on submission page
    assert b'Submit New Algorithm' in response.data
    assert b'Error: Missing required file: plugin_file' in response.data

def test_submit_algorithm_unauthorized_user(regular_user_client, mock_files):
    """Test algorithm submission by a user without 'submit_algorithms' permission."""
    response = regular_user_client.post(url_for('submit_algorithm'), data={
        'name': 'Unauthorized Algorithm',
        'description': 'Attempt by unauthorized user.',
        'version': '0.0.1',
        **mock_files
    }, content_type='multipart/form-data', follow_redirects=True)
    
    assert response.status_code == 403 # Forbidden

def test_submit_algorithm_form_get_request(developer_client):
    """Test that GET request to submission form works."""
    response = developer_client.get(url_for('submit_algorithm'))
    assert response.status_code == 200
    assert b'Submit New Algorithm' in response.data
