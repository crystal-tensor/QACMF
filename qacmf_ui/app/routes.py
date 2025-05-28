from app import app, db
from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user, login_required
from app.models import User, Role #, Permission
from app.decorators import role_required, permission_required
# from werkzeug.urls import url_parse # For redirecting back safely, if needed later

# For now, we'll define basic forms directly in routes or use request.form.
# Later, Flask-WTF forms can be added in a forms.py file.

@app.route('/')
def index():
    return render_template('index.html', title='Home')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if not username or not email or not password:
            flash('All fields are required for registration.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already taken. Please choose a different one.', 'warning')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email address already registered. Please use a different one or login.', 'warning')
            return redirect(url_for('register'))

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!', 'success')
        # TODO: Assign default role e.g. 'developer'
        login_user(user)
        return redirect(url_for('profile'))
    return render_template('register.html', title='Register')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember_me = request.form.get('remember_me') is not None

        if not username or not password:
            flash('Username and password are required.', 'danger')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()
        if user is None or not user.check_password(password):
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))
        
        login_user(user, remember=remember_me)
        flash(f'Welcome back, {user.username}!', 'success')
        
        # next_page = request.args.get('next')
        # if not next_page or url_parse(next_page).netloc != '':
        #     next_page = url_for('index')
        # return redirect(next_page)
        return redirect(url_for('profile')) # Simple redirect for now
        
    return render_template('login.html', title='Sign In')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', title='Profile', user=current_user)

# Admin Routes for User Management
@app.route('/admin/users')
@login_required
@role_required('super_admin')
def admin_users_list():
    users = User.query.all()
    return render_template('admin_users.html', title='Manage Users', users=users)

@app.route('/admin/user/<int:user_id>/manage_roles', methods=['GET', 'POST'])
@login_required
@role_required('super_admin')
def admin_manage_user_roles(user_id):
    user = User.query.get_or_404(user_id)
    all_roles = Role.query.all()
    if request.method == 'POST':
        # Clear existing roles for the user first
        user.roles.clear()
        # Get selected roles from the form
        selected_role_ids = request.form.getlist('roles')
        for role_id in selected_role_ids:
            role = Role.query.get(role_id)
            if role:
                user.roles.append(role)
        db.session.commit()
        flash(f'Roles for {user.username} updated successfully.', 'success')
        return redirect(url_for('admin_users_list'))
        
    user_role_ids = [role.id for role in user.roles]
    return render_template('manage_user_roles.html', title=f'Manage Roles for {user.username}', user=user, all_roles=all_roles, user_role_ids=user_role_ids)

from werkzeug.utils import secure_filename
import os # For potential future use with file paths

# Example of a protected route using permission
# This will be replaced by the actual submission form and logic
# @app.route('/submit_algorithm')
# @login_required
# @permission_required('submit_algorithms')
# def submit_algorithm_route():
#     # Logic for submitting an algorithm
#     return "Algorithm Submission Page (requires 'submit_algorithms' permission)"


@app.route('/algorithms/submit', methods=['GET', 'POST'])
@login_required
@permission_required('submit_algorithms') # Or @role_required('developer')
def submit_algorithm():
    if request.method == 'POST':
        # Check if all required fields are present
        required_fields = ['name', 'description', 'version']
        for field in required_fields:
            if not request.form.get(field):
                flash(f'Error: Missing required text field: {field}', 'danger')
                return render_template('submit_algorithm.html', title='Submit New Algorithm')

        # Check for file uploads
        required_files = ['config_file', 'api_spec_file', 'plugin_file']
        uploaded_files = {}
        for field_name in required_files:
            if field_name not in request.files or not request.files[field_name].filename:
                flash(f'Error: Missing required file: {field_name}', 'danger')
                return render_template('submit_algorithm.html', title='Submit New Algorithm')
            uploaded_files[field_name] = request.files[field_name]

        name = request.form.get('name')
        description = request.form.get('description')
        version = request.form.get('version')

        config_file = uploaded_files['config_file']
        api_spec_file = uploaded_files['api_spec_file']
        plugin_file_upload = uploaded_files['plugin_file']

        # Secure filenames
        config_filename = secure_filename(config_file.filename)
        api_spec_filename = secure_filename(api_spec_file.filename) # Though content is stored, filename might be logged or used
        plugin_filename = secure_filename(plugin_file_upload.filename)

        try:
            config_content = config_file.read().decode('utf-8')
            api_spec_content = api_spec_file.read().decode('utf-8')
            plugin_content = plugin_file_upload.read() # Read as bytes
        except UnicodeDecodeError:
            flash('Error: One of the text-based files (config or API spec) is not valid UTF-8 encoded text.', 'danger')
            return render_template('submit_algorithm.html', title='Submit New Algorithm')
        except Exception as e:
            flash(f'Error reading uploaded files: {e}', 'danger')
            return render_template('submit_algorithm.html', title='Submit New Algorithm')

        # Create and store the SubmittedAlgorithm object
        new_algorithm = SubmittedAlgorithm(
            name=name,
            description=description,
            version=version,
            developer_id=current_user.id,
            config_file_content=config_content,
            api_spec_content=api_spec_content,
            plugin_file_content=plugin_content,
            plugin_filename=plugin_filename
            # status defaults to 'pending_review' as per model
        )
        
        db.session.add(new_algorithm)
        try:
            db.session.commit()
            flash('Algorithm submitted successfully for review!', 'success')
            return redirect(url_for('profile')) # Or a page listing submitted algorithms
        except Exception as e:
            db.session.rollback()
            flash(f'Database error: Could not save algorithm. {e}', 'danger')
            return render_template('submit_algorithm.html', title='Submit New Algorithm')

    # For GET request, just render the submission form
    return render_template('submit_algorithm.html', title='Submit New Algorithm')

from app.models import SubmittedAlgorithm # Ensure this is imported if not already

# ... (other routes)

# The old /submit_algorithm route is now replaced by /algorithms/submit
# The old /approve_algorithm route is now effectively replaced by /admin/algorithms/<id>/status
# and the listing page.
# @app.route('/approve_algorithm')
# @login_required
# @permission_required('approve_algorithms')
# def approve_algorithm_route():
#     # Logic for approving an algorithm
#     return "Algorithm Approval Page (requires 'approve_algorithms' permission)"

# Algorithm Management Routes
import os
from werkzeug.utils import secure_filename
from flask import current_app

@app.route('/admin/algorithms/list')
@login_required
@permission_required('approve_algorithms') # Or a more general 'manage_algorithms'
def admin_list_algorithms():
    algorithms = SubmittedAlgorithm.query.order_by(SubmittedAlgorithm.submission_date.desc()).all()
    return render_template('admin_list_algorithms.html', title='Manage Submitted Algorithms', algorithms=algorithms)

@app.route('/admin/algorithms/<int:algorithm_id>/status', methods=['POST'])
@login_required
@permission_required('approve_algorithms')
def admin_set_algorithm_status(algorithm_id):
    algorithm = SubmittedAlgorithm.query.get_or_404(algorithm_id)
    new_status = request.form.get('status')

    if not new_status or new_status not in ['approved', 'rejected']:
        flash('Invalid status provided.', 'danger')
        return redirect(url_for('admin_list_algorithms'))

    algorithm.status = new_status
    if new_status == 'approved':
        if not algorithm.plugin_file_content or not algorithm.plugin_filename:
            flash('Error: Plugin file content or filename is missing for this algorithm.', 'danger')
            db.session.rollback() # Rollback status change if file cannot be saved
            return redirect(url_for('admin_list_algorithms'))

        # Ensure the approved_plugins directory exists
        approved_plugins_dir = os.path.join(current_app.root_path, '..', 'qacmf_ui', 'approved_plugins') # Correct path relative to instance_path or app.root_path
        if not os.path.exists(approved_plugins_dir):
            os.makedirs(approved_plugins_dir)
            print(f"Created directory: {approved_plugins_dir}")


        secured_filename = secure_filename(algorithm.plugin_filename)
        # It's better to use a unique name for the stored file to avoid conflicts, 
        # e.g., by prefixing with algorithm_id or a UUID.
        # For now, just using the secured filename.
        # Example: unique_filename = f"{algorithm.id}_{secured_filename}"
        file_path = os.path.join(approved_plugins_dir, secured_filename)
        
        try:
            with open(file_path, 'wb') as f:
                f.write(algorithm.plugin_file_content)
            algorithm.approved_plugin_path = os.path.join('approved_plugins', secured_filename) # Store relative path
            # Consider removing plugin_file_content from db after saving to file to save space
            # algorithm.plugin_file_content = None 
            flash(f'Algorithm "{algorithm.name}" approved and plugin file saved.', 'success')
        except Exception as e:
            flash(f'Error saving plugin file: {e}', 'danger')
            db.session.rollback() # Rollback status change
            return redirect(url_for('admin_list_algorithms'))
    elif new_status == 'rejected':
        # If rejected, ensure any previously approved path is cleared (if logic allows re-review)
        algorithm.approved_plugin_path = None
        flash(f'Algorithm "{algorithm.name}" has been rejected.', 'info')
    
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash(f'Database error: Could not update algorithm status. {e}', 'danger')
    
    return redirect(url_for('admin_list_algorithms'))

@app.route('/admin/algorithms/<int:algorithm_id>/deploy', methods=['POST'])
@login_required
@permission_required('deploy_algorithms')
def admin_deploy_algorithm(algorithm_id):
    submitted_algorithm = SubmittedAlgorithm.query.get_or_404(algorithm_id)

    if submitted_algorithm.status != 'approved':
        flash(f'Algorithm "{submitted_algorithm.name}" must be approved before it can be deployed.', 'warning')
        return redirect(url_for('admin_list_algorithms'))

    if not submitted_algorithm.approved_plugin_path:
        flash(f'Approved plugin path not found for algorithm "{submitted_algorithm.name}". Cannot deploy.', 'danger')
        return redirect(url_for('admin_list_algorithms'))

    # Check if this specific version is already deployed to avoid duplicate deployments
    # (Can be more sophisticated based on business context)
    existing_deployment = DeployedAlgorithm.query.filter_by(submitted_algorithm_id=algorithm_id).first()
    if existing_deployment:
        flash(f'Algorithm "{submitted_algorithm.name}" version {submitted_algorithm.version} is already deployed or has a pending deployment record.', 'info')
        # Optionally, redirect to a page to manage this existing deployment or allow redeploy
        return redirect(url_for('admin_list_algorithms')) 

    business_context = request.form.get('business_context', 'General Use') # Default or from form
    config_override = request.form.get('config_override', None) # Optional from form

    new_deployment = DeployedAlgorithm(
        submitted_algorithm_id=submitted_algorithm.id,
        business_context=business_context,
        config_override=config_override,
        status='active' # Or 'inactive' if manual activation is desired
    )

    db.session.add(new_deployment)
    try:
        db.session.commit()
        flash(f'Algorithm "{submitted_algorithm.name}" (v{submitted_algorithm.version}) has been marked for deployment.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Database error: Could not deploy algorithm. {e}', 'danger')
        
    return redirect(url_for('admin_list_algorithms')) # Or a page listing deployed algorithms

@app.route('/admin/deployed_algorithms')
@login_required
@permission_required('deploy_algorithms') # Or a more general 'manage_deployments'
def admin_list_deployed_algorithms():
    deployed_algorithms = DeployedAlgorithm.query.order_by(DeployedAlgorithm.deployment_date.desc()).all()
    return render_template('admin_deployed_algorithms.html', title='View Deployed Algorithms', algorithms=deployed_algorithms)

import logging # For logging maintenance tasks

# Placeholder Maintenance Tasks
MAINTENANCE_TASKS = [
    {'name': 'clear_temporary_files', 'description': 'Clears temporary files and cache from the system.'},
    {'name': 'database_backup_dry_run', 'description': 'Simulates a database backup process and reports potential issues.'},
    {'name': 'plugin_signature_check', 'description': 'Verifies the digital signatures of all approved plugins.'},
    {'name': 'system_health_check', 'description': 'Performs a basic health check of system components.'}
]

@app.route('/admin/maintenance', methods=['GET'])
@login_required
@permission_required('trigger_maintenance')
def admin_maintenance_tasks():
    return render_template('admin_maintenance.html', title='System Maintenance', tasks=MAINTENANCE_TASKS)

@app.route('/admin/maintenance/run/<task_name>', methods=['POST'])
@login_required
@permission_required('trigger_maintenance')
def admin_run_maintenance_task(task_name):
    # Find the task to ensure it's a valid task
    task_exists = any(task['name'] == task_name for task in MAINTENANCE_TASKS)
    if not task_exists:
        flash(f'Error: Maintenance task "{task_name}" not found.', 'danger')
        return redirect(url_for('admin_maintenance_tasks'))

    # Log the action
    log_message = f"Maintenance task '{task_name}' triggered by user '{current_user.username}'."
    app.logger.info(log_message) # Using Flask's app.logger
    
    # Placeholder for actual task execution logic
    # For now, we just flash a message
    flash(f'Task "{task_name}" has been triggered successfully.', 'success')
    
    return redirect(url_for('admin_maintenance_tasks'))
