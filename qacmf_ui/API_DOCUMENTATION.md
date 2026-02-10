# QACMF UI - API Documentation

This document provides details on the API endpoints for the QACMF UI application.

## Base URL

All URLs are relative to the application's root (e.g., `http://localhost:5000`).

## Authentication

### 1. Register User

*   **Endpoint:** `POST /register`
*   **Permissions/Roles:** None (Public)
*   **Request Body/Form Data:**
    *   `username` (string, required): Desired username.
    *   `email` (string, required): User's email address.
    *   `password` (string, required): User's password.
*   **Success Response:**
    *   Status Code: `302 FOUND` (Redirects to `/profile`)
    *   Session: User is logged in.
    *   Flash Message: "Congratulations, you are now a registered user!"
*   **Error Responses:**
    *   If fields are missing: Redirects to `/register` with flash message (e.g., "All fields are required...").
    *   If username/email taken: Redirects to `/register` with flash message (e.g., "Username already taken...").

### 2. Login User

*   **Endpoint:** `POST /login`
*   **Permissions/Roles:** None (Public)
*   **Request Body/Form Data:**
    *   `username` (string, required): User's username.
    *   `password` (string, required): User's password.
    *   `remember_me` (boolean, optional): Checkbox value for "Remember me".
*   **Success Response:**
    *   Status Code: `302 FOUND` (Redirects to `/profile`)
    *   Session: User is logged in.
    *   Flash Message: "Welcome back, {username}!"
*   **Error Responses:**
    *   If fields missing: Redirects to `/login` with flash message.
    *   If invalid credentials: Redirects to `/login` with flash message "Invalid username or password."

### 3. Logout User

*   **Endpoint:** `GET /logout`
*   **Permissions/Roles:** Authenticated User
*   **Request Body/Form Data:** None
*   **Success Response:**
    *   Status Code: `302 FOUND` (Redirects to `/`)
    *   Session: User is logged out.
    *   Flash Message: "You have been logged out."

### 4. View Profile

*   **Endpoint:** `GET /profile`
*   **Permissions/Roles:** Authenticated User
*   **Request Body/Form Data:** None
*   **Success Response:**
    *   Status Code: `200 OK`
    *   Body: Renders `profile.html` with user details.

## Algorithm Submission

### 1. Submit New Algorithm

*   **Endpoint:** `POST /algorithms/submit`
*   **Permissions/Roles:** Requires 'submit_algorithms' permission (e.g., 'developer' role).
*   **Request Body/Form Data (multipart/form-data):**
    *   `name` (string, required): Name of the algorithm.
    *   `description` (string, required): Description of the algorithm.
    *   `version` (string, required): Version of the algorithm (e.g., "1.0.0").
    *   `config_file` (file, required): Configuration file (e.g., .json, .yaml).
    *   `api_spec_file` (file, required): API specification file (e.g., OpenAPI .json, .yaml).
    *   `plugin_file` (file, required): Plugin file (e.g., .py, .zip).
*   **Success Response:**
    *   Status Code: `302 FOUND` (Redirects to `/profile` or algorithm list)
    *   Flash Message: "Algorithm submitted successfully for review!"
    *   Database: A new `SubmittedAlgorithm` record is created with status 'pending_review'.
*   **Error Responses:**
    *   Missing field/file: Renders `submit_algorithm.html` again with appropriate flash error (e.g., "Error: Missing required text field: name").
    *   File read error: Renders `submit_algorithm.html` with error flash.
    *   User not authorized: `403 FORBIDDEN`.

### 2. View Algorithm Submission Form

*   **Endpoint:** `GET /algorithms/submit`
*   **Permissions/Roles:** Requires 'submit_algorithms' permission.
*   **Request Body/Form Data:** None
*   **Success Response:**
    *   Status Code: `200 OK`
    *   Body: Renders `submit_algorithm.html`.

## Algorithm Management (Admin)

### 1. List Submitted Algorithms

*   **Endpoint:** `GET /admin/algorithms/list`
*   **Permissions/Roles:** Requires 'approve_algorithms' permission (e.g., 'algorithm_admin', 'super_admin' roles).
*   **Request Body/Form Data:** None
*   **Success Response:**
    *   Status Code: `200 OK`
    *   Body: Renders `admin_list_algorithms.html` with a table of submitted algorithms.

### 2. Update Algorithm Status (Approve/Reject)

*   **Endpoint:** `POST /admin/algorithms/<int:algorithm_id>/status`
*   **Permissions/Roles:** Requires 'approve_algorithms' permission.
*   **Request Body/Form Data:**
    *   `status` (string, required): New status, either "approved" or "rejected".
*   **Success Response:**
    *   Status Code: `302 FOUND` (Redirects to `/admin/algorithms/list`)
    *   Flash Message: Confirmation message (e.g., "Algorithm '...' approved and plugin file saved." or "Algorithm '...' has been rejected.").
    *   Database: `SubmittedAlgorithm` record updated. If approved, `plugin_file_content` is saved to `qacmf_ui/approved_plugins/` and `approved_plugin_path` is set.
*   **Error Responses:**
    *   Invalid status: Redirects with flash error.
    *   Algorithm not found: `404 NOT FOUND`.
    *   File saving error (if approving): Redirects with flash error.
    *   User not authorized: `403 FORBIDDEN`.

### 3. Deploy Algorithm

*   **Endpoint:** `POST /admin/algorithms/<int:algorithm_id>/deploy`
*   **Permissions/Roles:** Requires 'deploy_algorithms' permission (e.g., 'algorithm_admin', 'super_admin' roles).
*   **Request Body/Form Data:**
    *   `business_context` (string, optional, defaults to "General Use"): Context for deployment.
    *   `config_override` (string, optional): JSON/YAML string for configuration overrides.
*   **Success Response:**
    *   Status Code: `302 FOUND` (Redirects to `/admin/algorithms/list`)
    *   Flash Message: "Algorithm '...' (v...) has been marked for deployment."
    *   Database: A new `DeployedAlgorithm` record is created.
*   **Error Responses:**
    *   Algorithm not approved or plugin path missing: Redirects with flash error.
    *   Algorithm already deployed (current logic): Redirects with info flash.
    *   Algorithm not found: `404 NOT FOUND`.
    *   User not authorized: `403 FORBIDDEN`.

### 4. List Deployed Algorithms

*   **Endpoint:** `GET /admin/deployed_algorithms`
*   **Permissions/Roles:** Requires 'deploy_algorithms' permission.
*   **Request Body/Form Data:** None
*   **Success Response:**
    *   Status Code: `200 OK`
    *   Body: Renders `admin_deployed_algorithms.html` with a table of deployed algorithms.

## User Management (Super Admin)

### 1. List Users

*   **Endpoint:** `GET /admin/users`
*   **Permissions/Roles:** Requires 'super_admin' role.
*   **Request Body/Form Data:** None
*   **Success Response:**
    *   Status Code: `200 OK`
    *   Body: Renders `admin_users.html` with a list of users.

### 2. Manage User Roles (Form)

*   **Endpoint:** `GET /admin/user/<int:user_id>/manage_roles`
*   **Permissions/Roles:** Requires 'super_admin' role.
*   **Request Body/Form Data:** None
*   **Success Response:**
    *   Status Code: `200 OK`
    *   Body: Renders `manage_user_roles.html` with roles selection for the user.

### 3. Update User Roles

*   **Endpoint:** `POST /admin/user/<int:user_id>/manage_roles`
*   **Permissions/Roles:** Requires 'super_admin' role.
*   **Request Body/Form Data:**
    *   `roles` (list of integers): List of role IDs to assign to the user.
*   **Success Response:**
    *   Status Code: `302 FOUND` (Redirects to `/admin/users`)
    *   Flash Message: "Roles for {username} updated successfully."
    *   Database: User's roles are updated.
*   **Error Responses:**
    *   User not found: `404 NOT FOUND`.

## System Maintenance (Super Admin)

### 1. View Maintenance Tasks

*   **Endpoint:** `GET /admin/maintenance`
*   **Permissions/Roles:** Requires 'trigger_maintenance' permission (assigned to 'super_admin').
*   **Request Body/Form Data:** None
*   **Success Response:**
    *   Status Code: `200 OK`
    *   Body: Renders `admin_maintenance.html` with a list of placeholder maintenance tasks.

### 2. Run Maintenance Task

*   **Endpoint:** `POST /admin/maintenance/run/<task_name>`
*   **Permissions/Roles:** Requires 'trigger_maintenance' permission.
*   **Request Body/Form Data:** None
*   **Success Response:**
    *   Status Code: `302 FOUND` (Redirects to `/admin/maintenance`)
    *   Flash Message: "Task '{task_name}' has been triggered successfully."
    *   Log: An entry is made using `app.logger.info()`.
*   **Error Responses:**
    *   Invalid `task_name`: Redirects with flash error.
    *   User not authorized: `403 FORBIDDEN`.

---
*Note: This documentation assumes default behavior. Specific error codes or response bodies might vary based on Flask/extension configurations.*
---
