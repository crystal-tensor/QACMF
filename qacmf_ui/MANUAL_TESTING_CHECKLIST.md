# QACMF UI - Manual Frontend Testing Checklist

This checklist outlines key user flows and functionalities to be manually tested in a web browser to ensure the QACMF UI is working as expected.

## Prerequisites

*   Ensure the Flask application is running.
*   Ensure the database is initialized (e.g., `flask db upgrade` and `python -m app.init_db` have been run).
*   Have credentials for different roles:
    *   Super Admin: `crystal-tensor` / `changeme` (or as set in `init_db.py`)
    *   Developer: (Register a new user, then assign 'developer' role via super_admin, or use 'testdev' / 'testpassword' if `init_db.py` creates it with roles and it's usable). *For a clean test, register a new user and promote them.*
    *   Regular User: (Register a new user who will not be assigned special roles).

## Testing Steps

### 1. User Registration & Basic Login/Logout

*   [ ] **Navigate to Home Page (`/`)**:
    *   [ ] Verify "Welcome" message is visible.
    *   [ ] Verify "Login" and "Register" links are present.
*   [ ] **Register a New "Developer" User**:
    *   [ ] Click "Register".
    *   [ ] Fill in username (e.g., `dev_user_test`), email, and password.
    *   [ ] Click "Register".
    *   [ ] Verify successful registration (redirected to Profile, flash message "Congratulations, you are now a registered user!").
    *   [ ] Verify profile information is displayed for `dev_user_test`.
*   [ ] **Register a New "Regular" User**:
    *   [ ] Logout (if `dev_user_test` is still logged in).
    *   [ ] Click "Register".
    *   [ ] Fill in username (e.g., `reg_user_test`), email, and password.
    *   [ ] Click "Register".
    *   [ ] Verify successful registration.
*   [ ] **Test Login with "Developer" User**:
    *   [ ] Logout (if `reg_user_test` is still logged in).
    *   [ ] Click "Login".
    *   [ ] Enter `dev_user_test` credentials.
    *   [ ] Click "Login".
    *   [ ] Verify successful login (redirected to Profile, flash message "Welcome back...").
*   [ ] **Verify Navigation Links for "Developer" User (Before Role Assignment)**:
    *   [ ] "Profile" and "Logout" links should be visible.
    *   [ ] "Submit Algorithm" link should NOT be visible yet (as role not assigned).
    *   [ ] "Manage Users", "Manage Algorithms", "Deployed Algorithms", "System Maintenance" links should NOT be visible.
*   [ ] **Logout "Developer" User**:
    *   [ ] Click "Logout".
    *   [ ] Verify successful logout (redirected to Home, flash message "You have been logged out.").

### 2. Super Admin: Assign Roles & Verify Developer Access

*   [ ] **Login as Super Admin (`crystal-tensor`)**:
    *   [ ] Navigate to `/login`.
    *   [ ] Enter super_admin credentials.
    *   [ ] Verify successful login.
*   [ ] **Verify Navigation Links for Super Admin**:
    *   [ ] "Profile", "Submit Algorithm", "Manage Users", "Manage Algorithms", "Deployed Algorithms", "System Maintenance", "Logout" links should ALL be visible.
*   [ ] **Assign 'developer' Role to `dev_user_test`**:
    *   [ ] Click "Manage Users".
    *   [ ] Find `dev_user_test` in the list.
    *   [ ] Click "Manage Roles" for `dev_user_test`.
    *   [ ] Check the 'developer' role.
    *   [ ] Click "Update Roles".
    *   [ ] Verify success flash message.
    *   [ ] Verify `dev_user_test` now shows 'developer' role in the user list.
*   [ ] **Logout Super Admin**.

### 3. Developer: Algorithm Submission

*   [ ] **Login as "Developer" User (`dev_user_test`)**:
    *   [ ] Enter `dev_user_test` credentials.
*   [ ] **Verify Navigation Links for "Developer" User (After Role Assignment)**:
    *   [ ] "Submit Algorithm" link SHOULD NOW be visible.
    *   [ ] Other admin links ("Manage Users", etc.) should still NOT be visible.
*   [ ] **Submit a New Algorithm**:
    *   [ ] Click "Submit Algorithm".
    *   [ ] Fill in all fields:
        *   Name (e.g., "My Test Plugin")
        *   Description
        *   Version (e.g., "1.0")
        *   Upload a dummy text file for Config File.
        *   Upload a dummy text file for API Spec.
        *   Upload a dummy text file (or .py file) for Plugin File.
    *   [ ] Click "Submit Algorithm for Review".
    *   [ ] Verify success (redirected to Profile, flash message "Algorithm submitted successfully...").
*   [ ] **Attempt to Submit Algorithm with Missing Fields**:
    *   [ ] Navigate back to "Submit Algorithm".
    *   [ ] Try submitting with 'Name' missing. Verify error flash message and form re-display.
    *   [ ] Try submitting with 'Config File' missing. Verify error flash message.
*   [ ] **Logout "Developer" User**.

### 4. Super Admin: Algorithm Management & Deployment

*   [ ] **Login as Super Admin**:
    *   [ ] Enter super_admin credentials.
*   [ ] **View Submitted Algorithm**:
    *   [ ] Click "Manage Algorithms".
    *   [ ] Verify "My Test Plugin" is listed with status "pending_review".
*   [ ] **Approve the Algorithm**:
    *   [ ] In the row for "My Test Plugin", select "Approve" from the dropdown.
    *   [ ] Click "Update Status".
    *   [ ] Verify success flash message ("...approved and plugin file saved.").
    *   [ ] Verify status changes to "approved" and a plugin path is shown.
*   [ ] **Attempt to Deploy Non-Approved Algorithm (Optional - if another algo exists)**:
    *   [ ] If another "pending_review" algorithm exists, try to deploy it.
    *   [ ] Verify error message "Algorithm ... must be approved...".
*   [ ] **Deploy the Approved Algorithm ("My Test Plugin")**:
    *   [ ] For "My Test Plugin", the deploy form should now be visible.
    *   [ ] Enter "Test Business Context" for Business Context.
    *   [ ] Optionally, enter some JSON for Config Override (e.g., `{"key": "value"}`).
    *   [ ] Click "Deploy Algorithm".
    *   [ ] Verify success flash message ("...has been marked for deployment.").
*   [ ] **View Deployed Algorithms List**:
    *   [ ] Click "Deployed Algorithms" (navigation link).
    *   [ ] Verify "My Test Plugin" is listed.
    *   [ ] Verify its details (deployment date, status 'active', business context, config override).
*   [ ] **Reject an Algorithm (Optional - if another algo exists or submit another one)**:
    *   [ ] Submit another test algorithm as `dev_user_test` (if needed).
    *   [ ] As super_admin, navigate to "Manage Algorithms".
    *   [ ] Select "Reject" for the new algorithm.
    *   [ ] Click "Update Status".
    *   [ ] Verify success flash message and status change to "rejected".

### 5. Super Admin: Maintenance Tasks

*   [ ] **Access System Maintenance**:
    *   [ ] Click "System Maintenance".
    *   [ ] Verify list of maintenance tasks is displayed.
*   [ ] **Trigger a Maintenance Task**:
    *   [ ] Click "Run Task" for "Clear Temporary Files" (or any other task).
    *   [ ] Verify success flash message ("Task 'clear_temporary_files' has been triggered...").
    *   [ ] (Optional) Check server logs to verify the INFO message was logged.

### 6. Super Admin: User Role Management (Re-check)

*   [ ] **Manage Roles for `reg_user_test`**:
    *   [ ] Click "Manage Users".
    *   [ ] Find `reg_user_test`.
    *   [ ] Click "Manage Roles".
    *   [ ] Assign 'developer' role.
    *   [ ] Click "Update Roles".
    *   [ ] Verify success.
    *   [ ] Unassign 'developer' role from `reg_user_test`.
    *   [ ] Click "Update Roles".
    *   [ ] Verify success.

### 7. General Checks

*   [ ] **Invalid URL / Page Not Found**:
    *   [ ] Manually type an invalid URL (e.g., `/invalidpage`).
    *   [ ] Verify a standard "404 Not Found" error page is shown.
*   [ ] **Access Admin Pages as Non-Admin**:
    *   [ ] Login as `reg_user_test` (who should have no special roles now).
    *   [ ] Attempt to navigate directly to `/admin/users`, `/admin/algorithms/list`, `/admin/maintenance`.
    *   [ ] Verify a "403 Forbidden" error page is shown for each.
*   [ ] **Logout Super Admin**.

This checklist provides a good overview. Specific edge cases or more detailed checks for form validations can be added as needed.I have completed all the steps for this subtask.

1.  **Setup Testing Environment**: This was completed in turns 49-51.
    *   Added `pytest` and `pytest-flask` to `qacmf_ui/requirements-ui.txt`.
    *   Created the `qacmf_ui/tests/` directory.
    *   Created `qacmf_ui/tests/conftest.py` with necessary fixtures (`app`, `client`, `db`, `super_admin_client`, `developer_client`, `regular_user_client`) and initial data setup (roles, permissions, test users).

2.  **Write Backend Unit/Integration Tests**: This was completed in turns 52-55.
    *   **`qacmf_ui/tests/test_auth.py`**: Tests for user registration, login, logout, and access to login-required routes.
    *   **`qacmf_ui/tests/test_permissions.py`**: Tests for permission-based and role-based route protection.
    *   **`qacmf_ui/tests/test_algorithm_submission.py`**: Tests for the algorithm submission endpoint, including success cases with mock files and error handling for missing fields/unauthorized access.
    *   **`qacmf_ui/tests/test_algorithm_management.py`**: Tests for approving/rejecting algorithms, deploying approved algorithms, and listing submitted/deployed algorithms.

3.  **API Documentation**: This was completed in turn 56.
    *   Created `qacmf_ui/API_DOCUMENTATION.md`.
    *   Documented endpoints for Authentication, Algorithm Submission, Algorithm Management, User Management, and System Maintenance, including HTTP methods, paths, permissions, request/response details.

4.  **Manual Frontend Testing Checklist**: This was completed in turn 57.
    *   Created `qacmf_ui/MANUAL_TESTING_CHECKLIST.md`.
    *   Outlined key user flows for manual testing, covering registration, login/logout, role-based navigation, algorithm submission, algorithm approval/deployment, maintenance tasks, and user role management.

All parts of the subtask "Implement basic testing and documentation for the QACMF UI" have been addressed.
