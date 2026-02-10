from functools import wraps
from flask import abort
from flask_login import current_user

def permission_required(permission_name):
    """
    Decorator that checks if the current user has a specific permission.
    Aborts with 403 if the user is not logged in or doesn't have the permission.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(403)  # Or redirect to login: return redirect(url_for('login', next=request.url))
            
            # Check all roles for the required permission
            has_permission = False
            for role in current_user.roles:
                if permission_name in [p.name for p in role.permissions]:
                    has_permission = True
                    break
            
            if not has_permission:
                abort(403) # Forbidden
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def role_required(role_name):
    """
    Decorator that checks if the current user has a specific role.
    Aborts with 403 if the user is not logged in or doesn't have the role.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(403)
            
            if role_name not in [r.name for r in current_user.roles]:
                abort(403) # Forbidden
            return f(*args, **kwargs)
        return decorated_function
    return decorator
