from app import app, db
from app.models import User, Role, Permission

def create_initial_roles_permissions():
    """Creates initial roles and permissions if they don't exist."""
    roles_permissions_map = {
        'super_admin': ['manage_users', 'manage_roles', 'submit_algorithms', 'approve_algorithms', 'deploy_algorithms', 'trigger_maintenance'],
        'algorithm_admin': ['approve_algorithms', 'deploy_algorithms'],
        'developer': ['submit_algorithms']
    }
    
    all_permissions = set()
    for permissions in roles_permissions_map.values():
        all_permissions.update(permissions)
        
    for perm_name in all_permissions:
        if not Permission.query.filter_by(name=perm_name).first():
            permission = Permission(name=perm_name)
            db.session.add(permission)
            print(f"Created permission: {perm_name}")

    for role_name, perm_names in roles_permissions_map.items():
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            role = Role(name=role_name)
            db.session.add(role)
            print(f"Created role: {role_name}")
        
        for perm_name in perm_names:
            permission = Permission.query.filter_by(name=perm_name).first()
            if permission and permission not in role.permissions:
                role.permissions.append(permission)
                print(f"Assigned '{perm_name}' to role '{role_name}'")
    
    db.session.commit()
    print("Initial roles and permissions setup complete.")

def create_super_admin():
    """Creates the super_admin user if it doesn't exist."""
    super_admin_username = 'crystal-tensor' # Corrected username
    super_admin_email = 'admin@qacmf.com'
    super_admin_password = 'changeme' # Placeholder password

    if User.query.filter_by(username=super_admin_username).first():
        print(f"User '{super_admin_username}' already exists.")
        return

    super_admin_role = Role.query.filter_by(name='super_admin').first()
    if not super_admin_role:
        print("Super admin role not found. Please run create_initial_roles_permissions() first.")
        return

    admin = User(username=super_admin_username, email=super_admin_email)
    admin.set_password(super_admin_password)
    admin.roles.append(super_admin_role)
    db.session.add(admin)
    db.session.commit()
    print(f"Super admin user '{super_admin_username}' created successfully with role 'super_admin'.")
    print(f"IMPORTANT: Please change the password for '{super_admin_username}' immediately!")

def init_access_control():
    """Initializes all access control elements."""
    print("Starting access control initialization...")
    create_initial_roles_permissions()
    create_super_admin()
    print("Access control initialization finished.")

if __name__ == '__main__':
    # This allows running this script directly, but it's better to use Flask CLI
    # For direct script execution, the app context needs to be pushed
    with app.app_context():
        init_access_control()
