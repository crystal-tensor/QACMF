from app import db
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

# Association table for User and Role
UserRoles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True)
)

# Association table for Role and Permission
RolePermissions = db.Table('role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permission.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False) # Increased length for stronger hashes
    email = db.Column(db.String(120), unique=True, nullable=False)
    roles = db.relationship('Role', secondary=UserRoles, backref=db.backref('users', lazy='dynamic'))

    def __repr__(self):
        return f'<User {self.username}>'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    permissions = db.relationship('Permission', secondary=RolePermissions, backref=db.backref('roles', lazy='dynamic'))

    def __repr__(self):
        return f'<Role {self.name}>'

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)

    def __repr__(self):
        return f'<Permission {self.name}>'

class SubmittedAlgorithm(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    version = db.Column(db.String(20), nullable=False)
    developer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    submission_date = db.Column(db.DateTime, default=datetime.utcnow)
    config_file_content = db.Column(db.Text, nullable=True)
    api_spec_content = db.Column(db.Text, nullable=True)
    plugin_file_content = db.Column(db.LargeBinary, nullable=True)
    plugin_filename = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(50), default='pending_review') # e.g., 'pending_review', 'approved', 'rejected'
    approved_plugin_path = db.Column(db.String(255), nullable=True) # Path to the saved plugin file upon approval
    developer = db.relationship('User', backref=db.backref('submitted_algorithms', lazy='dynamic'))

    def __repr__(self):
        return f'<SubmittedAlgorithm {self.name} v{self.version}>'

class DeployedAlgorithm(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    submitted_algorithm_id = db.Column(db.Integer, db.ForeignKey('submitted_algorithm.id'), nullable=False)
    business_context = db.Column(db.String(255), nullable=True)
    deployment_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='inactive')
    config_override = db.Column(db.Text, nullable=True)
    submitted_algorithm = db.relationship('SubmittedAlgorithm', backref=db.backref('deployments', lazy='dynamic'))

    def __repr__(self):
        return f'<DeployedAlgorithm {self.submitted_algorithm.name} ({self.business_context})>'
