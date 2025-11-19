from . import db
from flask_login import UserMixin
from datetime import datetime

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=True)
    avatar_url = db.Column(db.String(500))
    bio = db.Column(db.Text)
    github_id = db.Column(db.String(100), unique=True)
    gitlab_id = db.Column(db.String(100), unique=True)
    github_token = db.Column(db.String(500))
    gitlab_token = db.Column(db.String(500))
    gitlab_refresh_token = db.Column(db.String(500))
    gitlab_token_expires_at = db.Column(db.DateTime)
    is_premium = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    public_profile = db.Column(db.Boolean, default=False)
    publish_private_repos = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_analysis = db.Column(db.DateTime)
    language = db.Column(db.String(10), default='en')
    theme = db.Column(db.String(10), default='light')
    stripe_customer_id = db.Column(db.String(100))
    premium_expires_at = db.Column(db.DateTime)
    avatar_source = db.Column(db.String(20), default='github')
    last_username_change = db.Column(db.DateTime)
    deleted_at = db.Column(db.DateTime)
    
