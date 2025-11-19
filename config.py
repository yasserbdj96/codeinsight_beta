# config.py
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-here-change-in-production')
    FLASK_DEBUG = os.environ.get('FLASK_DEBUG', 'False') == 'True'
    
    # Specify database file name with absolute path
    database_name = os.environ.get('DATABASE_NAME', 'codeinsight.db')
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{database_name}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True, 
        'pool_recycle': 300, 
        'connect_args': {'timeout': 30, 'check_same_thread': False}
    }

    # Background task scheduling
    CHECK_HOUR=int(os.environ.get('CHECK_HOUR', 0))
    CHECK_MINUTE=int(os.environ.get('CHECK_MINUTE', 0))
    CHECK_SECOND=int(os.environ.get('CHECK_SECOND', 0))
    
    # Email
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    EMAIL_PORT = int(os.environ.get('EMAIL_PORT', 587))
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@codeinsight.com')
    
    # OAuth
    GITHUB_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID', '')
    GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET', '')
    GITHUB_REDIRECT_URI = os.environ.get('GITHUB_REDIRECT_URI', 'http://localhost:5000/auth/github/callback')
    
    # GitLab OAuth
    GITLAB_CLIENT_ID = os.environ.get('GITLAB_CLIENT_ID', '')
    GITLAB_CLIENT_SECRET = os.environ.get('GITLAB_CLIENT_SECRET', '')
    # Make sure this EXACTLY matches what's in your GitLab OAuth app settings
    GITLAB_REDIRECT_URI = os.environ.get('GITLAB_REDIRECT_URI', 'http://localhost:5000/auth/gitlab/callback')
    GITLAB_TOKEN_URL = 'https://gitlab.com/oauth/token'

config = Config()