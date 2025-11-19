# routes/auth.py
from flask import Blueprint, redirect, request, url_for, flash, session
from flask_login import login_user, current_user, logout_user, login_required
import requests
from models import db, User
from config import config
from utils.email_sender import email_sender

github_auth_bp = Blueprint('auth', __name__)

# GitHub OAuth endpoints
GITHUB_AUTH_URL = 'https://github.com/login/oauth/authorize'
GITHUB_TOKEN_URL = 'https://github.com/login/oauth/access_token'
GITHUB_USER_URL = 'https://api.github.com/user'
GITHUB_EMAIL_URL = 'https://api.github.com/user/emails'

@github_auth_bp.route('/auth/github')
def github_login():
    """Redirect user to GitHub for authorization"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    import secrets
    state = secrets.token_urlsafe(16)
    session['oauth_state'] = state
    
    # Build the authorization URL
    params = {
        'client_id': config.GITHUB_CLIENT_ID,
        'redirect_uri': config.GITHUB_REDIRECT_URI,
        'scope': 'user:email read:user',
        'state': state,
        'allow_signup': 'true'
    }
    
    # Create proper URL with encoded parameters
    from urllib.parse import urlencode
    auth_url = f"{GITHUB_AUTH_URL}?{urlencode(params)}"
    
    print(f"🔗 Redirecting to GitHub OAuth:")
    print(f"   Client ID: {config.GITHUB_CLIENT_ID}")
    print(f"   Redirect URI: {config.GITHUB_REDIRECT_URI}")
    print(f"   Full URL: {auth_url}")
    
    return redirect(auth_url)

# Main callback route (standard route)
@github_auth_bp.route('/auth/github/callback')
def github_callback():
    """Handle GitHub OAuth callback - standard route"""
    return _handle_github_callback()

# Alternate callback route (if GitHub is configured with /callback/github)
@github_auth_bp.route('/callback/github')
def github_callback_alternate():
    """Handle GitHub OAuth callback - alternate route"""
    return _handle_github_callback()

def _handle_github_callback():
    """Common handler for GitHub OAuth callback"""
    print("📥 GitHub callback received!")
    print(f"   Request args: {request.args}")
    print(f"   Request path: {request.path}")
    
    # Check for errors from GitHub
    error = request.args.get('error')
    if error:
        error_description = request.args.get('error_description', 'Unknown error')
        print(f"❌ GitHub OAuth error: {error} - {error_description}")
        flash(f'GitHub authentication failed: {error_description}', 'error')
        return redirect(url_for('main.login'))
    
    # Verify state parameter to prevent CSRF
    state = request.args.get('state')
    stored_state = session.pop('oauth_state', None)
    
    if not state or state != stored_state:
        print(f"❌ State mismatch: received={state}, stored={stored_state}")
        flash('Invalid state parameter. Please try again.', 'error')
        return redirect(url_for('main.login'))
    
    # Get authorization code
    code = request.args.get('code')
    if not code:
        print("❌ No authorization code received")
        flash('Authorization failed: No code received', 'error')
        return redirect(url_for('main.login'))
    
    try:
        # Exchange code for access token
        print("🔄 Exchanging code for access token...")
        token_data = {
            'client_id': config.GITHUB_CLIENT_ID,
            'client_secret': config.GITHUB_CLIENT_SECRET,
            'code': code,
            'redirect_uri': config.GITHUB_REDIRECT_URI
        }
        headers = {'Accept': 'application/json'}
        
        token_response = requests.post(GITHUB_TOKEN_URL, data=token_data, headers=headers)
        
        if token_response.status_code != 200:
            print(f"❌ Token exchange failed with status {token_response.status_code}")
            print(f"   Response: {token_response.text}")
            flash('Failed to authenticate with GitHub', 'error')
            return redirect(url_for('main.login'))
        
        token_json = token_response.json()
        access_token = token_json.get('access_token')
        
        if not access_token:
            print(f"❌ No access token in response: {token_json}")
            error_msg = token_json.get('error_description', 'Failed to get access token')
            flash(f'Authentication failed: {error_msg}', 'error')
            return redirect(url_for('main.login'))
        
        print("✅ Access token received")
        
        # Get user info from GitHub
        print("👤 Fetching user information...")
        user_headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        user_response = requests.get(GITHUB_USER_URL, headers=user_headers)
        
        if user_response.status_code != 200:
            print(f"❌ Failed to fetch user info: {user_response.status_code}")
            flash('Failed to get user information from GitHub', 'error')
            return redirect(url_for('main.login'))
        
        user_data = user_response.json()
        print(f"✅ User data received for: {user_data.get('login')}")
        
        # Get user email if not public
        email = user_data.get('email')
        if not email:
            print("📧 Fetching user email...")
            email_response = requests.get(GITHUB_EMAIL_URL, headers=user_headers)
            if email_response.status_code == 200:
                emails = email_response.json()
                # Get primary verified email
                for email_data in emails:
                    if email_data.get('primary') and email_data.get('verified'):
                        email = email_data.get('email')
                        break
                # If no primary, get first verified
                if not email:
                    for email_data in emails:
                        if email_data.get('verified'):
                            email = email_data.get('email')
                            break
        
        # Find or create user
        github_id = str(user_data['id'])
        user = User.query.filter_by(github_id=github_id).first()
        
        if not user:
            # Check if username or email already exists
            existing_user = User.query.filter(
                (User.username == user_data['login']) | 
                (User.email == email if email else False)
            ).first()
            
            if existing_user:
                # Link existing account with GitHub
                print(f"🔗 Linking existing user {existing_user.username} with GitHub")
                existing_user.github_id = github_id
                existing_user.github_token = access_token
                existing_user.avatar_url = user_data.get('avatar_url')
                existing_user.bio = user_data.get('bio')
                db.session.commit()
                user = existing_user
            else:
                # Create new user
                print(f"✨ Creating new user: {user_data['login']}")
                user = User(
                    username=user_data['login'],
                    email=email,
                    github_id=github_id,
                    github_token=access_token,
                    avatar_url=user_data.get('avatar_url'),
                    bio=user_data.get('bio'),
                    avatar_source='github'
                )
                if user.email:
                    # Send welcome email when user signs up
                    email_sender.send_email(to_email=user.email, subject='✅ Created new user', html_content=f"hello {user.username}, welcome to CodeInsight!", text_content=None)

                db.session.add(user)
                db.session.commit()
                print(f"✅ Created new user with ID: {user.id}")
        else:
            # Update existing user
            print(f"🔄 Updating existing user: {user.username}")
            user.github_token = access_token
            user.avatar_url = user_data.get('avatar_url')
            user.bio = user_data.get('bio')
            if email and not user.email:
                user.email = email
            db.session.commit()
            print(f"✅ User updated successfully")
        
        # Log the user in
        login_user(user, remember=True)
        print(f"🎉 User {user.username} logged in successfully")
        flash(f'Welcome back, {user.username}!', 'success')
        if user.email:
                    # Send welcome email when user signs up
                    email_sender.send_email(to_email=user.email, subject='✅ New login', html_content=f"Welcome back, {user.username}", text_content=None)
        
        
        return redirect(url_for('main.dashboard'))
        
    except requests.exceptions.RequestException as e:
        print(f"❌ Network error during GitHub OAuth: {str(e)}")
        flash('Network error. Please try again.', 'error')
        return redirect(url_for('main.login'))
    except Exception as e:
        print(f"❌ Unexpected error during GitHub OAuth: {str(e)}")
        import traceback
        traceback.print_exc()
        flash(f'Authentication failed. Please try again.', 'error')
        return redirect(url_for('main.login'))

@github_auth_bp.route('/logout')
@login_required
def logout():
    """Log out the current user"""
    username = current_user.username
    logout_user()
    flash(f'Goodbye {username}! You have been logged out successfully.', 'info')
    return redirect(url_for('main.index'))