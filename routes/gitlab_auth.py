# routes/gitlab_auth.py
from flask import Blueprint, redirect, request, url_for, flash, session, make_response
from flask_login import login_user, current_user
import requests
import secrets
from datetime import datetime, timedelta
from models import db, User
from config import config

gitlab_auth_bp = Blueprint('gitlab_auth', __name__)

# GitLab OAuth endpoints
GITLAB_AUTH_URL = 'https://gitlab.com/oauth/authorize'
GITLAB_TOKEN_URL = 'https://gitlab.com/oauth/token'
GITLAB_USER_URL = 'https://gitlab.com/api/v4/user'

@gitlab_auth_bp.route('/auth/gitlab')
def gitlab_login():
    """Redirect user to GitLab for authorization"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    # Check if GitLab credentials are configured
    if not config.GITLAB_CLIENT_ID or not config.GITLAB_CLIENT_SECRET:
        flash('GitLab OAuth is not configured. Please contact administrator.', 'error')
        print("❌ GitLab credentials not configured!")
        print(f"   GITLAB_CLIENT_ID: {config.GITLAB_CLIENT_ID}")
        print(f"   GITLAB_CLIENT_SECRET: {'Set' if config.GITLAB_CLIENT_SECRET else 'Not Set'}")
        return redirect(url_for('main.login'))
    
    # Generate state token for CSRF protection
    state = secrets.token_urlsafe(32)
    
    # Store state in session with permanent flag
    session.permanent = True
    session['gitlab_oauth_state'] = state
    session.modified = True
    
    print(f"🔐 Generated GitLab OAuth state: {state}")
    print(f"📦 Session before redirect: {dict(session)}")
    
    # Build the authorization URL
    params = {
        'client_id': config.GITLAB_CLIENT_ID,
        'redirect_uri': config.GITLAB_REDIRECT_URI,
        'response_type': 'code',
        'state': state,
        'scope': 'read_user api read_repository'
    }
    
    # Create proper URL with encoded parameters
    from urllib.parse import urlencode
    auth_url = f"{GITLAB_AUTH_URL}?{urlencode(params)}"
    
    print(f"🔗 Redirecting to GitLab OAuth:")
    print(f"   Client ID: {config.GITLAB_CLIENT_ID}")
    print(f"   Redirect URI: {config.GITLAB_REDIRECT_URI}")
    print(f"   State: {state}")
    print(f"   Full URL: {auth_url}")
    print(f"")
    print(f"⚠️  IMPORTANT: Make sure your GitLab OAuth app has this EXACT redirect URI:")
    print(f"   {config.GITLAB_REDIRECT_URI}")
    
    response = make_response(redirect(auth_url))
    return response

@gitlab_auth_bp.route('/auth/gitlab/callback')
def gitlab_callback():
    """Handle GitLab OAuth callback - standard route"""
    return _handle_gitlab_callback()

# Alternate callback route (if GitLab is configured with /callback/gitlab)
@gitlab_auth_bp.route('/callback/gitlab')
def gitlab_callback_alternate():
    """Handle GitLab OAuth callback - alternate route"""
    return _handle_gitlab_callback()

def _handle_gitlab_callback():
    """Handle GitLab OAuth callback"""
    print("📥 GitLab callback received!")
    print(f"   Request path: {request.path}")
    print(f"   Request args: {dict(request.args)}")
    print(f"   Session data: {dict(session)}")
    
    # Check for errors from GitLab
    error = request.args.get('error')
    if error:
        error_description = request.args.get('error_description', 'Unknown error')
        print(f"❌ GitLab OAuth error: {error} - {error_description}")
        flash(f'GitLab authentication failed: {error_description}', 'error')
        return redirect(url_for('main.login'))
    
    # Get state parameters
    state_from_url = request.args.get('state')
    state_from_session = session.get('gitlab_oauth_state')
    
    print(f"🔐 State from URL: {state_from_url}")
    print(f"🔐 State from session: {state_from_session}")
    
    # Verify state parameter to prevent CSRF
    if not state_from_url:
        print("❌ No state parameter in callback")
        flash('Missing state parameter. Please try again.', 'error')
        return redirect(url_for('main.login'))
    
    if not state_from_session:
        print("❌ No state found in session - session may have expired")
        print(f"   Available session keys: {list(session.keys())}")
        flash('Session expired. Please try logging in again.', 'error')
        return redirect(url_for('main.login'))
    
    if state_from_url != state_from_session:
        print(f"❌ State mismatch!")
        print(f"   Expected: {state_from_session}")
        print(f"   Received: {state_from_url}")
        flash('Invalid state parameter. Please try again.', 'error')
        return redirect(url_for('main.login'))
    
    # Clear the state from session
    session.pop('gitlab_oauth_state', None)
    print("✅ State verified successfully")
    
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
            'client_id': config.GITLAB_CLIENT_ID,
            'client_secret': config.GITLAB_CLIENT_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': config.GITLAB_REDIRECT_URI
        }
        
        token_response = requests.post(GITLAB_TOKEN_URL, data=token_data, timeout=10)
        
        if token_response.status_code != 200:
            print(f"❌ Token exchange failed with status {token_response.status_code}")
            print(f"   Response: {token_response.text}")
            flash('Failed to authenticate with GitLab', 'error')
            return redirect(url_for('main.login'))
        
        token_json = token_response.json()
        access_token = token_json.get('access_token')
        refresh_token = token_json.get('refresh_token')
        expires_in = token_json.get('expires_in', 7200)  # Default 2 hours
        
        if not access_token:
            print(f"❌ No access token in response: {token_json}")
            error_msg = token_json.get('error_description', 'Failed to get access token')
            flash(f'Authentication failed: {error_msg}', 'error')
            return redirect(url_for('main.login'))
        
        print("✅ Access token received")
        
        # Calculate token expiration time
        token_expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
        
        # Get user info from GitLab
        print("👤 Fetching user information...")
        user_headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }
        
        user_response = requests.get(GITLAB_USER_URL, headers=user_headers, timeout=10)
        
        if user_response.status_code != 200:
            print(f"❌ Failed to fetch user info: {user_response.status_code}")
            print(f"   Response: {user_response.text}")
            flash('Failed to get user information from GitLab', 'error')
            return redirect(url_for('main.login'))
        
        user_data = user_response.json()
        print(f"✅ User data received for: {user_data.get('username')}")
        print(f"   User ID: {user_data.get('id')}")
        print(f"   Email: {user_data.get('email')}")
        
        # Find or create user
        gitlab_id = str(user_data['id'])
        user = User.query.filter_by(gitlab_id=gitlab_id).first()
        
        if not user:
            # Check if username or email already exists
            email = user_data.get('email')
            username = user_data.get('username')
            
            existing_user = None
            if email:
                existing_user = User.query.filter(
                    (User.username == username) | (User.email == email)
                ).first()
            else:
                existing_user = User.query.filter_by(username=username).first()
            
            if existing_user:
                # Link existing account with GitLab
                print(f"🔗 Linking existing user {existing_user.username} with GitLab")
                existing_user.gitlab_id = gitlab_id
                existing_user.gitlab_token = access_token
                existing_user.gitlab_refresh_token = refresh_token
                existing_user.gitlab_token_expires_at = token_expires_at
                
                # Update avatar only if not set or if user prefers GitLab
                if not existing_user.avatar_url or existing_user.avatar_source == 'gitlab':
                    existing_user.avatar_url = user_data.get('avatar_url')
                    existing_user.avatar_source = 'gitlab'
                
                existing_user.bio = user_data.get('bio') or existing_user.bio
                existing_user.verified = True
                
                db.session.commit()
                user = existing_user
            else:
                # Create new user
                print(f"✨ Creating new user: {username}")
                user = User(
                    username=username,
                    email=email,
                    gitlab_id=gitlab_id,
                    gitlab_token=access_token,
                    gitlab_refresh_token=refresh_token,
                    gitlab_token_expires_at=token_expires_at,
                    avatar_url=user_data.get('avatar_url'),
                    bio=user_data.get('bio'),
                    verified=True,
                    avatar_source='gitlab'
                )
                db.session.add(user)
                db.session.commit()
                print(f"✅ Created new user with ID: {user.id}")
        else:
            # Update existing user
            print(f"🔄 Updating existing user: {user.username}")
            user.gitlab_token = access_token
            user.gitlab_refresh_token = refresh_token
            user.gitlab_token_expires_at = token_expires_at
            
            # Update avatar if user prefers GitLab
            if user.avatar_source == 'gitlab':
                user.avatar_url = user_data.get('avatar_url')
            
            # Update email and bio if not set
            if not user.email and user_data.get('email'):
                user.email = user_data.get('email')
            if not user.bio and user_data.get('bio'):
                user.bio = user_data.get('bio')
            
            user.verified = True
            db.session.commit()
            print(f"✅ User updated successfully")
        
        # Log the user in
        login_user(user, remember=True)
        print(f"🎉 User {user.username} logged in successfully via GitLab")
        flash(f'Welcome back, {user.username}!', 'success')
        
        return redirect(url_for('main.dashboard'))
        
    except requests.exceptions.RequestException as e:
        print(f"❌ Network error during GitLab OAuth: {str(e)}")
        flash('Network error. Please try again.', 'error')
        return redirect(url_for('main.login'))
    except Exception as e:
        print(f"❌ Unexpected error during GitLab OAuth: {str(e)}")
        import traceback
        traceback.print_exc()
        flash(f'Authentication failed. Please try again.', 'error')
        return redirect(url_for('main.login'))

@gitlab_auth_bp.route('/auth/gitlab/refresh')
def refresh_gitlab_token():
    """Refresh GitLab access token using refresh token"""
    if not current_user.is_authenticated:
        flash('Please login first', 'error')
        return redirect(url_for('main.login'))
    
    if not current_user.gitlab_refresh_token:
        flash('No GitLab refresh token available', 'error')
        return redirect(url_for('main.dashboard'))
    
    try:
        print(f"🔄 Refreshing GitLab token for user: {current_user.username}")
        
        token_data = {
            'client_id': config.GITLAB_CLIENT_ID,
            'client_secret': config.GITLAB_CLIENT_SECRET,
            'refresh_token': current_user.gitlab_refresh_token,
            'grant_type': 'refresh_token',
            'redirect_uri': config.GITLAB_REDIRECT_URI
        }
        
        token_response = requests.post(GITLAB_TOKEN_URL, data=token_data, timeout=10)
        
        if token_response.status_code != 200:
            print(f"❌ Token refresh failed: {token_response.status_code}")
            print(f"   Response: {token_response.text}")
            flash('Failed to refresh GitLab token', 'error')
            return redirect(url_for('main.dashboard'))
        
        token_json = token_response.json()
        access_token = token_json.get('access_token')
        refresh_token = token_json.get('refresh_token')
        expires_in = token_json.get('expires_in', 7200)
        
        if not access_token:
            flash('Failed to refresh GitLab token', 'error')
            return redirect(url_for('main.dashboard'))
        
        # Update user tokens
        current_user.gitlab_token = access_token
        if refresh_token:
            current_user.gitlab_refresh_token = refresh_token
        current_user.gitlab_token_expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
        
        db.session.commit()
        print("✅ GitLab token refreshed successfully")
        flash('GitLab token refreshed successfully', 'success')
        
        return redirect(url_for('main.dashboard'))
        
    except Exception as e:
        print(f"❌ Error refreshing GitLab token: {str(e)}")
        flash('Failed to refresh GitLab token', 'error')
        return redirect(url_for('main.dashboard'))

@gitlab_auth_bp.route('/auth/gitlab/disconnect')
def disconnect_gitlab():
    """Disconnect GitLab account from user profile"""
    if not current_user.is_authenticated:
        flash('Please login first', 'error')
        return redirect(url_for('main.login'))
    
    try:
        print(f"🔌 Disconnecting GitLab for user: {current_user.username}")
        
        # Clear GitLab credentials
        current_user.gitlab_id = None
        current_user.gitlab_token = None
        current_user.gitlab_refresh_token = None
        current_user.gitlab_token_expires_at = None
        
        # If avatar source was GitLab, clear it
        if current_user.avatar_source == 'gitlab':
            current_user.avatar_source = 'github' if current_user.github_id else None
            if not current_user.github_id:
                current_user.avatar_url = None
        
        db.session.commit()
        print("✅ GitLab disconnected successfully")
        flash('GitLab account disconnected successfully', 'success')
        
    except Exception as e:
        print(f"❌ Error disconnecting GitLab: {str(e)}")
        flash('Failed to disconnect GitLab account', 'error')
    
    return redirect(url_for('main.dashboard'))