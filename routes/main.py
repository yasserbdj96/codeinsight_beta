from flask import Blueprint, render_template
from flask_login import login_required, current_user

# Create a blueprint
main_bp = Blueprint('main', __name__)

# Define routes
@main_bp.route('/')
def index():
    return render_template('home.html')

@main_bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@main_bp.route('/login')
def login():
    return render_template('login.html')