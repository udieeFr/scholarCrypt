from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from website.models import Applicant, Admin
from website import db
from werkzeug.security import generate_password_hash, check_password_hash

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/')
def index():
    return redirect(url_for('auth.login'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash("Username and password are required.", category='error')
            return redirect(url_for('auth.register'))

        existing_user = Applicant.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already taken.", category='error')
            return redirect(url_for('auth.register'))

        try:
            new_applicant = Applicant(
                username=username,
                password_hash=generate_password_hash(password),
                encrypted_nric=b'',
                encrypted_email=b'',
                encrypted_address=b'',
                hmac=b''
            )
            db.session.add(new_applicant)
            db.session.commit()
            flash("Registration successful! Please log in.", category='success')
            # Fixed: Changed from auth.pin to auth.login
            return redirect(url_for('auth.login'))
        except Exception as e:
            db.session.rollback()
            flash("An error occurred during registration. Please try again.", category='error')
            return redirect(url_for('auth.register'))

    return render_template('register.html')

@auth_bp.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')

        if not username or not password:
            flash("Username and password are required.", category='error')
            return redirect(url_for('auth.login'))
        
        if not role:
            flash("Please select a login role.", category='error')
            return redirect(url_for('auth.login'))

        if role == 'applicant':
            user = Applicant.query.filter_by(username=username).first()
            if not user or not check_password_hash(user.password_hash, password):
                flash("Invalid username or password.", category='error')
                return redirect(url_for('auth.login'))
            
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = 'applicant'
            flash(f"Welcome back, {username}!", category='success')
            # Fixed: This should work now with the corrected applicant.py
            return redirect(url_for('applicant.dashboard'))
            
        elif role == 'admin':
            admin = Admin.query.filter_by(username=username).first()
            if not admin or not check_password_hash(admin.password_hash, password):
                flash("Invalid admin credentials.", category='error')
                return redirect(url_for('auth.login'))
            
            session['user_id'] = admin.id
            session['username'] = admin.username
            session['role'] = 'admin'
            flash(f"Welcome back, Admin {username}!", category='success')
            # Fixed: Changed from auth.login to admin.dashboard
            return redirect(url_for('admin.dashboard'))
        
    return render_template('login.html')