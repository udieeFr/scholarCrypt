from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from website.models import Admin, Applicant, ApplicantCriteria, ShortlistedApplicant
from website import db

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

def admin_required(f):
    """Decorator to require admin login for admin routes"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash("Please log in as an administrator to access this page.", category='error')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

@admin_bp.route('/dashboard')
@admin_required
def dashboard():
    # Get current admin information
    user_id = session.get('user_id')
    username = session.get('username')
    
    # Get admin from database to ensure they still exist
    admin = Admin.query.get(user_id)
    if not admin:
        session.clear()
        flash("Admin account not found. Please log in again.", category='error')
        return redirect(url_for('auth.login'))
    
    # Get statistics for dashboard
    total_applicants = Applicant.query.count()
    total_applications = ApplicantCriteria.query.count()
    total_shortlisted = ShortlistedApplicant.query.count()
    
    # FIX: Changed template name from 'admin_dashboard.html' to 'adDashboard.html' to match your file name
    return render_template('adDashboard.html', 
                         username=username,
                         user_id=user_id,
                         total_applicants=total_applicants,
                         total_applications=total_applications,
                         total_shortlisted=total_shortlisted)

@admin_bp.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out successfully.", category='success')
    return redirect(url_for('auth.login'))