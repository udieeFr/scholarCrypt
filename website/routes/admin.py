from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from website.models import Admin, ApplicantCriteria, ShortlistedApplicant, Applicant
from website import db
from website.routes.encryption import decrypt_personal_data

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
    total_applicants = ApplicantCriteria.query.count()
    total_shortlisted = ShortlistedApplicant.query.count()

    # Query applicants who are not shortlisted (not in ShortlistedApplicant table)
    # FIX: Added better error handling and more efficient query
    try:
        non_shortlisted_applicants = db.session.query(ApplicantCriteria).join(
            Applicant, Applicant.id == ApplicantCriteria.applicant_id
        ).outerjoin(
            ShortlistedApplicant, ShortlistedApplicant.applicant_id == Applicant.id
        ).filter(ShortlistedApplicant.id == None).all()
        
    except Exception as e:
        print(f"Database error in dashboard: {e}")
        non_shortlisted_applicants = []
        flash("Error loading applicant data. Please try again.", category='error')

    return render_template('adDashboard.html', 
                         username=username,
                         user_id=user_id,
                         total_applicants=total_applicants,
                         total_shortlisted=total_shortlisted,
                         non_shortlisted_applicants=non_shortlisted_applicants)

@admin_bp.route('/shortlist/<int:applicant_id>', methods=['POST'])
@admin_required
def shortlist_applicant(applicant_id):
    """
    Shortlist an applicant by copying their data to the shortlisted table
    """
    try:
        # Get the applicant and their criteria
        applicant = Applicant.query.get(applicant_id)
        if not applicant:
            flash("Applicant not found.", category='error')
            return redirect(url_for('admin.dashboard'))
        
        # Check if applicant has submitted application criteria
        criteria = ApplicantCriteria.query.filter_by(applicant_id=applicant_id).first()
        if not criteria:
            flash("Applicant has not submitted their application yet.", category='error')
            return redirect(url_for('admin.dashboard'))
        
        # Check if already shortlisted
        existing_shortlist = ShortlistedApplicant.query.filter_by(applicant_id=applicant_id).first()
        if existing_shortlist:
            flash(f"Applicant {applicant.username} is already shortlisted.", category='error')
            return redirect(url_for('admin.dashboard'))
        
        # FIX: Decrypt personal data for shortlisted table
        try:
            nric, email, address = decrypt_personal_data(
                applicant.encrypted_nric,
                applicant.encrypted_email, 
                applicant.encrypted_address,
                applicant.hmac
            )
        except Exception as e:
            print(f"Decryption error for applicant {applicant_id}: {e}")
            flash("Error processing applicant data. Please contact technical support.", category='error')
            return redirect(url_for('admin.dashboard'))
        
        # Create shortlisted entry with all required data
        shortlisted_applicant = ShortlistedApplicant(
            applicant_id=applicant.id,
            username=applicant.username,
            nric=nric,
            email=email,
            address=address,
            academic_score=criteria.academic_score,
            merit_points=criteria.merit_points,
            household_income=criteria.household_income,
            num_siblings=criteria.num_siblings,
            applied_program=criteria.applied_program,
            disability_status=criteria.disability_status
        )
        
        db.session.add(shortlisted_applicant)
        db.session.commit()
        
        flash(f"✅ Applicant #{applicant_id} has been successfully shortlisted!", category='success')
        
    except Exception as e:
        db.session.rollback()
        print(f"Error shortlisting applicant {applicant_id}: {e}")
        flash("An error occurred while shortlisting the applicant. Please try again.", category='error')
    
    return redirect(url_for('admin.dashboard'))

# FIX: Added new route to view shortlisted applicants with full details
@admin_bp.route('/shortlisted')
@admin_required
def view_shortlisted():
    """
    View all shortlisted applicants with their full details (including personal info)
    """
    try:
        shortlisted_applicants = ShortlistedApplicant.query.order_by(
            ShortlistedApplicant.shortlisted_at.desc()
        ).all()
        
        return render_template('shortlisted.html', 
                             shortlisted_applicants=shortlisted_applicants,
                             username=session.get('username'),
                             user_id=session.get('user_id'))
                             
    except Exception as e:
        print(f"Error loading shortlisted applicants: {e}")
        flash("Error loading shortlisted applicants. Please try again.", category='error')
        return redirect(url_for('admin.dashboard'))

# FIX: Added route to remove from shortlist if needed
@admin_bp.route('/remove_shortlist/<int:shortlist_id>', methods=['POST'])
@admin_required
def remove_from_shortlist(shortlist_id):
    """
    Remove an applicant from the shortlist
    """
    try:
        shortlisted = ShortlistedApplicant.query.get(shortlist_id)
        if not shortlisted:
            flash("Shortlisted entry not found.", category='error')
            return redirect(url_for('admin.view_shortlisted'))
        
        username = shortlisted.username
        db.session.delete(shortlisted)
        db.session.commit()
        
        flash(f"❌ {username} has been removed from the shortlist.", category='success')
        
    except Exception as e:
        db.session.rollback()
        print(f"Error removing from shortlist: {e}")
        flash("Error removing applicant from shortlist. Please try again.", category='error')
    
    return redirect(url_for('admin.view_shortlisted'))

@admin_bp.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out successfully.", category='success')
    return redirect(url_for('auth.login'))