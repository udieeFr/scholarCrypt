from flask import Blueprint, render_template, redirect, url_for, flash, session, request
from website.models import Applicant, ApplicantCriteria, ShortlistedApplicant
from website import db
import re
from website.routes.encryption import encrypt_personal_data, decrypt_personal_data

# Fixed: Added url_prefix
applicant_bp = Blueprint('applicant', __name__, url_prefix='/applicant')

# Fixed: Removed extra return statement and renamed to login_required
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'applicant':
            flash("Please log in to access this page.", category='error')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function  # Fixed: Only one return statement

# Fixed: Added @login_required decorator
@applicant_bp.route('/dashboard')
@login_required
def dashboard():
    user_id = session.get('user_id')
    username = session.get('username')

    # Check if user is in session or not
    user = Applicant.query.get(user_id)
    if not user:
        session.clear()
        flash("User account not found. Please log in again.", category='error')
        return redirect(url_for('auth.login'))
    
    # If ada applicantsId = dah apply atau dah shortlisted
    has_applied = ApplicantCriteria.query.filter_by(applicant_id=user_id).first() is not None
    is_shortlisted = ShortlistedApplicant.query.filter_by(applicant_id=user_id).first() is not None

    # Render page with information
    # kiri = html variable name, kanan = python variable name
    return render_template('stDashboard.html', 
                         username=username, 
                         user_id=user_id, 
                         has_applied=has_applied, 
                         is_shortlisted=is_shortlisted)

# Fixed: Added missing route decorator and login_required
@applicant_bp.route('/apply', methods=['GET','POST'])
@login_required
def apply():
    # Check if user has already applied
    user_id = session.get('user_id')
    existing_application = ApplicantCriteria.query.filter_by(applicant_id=user_id).first()
    
    if existing_application:
        flash("You have already submitted an application.", category='error')
        return redirect(url_for('applicant.dashboard'))
    
    if request.method=='POST':
        nric = request.form.get('nric', '').strip()
        email = request.form.get('email', '').strip()
        address = request.form.get('address', '').strip()
        academic_score = request.form.get('academic_score')
        merit_points = request.form.get('merit_points')
        household_income = request.form.get('household_income')
        num_siblings = request.form.get('num_siblings')
        applied_program = request.form.get('applied_program')
        disability_status = request.form.get('disability_status') == 'yes'

        #sekarang, error is empty
        error = []

        #check if column are filled or not
        if not nric:
            error.append("NRIC/Passport number is required.")
        else:
            # Validate NRIC/Passport format
            malaysian_nric_pattern = r'^[0-9]{6}-[0-9]{2}-[0-9]{4}$'
            passport_pattern = r'^[A-Z0-9]{5,15}$'
            
            # FIX: Normalize passport to uppercase for consistent validation and storage
            if not re.match(malaysian_nric_pattern, nric):
                nric_upper = nric.upper()
                if re.match(passport_pattern, nric_upper):
                    nric = nric_upper  # Store the normalized uppercase version
                else:
                    error.append("Invalid NRIC/Passport format. Use format: 123456-78-9012 or A1234567")
        
        if not email:
            error.append("Email address is required.")
        elif not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            error.append("Invalid email format.")
        
        if not address:
            error.append("Full address is required.")
        elif len(address) < 10:
            error.append("Please provide a complete address.")

        if not academic_score:
            # FIX: Corrected typo "Scademic score is requeired" 
            error.append("Academic score is required.")
        if not merit_points:
            error.append("Merit points is required.")
        if not household_income:
            error.append("Household income is required.")
        if not num_siblings:
            error.append("Number of siblings is required.")
        if not applied_program:
            error.append("Applied program is required.")

        #input validation
        try:
            academic_score = float(academic_score)
            # FIX: Changed validation from 0-4.0 to 1.0-4.0 as requested
            if academic_score < 1.0 or academic_score > 4.0:
                error.append("Your GPA must be between 1.0 and 4.0")
        except (ValueError, TypeError):
                error.append("Academic score must be a valid number.")

        try:
            merit_points = float(merit_points)
            # FIX: Changed validation to be between 1.0-10.0 as requested
            if merit_points < 1.0 or merit_points > 10.0:
                error.append("Merit points must be between 1.0 and 10.0")
        except (ValueError, TypeError):
            error.append("Merit points must be a valid number.")
            
        try:
            household_income = float(household_income)
            if household_income < 0:
                error.append("Household income cannot be negative.")
        except (ValueError, TypeError):
            error.append("Household income must be a valid number.")
            
        try:
            num_siblings = int(num_siblings)
            if num_siblings < 0:
                error.append("Number of siblings cannot be negative.")
        except (ValueError, TypeError):
            error.append("Number of siblings must be a valid whole number.")

        #if error [] is not empty
        if error:
            for error_msg in error:  # FIX: Renamed variable to avoid confusion
                flash(error_msg, category='error')
            # FIX: Moved return statement to correct location - should render form again with errors
            return render_template('applyForm.html')

        # ENCRYPTION STEP: Encrypt personal information
        try:
            print(f"🔐 Encrypting personal data for user {user_id}...")
            
            # Encrypt the personal data
            encrypted_nric, encrypted_email, encrypted_address, data_hmac = encrypt_personal_data(
                nric, email, address
            )
            
            print(f"✅ Personal data encrypted successfully")
            
        except Exception as e:
            print(f"❌ Encryption failed: {e}")
            flash("An error occurred while securing your personal information. Please try again.", category='error')
            return render_template('applyForm.html')
        
        #Save to database
        try:
            #update data from  registered user (existing row)
            user = Applicant.query.get(user_id)
            if not user:
                flash("User account not found.", category='error')
                return redirect(url_for('auth.login'))
            
            user.encrypted_nric = encrypted_nric
            user.encrypted_email = encrypted_email
            user.encrypted_address = encrypted_address
            user.hmac = data_hmac

            #assign data get from form into table applicant criteria
            new_application = ApplicantCriteria(
                applicant_id=user_id,
                academic_score=academic_score,
                merit_points=merit_points,
                household_income=household_income,
                num_siblings=num_siblings,
                applied_program=applied_program,
                disability_status=disability_status
            )

            db.session.add(new_application)
            db.session.commit()
        
            flash("Your scholarship application has been submitted successfully!", category='success')
            return redirect(url_for('applicant.dashboard'))
        #if ada failure
        except Exception as e:
            #cancel changes made
            db.session.rollback()
            flash("An error occurred while submitting your application. Please try again.", category='error')
            print(f"Database error: {e}")  # For debugging
            return render_template('applyForm.html')
    
    # FIX: This return statement should be outside the POST block to handle GET requests
    return render_template('applyForm.html')

# Fixed: Added missing login_required decorator
@applicant_bp.route('/status')
@login_required
def status():
    user_id = session.get('user_id')
    
    # Get application details
    application = ApplicantCriteria.query.filter_by(applicant_id=user_id).first()
    shortlisted = ShortlistedApplicant.query.filter_by(applicant_id=user_id).first()
    
    return render_template('status.html', 
                         application=application, 
                         shortlisted=shortlisted)

# FIX: Added missing route for viewing personal data
@applicant_bp.route('/personal-data')
@login_required
def view_personal_data():
    """
    Route to view decrypted personal data (only accessible by the user themselves)
    """
    user_id = session.get('user_id')
    user = Applicant.query.get(user_id)
    
    if not user:
        flash("User account not found.", category='error')
        return redirect(url_for('auth.login'))
    
    # Check if user has submitted application with personal data
    if not user.encrypted_nric and not user.encrypted_email and not user.encrypted_address:
        flash("No personal data found. Please submit your scholarship application first.", category='error')
        return redirect(url_for('applicant.dashboard'))
    
    try:
        # Decrypt personal data for display
        nric, email, address = decrypt_personal_data(
            user.encrypted_nric, 
            user.encrypted_email, 
            user.encrypted_address, 
            user.hmac
        )
        
        return render_template('viewPersonalData.html', 
                             nric=nric, 
                             email=email, 
                             address=address)
                             
    except Exception as e:
        print(f"❌ Decryption failed: {e}")
        flash("Error retrieving your personal data. Please contact support.", category='error')
        return redirect(url_for('applicant.dashboard'))

# Fixed: Added missing @ symbol
@applicant_bp.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out successfully.", category='success')
    return redirect(url_for('auth.login'))