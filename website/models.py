# website/models.py

from website import db
from datetime import datetime

class Admin(db.Model):
    __tablename__ = 'admins'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

class Applicant(db.Model):
    __tablename__ = 'applicants'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    encrypted_nric = db.Column(db.LargeBinary, nullable=False)
    encrypted_email = db.Column(db.LargeBinary, nullable=False)
    encrypted_address = db.Column(db.LargeBinary, nullable=False)
    hmac = db.Column(db.LargeBinary, nullable=False)
    applied_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship to criteria
    criteria = db.relationship('ApplicantCriteria', backref='applicant', lazy=True, uselist=False)
    shortlisted = db.relationship('ShortlistedApplicant', backref='applicant', lazy=True)

class ApplicantCriteria(db.Model):
    __tablename__ = 'applicants_criteria'
    
    applicant_id = db.Column(db.Integer, db.ForeignKey('applicants.id'), primary_key=True)
    academic_score = db.Column(db.Numeric(5, 2), nullable=False)
    merit_points = db.Column(db.Integer, nullable=False)
    household_income = db.Column(db.Numeric(10, 2), nullable=False)
    num_siblings = db.Column(db.Integer, nullable=False)
    applied_program = db.Column(db.String(100), nullable=False)
    disability_status = db.Column(db.Boolean, default=False)

class ShortlistedApplicant(db.Model):
    __tablename__ = 'shortlisted_applicants'
    
    id = db.Column(db.Integer, primary_key=True)
    applicant_id = db.Column(db.Integer, db.ForeignKey('applicants.id'), nullable=False)
    username = db.Column(db.String(50), nullable=False)
    nric = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    address = db.Column(db.Text, nullable=False)
    academic_score = db.Column(db.Numeric(5, 2), nullable=False)
    merit_points = db.Column(db.Integer, nullable=False)
    household_income = db.Column(db.Numeric(10, 2), nullable=False)
    num_siblings = db.Column(db.Integer, nullable=False)
    applied_program = db.Column(db.String(100), nullable=False)
    disability_status = db.Column(db.Boolean, nullable=False)
    shortlisted_at = db.Column(db.DateTime, default=datetime.utcnow)