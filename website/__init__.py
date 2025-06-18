from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()  # Initialize without app first
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    
    # Load config BEFORE initializing extensions
    app.config.from_object('website.config.Config')  # Note: Full path to Config class
    
    # Initialize extensions with app
    db.init_app(app)
    login_manager.init_app(app)
    
    # Register blueprints
    from .routes.auth import auth_bp
    from .routes.applicant import applicant_bp
    from .routes.admin import admin_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(applicant_bp)
    app.register_blueprint(admin_bp)
    # Make sure this is after db and login_manager are initialized
    from website.models import Applicant

    @login_manager.user_loader
    def load_user(user_id):
        return Applicant.query.get(int(user_id))
    return app