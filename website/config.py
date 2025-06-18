import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'ilovecryptofrfr')
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:@localhost/scholarap?charset=utf8mb4'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {'pool_recycle': 299}  # Prevent MySQL timeout
    
    # 🔐 ENCRYPTION CONFIGURATION
    # For class project - you can put the key directly here
    ENCRYPTION_KEY = 'SayaSukaKelasCryptographyuwu'
    ENCRYPTION_SALT = 'diaAtauAkuGaramAtauMadu'

    # Main administrator password for CLI admin creation
    MAIN_ADMIN_PASSWORD = 'SuperSecretAdminPassword123!'