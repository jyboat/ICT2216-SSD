from flask import Flask
from .extensions import bcrypt, mysql, csrf
from .config import Config
from .auth import auth_bp
from .materials import materials_bp
from .courses import courses_bp
from .forum import forum_bp
from .admin import admin_bp
from .security import security_check

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Init extensions
    bcrypt.init_app(app)
    mysql.init_app(app)
    csrf.init_app(app)

    # Setup security middleware
    security_check(app)

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(materials_bp)
    app.register_blueprint(courses_bp)
    app.register_blueprint(forum_bp)
    app.register_blueprint(admin_bp)

    return app