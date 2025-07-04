from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from flask_wtf import CSRFProtect

mysql = MySQL()
bcrypt = Bcrypt()
csrf = CSRFProtect()