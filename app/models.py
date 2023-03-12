from datetime import datetime
from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from app import login

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    certificates = db.relationship('Certificate', backref='author', lazy='dynamic')

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login.user_loader
def load_user(id):
    return User.query.get(int(id))

class Certificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    csr = db.Column(db.LargeBinary)
    key = db.Column(db.LargeBinary)
    cn = db.Column(db.String(64), index=True)
    organization = db.Column(db.String(64), index=True)
    pfx = db.Column(db.LargeBinary)
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp,
            'cn': self.cn,
            'organization': self.organization,
        }

    def __repr__(self):
        return '<Certificate {}>}'.format(self.csr)
    
class Kantone(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    abbr = db.Column(db.String(2), unique=True, nullable=False)

    def __repr__(self):
        return '<Kantone {}>'.format(self.name)