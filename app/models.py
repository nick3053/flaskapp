from datetime import datetime
from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from app import login
from flask import current_app, url_for

class PaginatedAPIMixin(object):
    @staticmethod
    def to_collection_dict(query, page, per_page, endpoint, **kwargs):
        resources = query.paginate(page=page, per_page=per_page,
                                   error_out=False)
        data = {
            'items': [item.to_dict() for item in resources.items],
            '_meta': {
                'page': page,
                'per_page': per_page,
                'total_pages': resources.pages,
                'total_items': resources.total
            },
            '_links': {
                'self': url_for(endpoint, page=page, per_page=per_page,
                                **kwargs),
                'next': url_for(endpoint, page=page + 1, per_page=per_page,
                                **kwargs) if resources.has_next else None,
                'prev': url_for(endpoint, page=page - 1, per_page=per_page,
                                **kwargs) if resources.has_prev else None
            }
        }
        return data

class User(UserMixin, PaginatedAPIMixin, db.Model):
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
    
    def to_dict(self):
        data = {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'certificates_count' : self.certificates.count(),
            '_links': {
                'self': url_for('api.get_user', id=self.id)
            }
            }
        return data
    
    def from_dict(self, data, new_user=False):
        for field in ['username', 'email']:
            if field in data:
                setattr(self, field, data[field])
        if new_user and 'password' in data:
            self.set_password(data['password'])

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
        data = {
            'id': self.id,
            'csr': self.csr,
            'key': self.key,
            'cn': self.cn,
            'pfx': self.pfx,
            '_links': {
                'csr': url_for('api.get_csr', cn=self.cn),
                'key': url_for('api.get_key', cn=self.cn),
                'pfx': url_for('api.get_pfx', cn=self.cn),
            }
            }
        return data


    def __repr__(self):
        return '<Certificate {}>}'.format(self.csr)