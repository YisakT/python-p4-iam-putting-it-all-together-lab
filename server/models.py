from sqlalchemy_serializer import SerializerMixin
from sqlalchemy import (
    Column, String, Integer, ForeignKey, Text, CheckConstraint)
from sqlalchemy.orm import relationship, validates
from sqlalchemy.ext.hybrid import hybrid_property
from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String, nullable=False, unique=True)
    _password_hash = Column('password_hash', String(128))
   
    image_url = Column(String)
    bio = Column(String)
    recipes = relationship("Recipe", back_populates="user")

    @property
    def password_hash(self):
        raise AttributeError('password_hash: read-only field')

    @password_hash.setter
    def password_hash(self, password_plain):
        self._password_hash = bcrypt.generate_password_hash(password_plain).decode('utf-8')

    def check_password(self, password_plain):
        return bcrypt.check_password_hash(self._password_hash, password_plain)

    def authenticate(self, password_plain):
        """Alias for check_password for compatibility with tests."""
        return self.check_password(password_plain)
    
    @validates('username')
    def validate_username(self, key, username):
        if not username:
            raise ValueError("Username must be provided")
        if User.query.filter(User.username == username).first():
            raise ValueError(f"Username {username} is already in use.")
        return username
    
class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    user = relationship("User", back_populates="recipes")
    title = Column(String, nullable=False)
    instructions = Column(Text, nullable=False)
    minutes_to_complete = Column(Integer)

    __table_args__ = (
        CheckConstraint("LENGTH(instructions) >= 50", 
                        name='check_instructions_length'),
    )

