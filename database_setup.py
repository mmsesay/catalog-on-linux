from sqlalchemy import Column, String, Integer, ForeignKey, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import(TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)

Base = declarative_base()
    
# User Class
class User(Base, UserMixin):
    """This is the User schema class"""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    hash_password = Column(String(250))

    # constructor
    def __init__(self, username,email,password):
        self.username = username
        self.email = email
        self.hash_password = generate_password_hash(password)

    # verify password function
    def verify_password(self, password):
        return check_password_hash(self.hash_password, password)
   
# Category Class
class Category(Base):
    """This is the Category schema class"""
    __tablename__ = "categories"

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'))
    user = relationship(User)

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'id': self.id,
           'name': self.name
       }

# Items Class
class Items(Base):
    """This is the Items schema class"""
    __tablename__ = "items"

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    description = Column(String(250), nullable=False)
    category_id = Column(Integer, ForeignKey('categories.id'))
    category = relationship(Category)

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'id': self.id,
           'name': self.name,
           'description': self.description,  
           'category': self.category_id
       }

engine = create_engine('postgresql://cataloguser:catalog123@localhost/catalogdb')
 
Base.metadata.create_all(engine)

