from sqlalchemy import Column, String, Text
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class UserModel(Base):
    __tablename__ = 'users'

    username = Column(String, primary_key=True)
    first_name = Column(String)
    last_name = Column(String, nullable=True)
    ipaddress = Column(String)
    private_key = Column(String)
    public_key = Column(String)
    config_file = Column(Text)

