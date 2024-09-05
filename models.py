import datetime
import os
from atexit import register

from dotenv import load_dotenv
from sqlalchemy import create_engine, Integer, String, DateTime, ForeignKey, \
    func
from sqlalchemy.orm import DeclarativeBase, sessionmaker, mapped_column, \
    Mapped, relationship


load_dotenv()
POSTGRES_DB = os.getenv('POSTGRES_DB')
POSTGRES_USER = os.getenv('POSTGRES_USER')
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD')
POSTGRES_HOST = os.getenv('POSTGRES_HOST')
POSTGRES_PORT = os.getenv('POSTGRES_PORT')
DSN = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@" \
      f"{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
engine = create_engine(DSN)
Session = sessionmaker(bind=engine)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = 'user'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    first_name: Mapped[str] = mapped_column(String(32), nullable=False)
    last_name: Mapped[str] = mapped_column(String(32), nullable=False)
    email: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(64), nullable=False)
    token: Mapped[str] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, server_default=func.now())
    adverts: Mapped[int] = relationship('Advert', backref='user')

    @property
    def json(self):
        return {"id": self.id, "first_name": self.first_name,
                "last_name": self.last_name, "email": self.email,
                "created_at": self.created_at}


class Advert(Base):
    __tablename__ = 'advert'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(String(4096), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, server_default=func.now())
    owner: Mapped[int] = mapped_column(ForeignKey(User.id))

    @property
    def json(self):
        return {"id": self.id,
                "title": self.title,
                "description": self.description,
                "created_at": self.created_at,
                "owner": self.owner}


Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)
register(engine.dispose)
