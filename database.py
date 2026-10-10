from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATEBASE_URL = "mysql+pymysql://root:9816@localhost:3306/user_management"

engine = create_engine(DATEBASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
