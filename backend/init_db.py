from database import Base, engine
import models


print("Creating SentinelX database tables...")

Base.metadata.create_all(bind=engine)

print("Database tables created successfully.")
