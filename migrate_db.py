import os
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

load_dotenv()
db_url = os.getenv("DATABASE_URL")

if not db_url:
    print("No DATABASE_URL found.")
    exit(1)

engine = create_engine(db_url)

with engine.connect() as conn:
    print("Connected to database.")
    try:
        # Check if column exists first
        res = conn.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name='clients' AND column_name='device_public_key';"))
        if not res.fetchone():
            print("Adding column 'device_public_key' to 'clients' table...")
            conn.execute(text("ALTER TABLE clients ADD COLUMN device_public_key TEXT;"))
            conn.commit()
            print("Successfully added column.")
        else:
            print("Column 'device_public_key' already exists.")
    except Exception as e:
        print(f"Error updating schema: {e}")
