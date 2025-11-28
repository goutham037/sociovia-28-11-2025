from sqlalchemy import text
from datetime import datetime
from test import app, db  # import your Flask app and db

with app.app_context():
    # inspect columns
    res = db.session.execute(text("PRAGMA table_info('workspaces')")).fetchall()
    cols = [row[1] for row in res]  # row[1] is column name
    if 'updated_at' not in cols:
        print("Adding updated_at column to workspaces...")
        db.session.execute(text("ALTER TABLE workspaces ADD COLUMN updated_at DATETIME"))
        db.session.commit()
        # Optionally set updated_at to created_at for existing rows:
        db.session.execute(text("UPDATE workspaces SET updated_at = created_at WHERE updated_at IS NULL"))
        db.session.commit()
        print("Done.")
    else:
        print("updated_at already present.")
