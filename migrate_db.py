"""
Database Migration Module for Security Scanner Application.

This module handles database schema updates and migrations, ensuring backward compatibility
and data integrity through automated backups and schema modifications.

Constants:
    DB_PATH (str): Path to the SQLite database file, configurable via environment variable
    BACKUP_PATH (str): Path where database backups are stored, includes timestamp
"""

import sqlite3
import logging
import os
import shutil
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DB_PATH = os.environ.get('DB_PATH', 'scan_results.db')
BACKUP_PATH = f"{DB_PATH}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

def backup_database():
    """
    Create a backup of the existing database before performing migrations.

    The backup file is created with a timestamp suffix for easy identification
    and recovery if needed. This function is automatically called before any
    migration operations.

    Returns:
        None

    Raises:
        IOError: If backup creation fails due to file system issues
    """
    if os.path.exists(DB_PATH):
        shutil.copy2(DB_PATH, BACKUP_PATH)
        logger.info(f"Created database backup at {BACKUP_PATH}")

def migrate_database():
    """
    Perform database schema migrations to add new tables and columns.

    This function handles all necessary database schema updates, including:
    1. Creating the scheduled_scans table if it doesn't exist
    2. Adding new columns to the scans table
    3. Migrating data from old schema to new schema
    4. Handling multiple database locations (local and data directory)

    The function performs the following specific tasks:
    - Creates scheduled_scans table with all required columns
    - Adds progress, status, duration, and scan_type columns to scans table
    - Updates existing completed scans to have 100% progress
    - Handles both local and data directory database versions

    Returns:
        None

    Raises:
        sqlite3.Error: If any database operations fail
        Exception: For any other unexpected errors during migration
    """
    try:
        # Create backup first
        backup_database()

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Check if scheduled_scans table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scheduled_scans'")
        if not cursor.fetchone():
            logger.info("Creating scheduled_scans table...")
            cursor.execute('''
            CREATE TABLE scheduled_scans (
                id INTEGER PRIMARY KEY,
                target_url TEXT NOT NULL,
                schedule_type TEXT NOT NULL,
                schedule_time TEXT NOT NULL,
                schedule_day TEXT,
                next_scan_date TEXT,
                last_scan_date TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT,
                is_active INTEGER DEFAULT 1,
                description TEXT
            )
            ''')
            logger.info("Created scheduled_scans table successfully")

        # Get current columns in scans table
        cursor.execute("PRAGMA table_info(scans)")
        columns = [column[1] for column in cursor.fetchall()]

        # Add missing columns to scans table
        new_columns = {
            'progress': 'INTEGER DEFAULT 0',
            'status': 'TEXT DEFAULT "Completed"',
            'duration': 'INTEGER DEFAULT 0',
            'scan_type': 'TEXT DEFAULT "Full"',
            'scheduled_scan_id': 'INTEGER REFERENCES scheduled_scans(id)'
        }

        for column, definition in new_columns.items():
            if column not in columns:
                logger.info(f"Adding {column} column to scans table...")
                try:
                    cursor.execute(f"ALTER TABLE scans ADD COLUMN {column} {definition}")
                    if column == 'progress':
                        # Update existing completed scans to have 100% progress
                        cursor.execute("UPDATE scans SET progress = 100 WHERE status = 'Completed' OR status IS NULL")
                    logger.info(f"Successfully added {column} column")
                except sqlite3.OperationalError as e:
                    if "duplicate column name" in str(e):
                        logger.info(f"Column {column} already exists")
                    else:
                        raise

        # Check for both local and data directory databases
        data_db_path = os.path.join('data', 'scan_results.db')
        if os.path.exists(data_db_path) and os.path.abspath(data_db_path) != os.path.abspath(DB_PATH):
            logger.info(f"Found database in data directory, migrating {data_db_path}...")
            data_conn = sqlite3.connect(data_db_path)
            data_cursor = data_conn.cursor()

            # Create scheduled_scans table in data directory database
            data_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scheduled_scans'")
            if not data_cursor.fetchone():
                logger.info("Creating scheduled_scans table in data directory database...")
                data_cursor.execute('''
                CREATE TABLE scheduled_scans (
                    id INTEGER PRIMARY KEY,
                    target_url TEXT NOT NULL,
                    schedule_type TEXT NOT NULL,
                    schedule_time TEXT NOT NULL,
                    schedule_day TEXT,
                    next_scan_date TEXT,
                    last_scan_date TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT,
                    is_active INTEGER DEFAULT 1,
                    description TEXT
                )
                ''')
                logger.info("Created scheduled_scans table in data directory database successfully")

            # Add missing columns to scans table in data directory database
            data_cursor.execute("PRAGMA table_info(scans)")
            data_columns = [column[1] for column in data_cursor.fetchall()]

            for column, definition in new_columns.items():
                if column not in data_columns:
                    logger.info(f"Adding {column} column to scans table in data directory database...")
                    try:
                        data_cursor.execute(f"ALTER TABLE scans ADD COLUMN {column} {definition}")
                        if column == 'progress':
                            data_cursor.execute("UPDATE scans SET progress = 100 WHERE status = 'Completed' OR status IS NULL")
                        logger.info(f"Successfully added {column} column to data directory database")
                    except sqlite3.OperationalError as e:
                        if "duplicate column name" in str(e):
                            logger.info(f"Column {column} already exists in data directory database")
                        else:
                            raise

            data_conn.commit()
            data_conn.close()

        # Commit changes and verify
        conn.commit()

        # Verify tables and columns
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        logger.info(f"Current tables in database: {', '.join(table[0] for table in tables)}")

        cursor.execute("PRAGMA table_info(scans)")
        final_columns = [column[1] for column in cursor.fetchall()]
        logger.info(f"Current columns in scans table: {', '.join(final_columns)}")

        conn.close()
        logger.info("Database migration completed successfully")

    except Exception as e:
        logger.error(f"Error during database migration: {e}")
        logger.info(f"A backup of your original database is available at {BACKUP_PATH}")
        raise

if __name__ == '__main__':
    migrate_database()
