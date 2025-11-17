"""
Export MySQL database schema and sample data
For submission purposes
"""
import os
import pymysql
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()


def export_database(output_file: str = "database_export.sql"):
    """Export database schema and data to SQL file"""
    
    # Connect to database
    connection = pymysql.connect(
        host=os.getenv('DB_HOST', 'localhost'),
        port=int(os.getenv('DB_PORT', 3306)),
        user=os.getenv('DB_USER', 'scuser'),
        password=os.getenv('DB_PASSWORD', 'scpass'),
        database=os.getenv('DB_NAME', 'securechat'),
        charset='utf8mb4'
    )
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            # Write header
            f.write("-- SecureChat Database Export\n")
            f.write(f"-- Generated: {datetime.now()}\n")
            f.write("-- Database: securechat\n\n")
            
            f.write("-- Drop and create database\n")
            f.write("DROP DATABASE IF EXISTS securechat;\n")
            f.write("CREATE DATABASE securechat;\n")
            f.write("USE securechat;\n\n")
            
            with connection.cursor() as cursor:
                # Export schema
                f.write("-- Table structure for `users`\n")
                cursor.execute("SHOW CREATE TABLE users")
                result = cursor.fetchone()
                f.write(result[1] + ";\n\n")
                
                # Export data
                f.write("-- Sample data for `users`\n")
                cursor.execute("SELECT * FROM users LIMIT 10")
                users = cursor.fetchall()
                
                if users:
                    f.write("INSERT INTO users (id, email, username, salt, pwd_hash, created_at) VALUES\n")
                    for i, user in enumerate(users):
                        # Format the values
                        id_val = user[0]
                        email = user[1].replace("'", "\\'")
                        username = user[2].replace("'", "\\'")
                        salt = connection.escape(user[3]).decode()
                        pwd_hash = user[4]
                        created_at = user[5].strftime('%Y-%m-%d %H:%M:%S')
                        
                        line = f"({id_val}, '{email}', '{username}', {salt}, '{pwd_hash}', '{created_at}')"
                        if i < len(users) - 1:
                            f.write(line + ",\n")
                        else:
                            f.write(line + ";\n")
                else:
                    f.write("-- No sample data available\n")
                
                # Get statistics
                cursor.execute("SELECT COUNT(*) FROM users")
                count = cursor.fetchone()[0]
                
                f.write(f"\n-- Total users in database: {count}\n")
        
        print(f"✓ Database exported successfully to: {output_file}")
        print(f"  Total users: {count}")
        
    finally:
        connection.close()


def print_database_info():
    """Print database information and sample records"""
    connection = pymysql.connect(
        host=os.getenv('DB_HOST', 'localhost'),
        port=int(os.getenv('DB_PORT', 3306)),
        user=os.getenv('DB_USER', 'scuser'),
        password=os.getenv('DB_PASSWORD', 'scpass'),
        database=os.getenv('DB_NAME', 'securechat'),
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )
    
    try:
        with connection.cursor() as cursor:
            print("\n" + "="*70)
            print("DATABASE INFORMATION")
            print("="*70)
            
            # Table structure
            cursor.execute("DESCRIBE users")
            columns = cursor.fetchall()
            
            print("\nTable: users")
            print("-" * 70)
            print(f"{'Field':<20} {'Type':<20} {'Null':<6} {'Key':<6} {'Extra':<20}")
            print("-" * 70)
            for col in columns:
                print(f"{col['Field']:<20} {col['Type']:<20} {col['Null']:<6} {col['Key']:<6} {col['Extra']:<20}")
            
            # Sample records
            cursor.execute("SELECT id, email, username, created_at FROM users LIMIT 5")
            users = cursor.fetchall()
            
            if users:
                print("\n" + "="*70)
                print("SAMPLE RECORDS (Passwords hidden for security)")
                print("="*70)
                print(f"{'ID':<5} {'Email':<30} {'Username':<20} {'Created':<20}")
                print("-" * 70)
                for user in users:
                    print(f"{user['id']:<5} {user['email']:<30} {user['username']:<20} {str(user['created_at']):<20}")
            else:
                print("\nNo records found in database")
            
            # Statistics
            cursor.execute("SELECT COUNT(*) as total FROM users")
            total = cursor.fetchone()['total']
            print(f"\nTotal Users: {total}")
            print("="*70)
    
    finally:
        connection.close()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Export database")
    parser.add_argument("--output", default="database_export.sql", help="Output SQL file")
    parser.add_argument("--info", action="store_true", help="Print database info")
    
    args = parser.parse_args()
    
    if args.info:
        print_database_info()
    else:
        export_database(args.output)
