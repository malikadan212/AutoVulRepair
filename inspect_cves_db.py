import sqlite3

# Connect to the database
conn = sqlite3.connect('cves.db')
cursor = conn.cursor()

# Get all tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cursor.fetchall()
print("Tables:", tables)

# Get schema for each table
for table in tables:
    table_name = table[0]
    print(f"\n{table_name} schema:")
    cursor.execute(f"PRAGMA table_info({table_name})")
    schema = cursor.fetchall()
    for col in schema:
        print(f"  {col[1]} ({col[2]})")
    
    # Get sample data
    cursor.execute(f"SELECT * FROM {table_name} LIMIT 2")
    samples = cursor.fetchall()
    print(f"\nSample data from {table_name}:")
    for sample in samples:
        print(f"  {sample}")
    
    # Get count
    cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
    count = cursor.fetchone()[0]
    print(f"\nTotal records in {table_name}: {count}")

conn.close()
