import sqlite3

# This file contains DELIBERATE SQL injection vulnerabilities for testing the scanner.

def login_vulnerable_concatenation(username, password):
    db = sqlite3.connect("app.db")
    cursor = db.cursor()
    
    # OBVIOUS VULNERABILITY: String concatenation with user input
    # An attacker can enter: admin' --
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    print(f"Executing: {query}")
    cursor.execute(query)
    return cursor.fetchone()

def get_profile_vulnerable_fstring(user_id):
    db = sqlite3.connect("app.db")
    cursor = db.cursor()
    
    # OBVIOUS VULNERABILITY: F-string used directly in execute
    # An attacker can enter: 1 OR 1=1
    cursor.execute(f"SELECT secret_data FROM profiles WHERE id = {user_id}")
    return cursor.fetchone()

def search_vulnerable_legacy_format(search_term):
    db = sqlite3.connect("app.db")
    cursor = db.cursor()
    
    # OBVIOUS VULNERABILITY: % formatting
    query = "SELECT * FROM products WHERE name LIKE '%%%s%%'" % search_term
    cursor.execute(query)
    
    # OBVIOUS VULNERABILITY: .format()
    risky_query = "SELECT * FROM logs WHERE level = '{}'".format(search_term)
    cursor.execute(risky_query)

def admin_delete_vulnerable_variable(user_id):
    db = sqlite3.connect("app.db")
    cursor = db.cursor()
    
    # OBVIOUS VULNERABILITY: Tainted variable tracking
    # The query is built in a variable and executed later.
    sql_command = "DELETE FROM users WHERE id = " + str(user_id)
    
    # ... some logic ...
    
    cursor.execute(sql_command)
    db.commit()

def common_injection_patterns_test():
    db = sqlite3.connect("app.db")
    cursor = db.cursor()
    
    # These hardcoded strings simulate common SQL injection patterns
    # that an attacker might try to inject, or a developer might mistakenly hardcode.
    
    # Tautology
    cursor.execute("SELECT * FROM users WHERE id = 1 OR '1'='1'")
    
    # Commenting out the rest of the query
    cursor.execute("SELECT * FROM secrets WHERE id = 5 -- hidden comment")
    
    # Union-based injection
    cursor.execute("SELECT name FROM users UNION SELECT password FROM users")
    
    # Time-based blind injection
    cursor.execute("SELECT * FROM products WHERE id = 1 AND SLEEP(10)")

def safe_query_examples(user_id, name):
    db = sqlite3.connect("app.db")
    cursor = db.cursor()
    
    # SAFE: Parameterized queries (The correct way)
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    cursor.execute("UPDATE users SET name = ? WHERE id = ?", (name, user_id))
    
    # SAFE: Constant strings
    cursor.execute("SELECT count(*) FROM users")
