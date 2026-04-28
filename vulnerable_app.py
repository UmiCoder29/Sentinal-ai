"""
helpers/services.py
Business logic layer — receives user input, passes to db.py query builders,
then executes. Scanner must trace across files to catch this.
"""

from helpers.db import get_connection, build_user_query, build_search_query, build_order_query

def fetch_user(user_id):
    """Input comes from Flask route → here → db.py → executed here."""
    query = build_user_query(user_id)   # query built in db.py
    conn = get_connection()
    c = conn.cursor()
    try:
        # ❌ Execution point — query was tainted in db.py
        result = c.execute(query).fetchall()
        conn.close()
        return {"query": query, "result": result}
    except Exception as e:
        conn.close()
        return {"query": query, "error": str(e)}

def search_user(term):
    """Search flow — tainted in db.py, executed here."""
    query = build_search_query(term)
    conn = get_connection()
    c = conn.cursor()
    try:
        # ❌ Execution point
        result = c.execute(query).fetchall()
        conn.close()
        return {"query": query, "result": result}
    except Exception as e:
        conn.close()
        return {"query": query, "error": str(e)}

def fetch_order(user_id, item):
    """Order lookup — two tainted params from db.py."""
    query = build_order_query(user_id, item)
    conn = get_connection()
    c = conn.cursor()
    try:
        # ❌ Execution point
        result = c.execute(query).fetchall()
        conn.close()
        return {"query": query, "result": result}
    except Exception as e:
        conn.close()
        return {"query": query, "error": str(e)}