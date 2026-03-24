def load_user(cursor, email):
    return cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
