#!/usr/bin/env python3
"""
Vulnerable Web Application for Testing
A deliberately vulnerable Flask application to test the scanner
DO NOT deploy in production - for testing only!
"""

from flask import Flask, request, render_template_string, redirect, make_response
import sqlite3
import os

app = Flask(__name__)
app.config['DEBUG'] = True

# Database setup (in-memory for testing)
def init_db():
    conn = sqlite3.connect(':memory:')
    c = conn.cursor()
    c.execute('''CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    c.execute("INSERT INTO users VALUES (1, 'admin', 'admin123')")
    c.execute("INSERT INTO users VALUES (2, 'user', 'password')")
    conn.commit()
    conn.close()

# Vulnerable HTML template
VULNERABLE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Test Application</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #d32f2f; }
        h2 { color: #333; border-bottom: 2px solid #ddd; padding-bottom: 10px; }
        form { margin: 20px 0; padding: 15px; background: #fafafa; border-radius: 4px; }
        input[type="text"], input[type="password"] { 
            padding: 8px; margin: 5px; width: 300px; border: 1px solid #ddd; 
        }
        input[type="submit"] { 
            padding: 8px 20px; background: #2196F3; color: white; border: none; cursor: pointer; 
        }
        .error { color: #d32f2f; background: #ffebee; padding: 10px; border-radius: 4px; }
        .success { color: #388e3c; background: #e8f5e9; padding: 10px; border-radius: 4px; }
        .comments { margin: 20px 0; padding: 10px; background: #f5f5f5; border-left: 4px solid #2196F3; }
        a { color: #2196F3; }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚠️ Vulnerable Test Application</h1>
        <p style="color: #666;">This application contains intentional security vulnerabilities for testing purposes.</p>
        
        <h2>1. SQL Injection Test</h2>
        <form action="/search" method="GET">
            <label>Search Users:</label><br>
            <input type="text" name="q" placeholder="Enter username or ' OR '1'='1">
            <input type="submit" value="Search">
        </form>
        
        <h2>2. XSS (Cross-Site Scripting) Test</h2>
        <form action="/comment" method="POST">
            <label>Leave a Comment:</label><br>
            <input type="text" name="comment" placeholder="<script>alert('XSS')</script>">
            <input type="submit" value="Post Comment">
        </form>
        <div class="comments">
            <strong>Comments:</strong>
            <div id="comments">{{ comments|safe }}</div>
        </div>
        
        <h2>3. CSRF (Cross-Site Request Forgery) Test</h2>
        <form action="/transfer" method="POST">
            <label>Bank Transfer (No CSRF Protection):</label><br>
            <input type="text" name="to_account" placeholder="To Account">
            <input type="text" name="amount" placeholder="Amount ($)">
            <input type="submit" value="Transfer Money">
        </form>
        
        <h2>4. Open Redirect Test</h2>
        <p>Click to test redirect: <a href="/redirect?next=/profile">Go to Profile</a></p>
        <form action="/redirect" method="GET">
            <input type="text" name="next" placeholder="Redirect URL (try //evil.com)">
            <input type="submit" value="Go">
        </form>
        
        <h2>5. Directory Traversal / LFI Test</h2>
        <form action="/view" method="GET">
            <label>View File:</label><br>
            <input type="text" name="file" value="report.txt">
            <input type="submit" value="View File">
        </form>
        
        <h2>6. Command Injection Test</h2>
        <form action="/ping" method="GET">
            <label>Network Diagnostic:</label><br>
            <input type="text" name="host" placeholder="Enter IP (try: 127.0.0.1; cat /etc/passwd)">
            <input type="submit" value="Ping">
        </form>
        
        <h2>7. Insecure Direct Object Reference</h2>
        <p>View user profiles:</p>
        <a href="/profile?id=1">Profile 1</a> | 
        <a href="/profile?id=2">Profile 2</a> | 
        <a href="/profile?id=3">Profile 3</a>
        
        <h2>8. Weak Authentication</h2>
        <form action="/login" method="POST">
            <label>Username:</label><br>
            <input type="text" name="username" placeholder="admin"><br>
            <label>Password:</label><br>
            <input type="password" name="password" placeholder="admin123"><br>
            <input type="submit" value="Login">
        </form>
        
        <hr>
        <p style="font-size: 12px; color: #999;">
            <a href="/admin">Admin Panel</a> | 
            <a href="/api/users">API Endpoint</a> | 
            <a href="/config">Config</a>
        </p>
    </div>
</body>
</html>
"""


@app.route('/')
def index():
    return render_template_string(VULNERABLE_TEMPLATE, comments="")


@app.route('/search')
def search():
    """SQL Injection vulnerability"""
    q = request.args.get('q', '')
    
    # Vulnerable: Direct string concatenation in SQL
    conn = sqlite3.connect(':memory:')
    c = conn.cursor()
    
    try:
        # Intentionally vulnerable query
        query = f"SELECT * FROM users WHERE username = '{q}'"
        c.execute(query)
        results = c.fetchall()
        
        if results:
            output = "<h3>Search Results:</h3><ul>"
            for row in results:
                output += f"<li>ID: {row[0]}, Username: {row[1]}, Password: {row[2]}</li>"
            output += "</ul>"
            return output
        else:
            return f"No results found for: {q}"
            
    except sqlite3.Error as e:
        # Error message reveals SQL structure
        return f"<div class='error'>SQL Error: {str(e)}<br>Query: {query}</div>", 500
    finally:
        conn.close()


@app.route('/comment', methods=['POST'])
def comment():
    """Stored XSS vulnerability - no output encoding"""
    comment = request.form.get('comment', '')
    
    # Vulnerable: Stores raw input without sanitization
    # In real app, this would be saved to database
    comments_html = f"<div class='comment-item'>{comment}</div>"
    
    return render_template_string(VULNERABLE_TEMPLATE, comments=comments_html)


@app.route('/transfer', methods=['POST'])
def transfer():
    """CSRF vulnerability - no token validation"""
    to_account = request.form.get('to_account')
    amount = request.form.get('amount')
    
    # Vulnerable: No CSRF token check, no session validation
    return f"""
    <div class="container">
        <h2>Transfer Status</h2>
        <div class="success">
            Successfully transferred ${amount} to account {to_account}
        </div>
        <p>No CSRF token was required for this transaction!</p>
        <a href="/">Back to Home</a>
    </div>
    """


@app.route('/redirect')
def open_redirect():
    """Open Redirect vulnerability"""
    next_url = request.args.get('next', '/')
    
    # Vulnerable: No validation of redirect target
    return redirect(next_url, code=302)


@app.route('/view')
def directory_traversal():
    """Directory Traversal / Local File Inclusion"""
    filename = request.args.get('file', 'report.txt')
    
    # Vulnerable: No path sanitization
    # Simulating file read
    sensitive_files = {
        'report.txt': 'This is a normal report file.\nContent: Sales report Q1 2024',
        '../../../etc/passwd': """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
admin:x:1000:1000:admin:/home/admin:/bin/bash""",
        '..\\..\\..\\windows\\system32\\config\\sam': '[SAM file content - Windows password hashes]',
        '../../../etc/shadow': 'root:$6$xyz$encrypted:18747:0:99999:7:::',
        'config.php': '<?php $db_password = "super_secret_123"; ?>',
    }
    
    # Check for traversal patterns
    if 'passwd' in filename or 'shadow' in filename or 'sam' in filename or 'config' in filename:
        content = sensitive_files.get(filename, f"File not found: {filename}")
        return f"<pre>{content}</pre>"
    
    return f"<h3>File: {filename}</h3><pre>{sensitive_files.get('report.txt')}</pre>"


@app.route('/ping')
def command_injection():
    """Command Injection vulnerability"""
    host = request.args.get('host', '')
    
    if not host:
        return "Please provide a host parameter"
    
    # Vulnerable: Direct command execution
    import subprocess
    
    try:
        # DANGEROUS: Direct shell command execution
        cmd = f"ping -c 4 {host}"
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
        return f"<h3>Ping Results:</h3><pre>{result}</pre>"
    except Exception as e:
        return f"<div class='error'>Command failed: {str(e)}</div>"


@app.route('/profile')
def idor():
    """Insecure Direct Object Reference"""
    user_id = request.args.get('id', '1')
    
    # Vulnerable: No authorization check
    users = {
        '1': {'name': 'Admin User', 'email': 'admin@company.com', 'ssn': '123-45-6789'},
        '2': {'name': 'John Doe', 'email': 'john@company.com', 'ssn': '987-65-4321'},
        '3': {'name': 'Jane Smith', 'email': 'jane@company.com', 'ssn': '456-78-9012'},
    }
    
    user = users.get(user_id, {'name': 'Unknown', 'email': 'N/A', 'ssn': 'N/A'})
    
    return f"""
    <div class="container">
        <h2>User Profile</h2>
        <p><strong>ID:</strong> {user_id}</p>
        <p><strong>Name:</strong> {user['name']}</p>
        <p><strong>Email:</strong> {user['email']}</p>
        <p><strong>SSN:</strong> {user['ssn']}</p>
        <p style="color: red;">Note: No authorization check - you can view any user!</p>
    </div>
    """


@app.route('/login', methods=['POST'])
def weak_auth():
    """Weak authentication - no brute force protection"""
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Vulnerable: Weak password storage, no rate limiting
    users = {
        'admin': 'admin123',
        'user': 'password',
        'test': 'test123'
    }
    
    if username in users and users[username] == password:
        response = make_response(f"""
        <div class="container">
            <h2>Login Successful</h2>
            <p>Welcome, {username}!</p>
            <p>Session token: {os.urandom(16).hex()}</p>
        </div>
        """)
        # Vulnerable: No HttpOnly flag, no Secure flag
        response.set_cookie('session', f'user_{username}', httponly=False, secure=False, samesite='None')
        response.set_cookie('is_admin', 'true' if username == 'admin' else 'false')
        return response
    else:
        return "<div class='error'>Invalid credentials</div>"


@app.route('/admin')
def admin_panel():
    """Hidden admin panel - weak access control"""
    # Vulnerable: Only checks cookie, easily forged
    is_admin = request.cookies.get('is_admin', 'false')
    
    if is_admin == 'true':
        return """
        <div class="container">
            <h1>🔐 Admin Panel</h1>
            <p>Welcome to the admin dashboard!</p>
            <ul>
                <li><a href="#">View all users</a></li>
                <li><a href="#">Database dump</a></li>
                <li><a href="#">System logs</a></li>
                <li><a href="#">Configuration</a></li>
            </ul>
        </div>
        """
    else:
        return "<div class='error'>Access Denied: Admin only</div>", 403


@app.route('/api/users')
def api_endpoint():
    """API with potential vulnerabilities"""
    # Vulnerable: No authentication, information disclosure
    users = [
        {"id": 1, "username": "admin", "password": "admin123", "api_key": "sk-1234567890abcdef"},
        {"id": 2, "username": "user", "password": "password", "api_key": "sk-0987654321fedcba"},
    ]
    
    import json
    response = make_response(json.dumps(users, indent=2))
    response.headers['Content-Type'] = 'application/json'
    # Vulnerable: Overly permissive CORS
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE'
    return response


@app.route('/config')
def config_exposure():
    """Configuration exposure"""
    config = {
        "database": {
            "host": "localhost",
            "port": 3306,
            "username": "db_admin",
            "password": "SuperSecretDBPass123!"
        },
        "api_keys": {
            "stripe": "sk_live_abcdefghijklmnopqrstuvwxyz",
            "aws": "AKIAIOSFODNN7EXAMPLE"
        },
        "debug": True,
        "secret_key": "dev_secret_key_do_not_use_in_production_12345"
    }
    
    import json
    return f"<pre>{json.dumps(config, indent=2)}</pre>"


@app.errorhandler(404)
def not_found(e):
    """Information disclosure in error pages"""
    return f"""
    <div class="container">
        <h1>404 - Page Not Found</h1>
        <p>The requested URL was not found on this server.</p>
        <hr>
        <p><strong>Debug Info:</strong></p>
        <pre>Path: {request.path}
Method: {request.method}
User-Agent: {request.headers.get('User-Agent')}
Cookies: {dict(request.cookies)}
Headers: {dict(request.headers)}</pre>
    </div>
    """, 404


if __name__ == '__main__':
    print("=" * 60)
    print("VULNERABLE TEST APPLICATION")
    print("=" * 60)
    print("WARNING: This application contains INTENTIONAL security")
    print("vulnerabilities for testing purposes only!")
    print("DO NOT expose to untrusted networks!")
    print("=" * 60)
    print("\nAccess the application at: http://localhost:5000")
    print("Test the scanner against: http://localhost:5000")
    print("\nPress Ctrl+C to stop the server")
    print("=" * 60)
    
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
