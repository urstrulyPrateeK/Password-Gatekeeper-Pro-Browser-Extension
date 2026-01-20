"""
Password Gatekeeper Pro
Enhanced Flask application with REST API and password strength checking
"""

from flask import Flask, render_template, request
from flask_cors import CORS

# Import API blueprint
from api import api_bp, PasswordStrengthChecker


app = Flask(__name__)

# Enable CORS for browser extension
CORS(app, resources={
    r"/api/*": {
        "origins": ["chrome-extension://*", "moz-extension://*", "http://localhost:*"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# Register API blueprint
app.register_blueprint(api_bp)


def password_strength(password):
    """
    Original password strength function
    Maintained for backward compatibility with web interface
    """
    has_upper = False
    has_lower = False
    has_digit = False
    has_special = False

    if len(password) < 8:
        return "Weak Password"

    for ch in password:
        if ch == " ":
            return "Invalid Password"
        if 'A' <= ch <= 'Z':
            has_upper = True
        elif 'a' <= ch <= 'z':
            has_lower = True
        elif '0' <= ch <= '9':
            has_digit = True
        else:
            has_special = True

    if has_upper and has_lower and has_digit and has_special:
        return "Strong Password"

    if (has_upper or has_lower) and has_digit:
        return "Medium Password"

    return "Weak Password"


@app.route('/', methods=['GET', 'POST'])
def index():
    """Original web interface - maintained for backward compatibility"""
    result = ""
    score = 0
    strength_class = ""
    
    if request.method == 'POST':
        pwd = request.form['password']
        result = password_strength(pwd)
        
        # Calculate score using new PasswordStrengthChecker
        validation = PasswordStrengthChecker.validate(pwd)
        score = validation['score']
        
        # Determine CSS class for styling
        if 'Strong' in result:
            strength_class = 'strong'
        elif 'Medium' in result:
            strength_class = 'medium'
        elif 'Weak' in result:
            strength_class = 'weak'
        else:
            strength_class = 'invalid'
    
    return render_template('index.html', 
                           result=result, 
                           score=score,
                           strength_class=strength_class)


@app.route('/extension')
def extension_info():
    """Information page about the browser extension"""
    return render_template('extension.html')


if __name__ == '__main__':
    print("\n" + "="*60)
    print("  Password Gatekeeper Pro - Server Started")
    print("="*60)
    print("\n  Web Interface: http://127.0.0.1:5000")
    print("  API Endpoint:  http://127.0.0.1:5000/api")
    print("\n  API Endpoints:")
    print("    POST /api/auth/register  - Register new account")
    print("    POST /api/auth/login     - Login and get token")
    print("    GET  /api/passwords      - Get all passwords")
    print("    POST /api/passwords      - Create password")
    print("    POST /api/passwords/sync - Sync passwords")
    print("    POST /api/password/check - Check password strength")
    print("\n" + "="*60 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)