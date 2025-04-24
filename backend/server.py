import os
import random
from flask import Flask, request, jsonify
from flask_cors import CORS
from functools import wraps
import hashlib
import hmac
import secrets
import time
import threading
import socket
import re
from datetime import datetime, timedelta
import logging
from logging.handlers import RotatingFileHandler
import jwt  # PyJWT package
from werkzeug.security import generate_password_hash, check_password_hash
from rate_limiter import RateLimiter  # Custom rate limiter

# Initialize Flask app
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": ["http://localhost:34453/#/dashboard"]}})

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['TOKEN_EXPIRATION'] = 3600  # 1 hour in seconds
app.config['RATE_LIMIT'] = "100 per hour"
app.config['LOG_FILE'] = 'app.log'
app.config['MAX_LOG_SIZE'] = 10 * 1024 * 1024  # 10MB
app.config['LOG_BACKUP_COUNT'] = 3

# Setup logging
handler = RotatingFileHandler(
    app.config['LOG_FILE'],
    maxBytes=app.config['MAX_LOG_SIZE'],
    backupCount=app.config['LOG_BACKUP_COUNT']
)
handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

# Initialize rate limiter
rate_limiter = RateLimiter(app.config['RATE_LIMIT'])

# Database simulation (in production, use a real database)
users_db = {
    "mujaheed": {
        "password_hash": generate_password_hash("password123"),
        "failed_attempts": 0,
        "locked_until": None,
        "last_login": None
    }
}

tokens_db = {}
scan_results = {}
attack_status = {}
keylogger_status = {"active": False, "logs": []}
packet_capture = {"active": False, "packets": []}

# Helper Functions
def validate_ip(ip):
    """Validate IP address format"""
    pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return re.match(pattern, ip) is not None

def validate_domain(domain):
    """Validate domain name format"""
    pattern = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
    return re.match(pattern, domain, re.IGNORECASE) is not None

def validate_port(port):
    """Validate port number"""
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except ValueError:
        return False

def generate_csrf_token():
    """Generate CSRF token"""
    return secrets.token_hex(32)

def log_activity(user, action, status, details=None):
    """Log security-relevant activities"""
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "user": user,
        "action": action,
        "status": status,
        "ip": request.remote_addr,
        "details": details
    }
    app.logger.info(f"Activity: {log_entry}")

# Decorators
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        
        if not token:
            log_activity("anonymous", "access", "failed", "No token provided")
            return jsonify({"success": False, "message": "Token is missing"}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['user']
            
            # Verify token exists in our database
            if current_user not in tokens_db or tokens_db[current_user] != token:
                log_activity(current_user, "access", "failed", "Invalid token")
                return jsonify({"success": False, "message": "Token is invalid"}), 401
                
        except jwt.ExpiredSignatureError:
            log_activity(current_user, "access", "failed", "Expired token")
            return jsonify({"success": False, "message": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            log_activity("anonymous", "access", "failed", "Invalid token format")
            return jsonify({"success": False, "message": "Token is invalid"}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

def rate_limit(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = request.remote_addr
        if not rate_limiter.check(ip):
            log_activity("anonymous" if 'user' not in kwargs else kwargs['user'], 
                        "rate_limit", "blocked", f"IP: {ip}")
            return jsonify({
                "success": False, 
                "message": "Too many requests. Please try again later."
            }), 429
        return f(*args, **kwargs)
    return decorated

def validate_input(schema):
    """Validate request data against a schema"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            data = request.get_json()
            if not data:
                return jsonify({"success": False, "message": "No input data provided"}), 400
                
            errors = {}
            for field, rules in schema.items():
                if field not in data:
                    if rules.get('required', True):
                        errors[field] = "This field is required"
                    continue
                    
                value = data[field]
                if 'type' in rules and not isinstance(value, rules['type']):
                    errors[field] = f"Must be of type {rules['type'].__name__}"
                
                if 'validator' in rules and not rules['validator'](value):
                    errors[field] = rules.get('message', "Invalid value")
            
            if errors:
                return jsonify({
                    "success": False,
                    "message": "Validation failed",
                    "errors": errors
                }), 400
                
            return f(*args, **kwargs)
        return decorated
    return decorator

# Authentication Routes
@app.route('/api/login', methods=['POST'])
@rate_limit
@validate_input({
    'username': {'type': str, 'required': True},
    'password': {'type': str, 'required': True}
})
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    
    # Check if account is locked
    if username in users_db and users_db[username].get('locked_until'):
        if datetime.utcnow() < users_db[username]['locked_until']:
            remaining = (users_db[username]['locked_until'] - datetime.utcnow()).seconds
            log_activity(username, "login", "failed", "Account locked")
            return jsonify({
                "success": False,
                "message": f"Account locked. Try again in {remaining} seconds"
            }), 403
    
    # Verify credentials
    if username in users_db and check_password_hash(users_db[username]['password_hash'], password):
        # Reset failed attempts
        users_db[username]['failed_attempts'] = 0
        users_db[username]['last_login'] = datetime.utcnow()
        
        # Generate token
        token = jwt.encode({
            'user': username,
            'exp': datetime.utcnow() + timedelta(seconds=app.config['TOKEN_EXPIRATION'])
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        # Store token
        tokens_db[username] = token
        
        log_activity(username, "login", "success")
        return jsonify({
            "success": True,
            "token": token,
            "csrf_token": generate_csrf_token(),
            "message": "Login successful"
        })
    else:
        # Track failed attempts
        if username in users_db:
            users_db[username]['failed_attempts'] += 1
            
            # Lock account after 5 failed attempts
            if users_db[username]['failed_attempts'] >= 5:
                users_db[username]['locked_until'] = datetime.utcnow() + timedelta(minutes=15)
                log_activity(username, "login", "locked", "Too many failed attempts")
                return jsonify({
                    "success": False,
                    "message": "Account locked for 15 minutes due to too many failed attempts"
                }), 403
        
        log_activity(username, "login", "failed", "Invalid credentials")
        return jsonify({
            "success": False,
            "message": "Invalid username or password"
        }), 401

@app.route('/api/logout', methods=['POST'])
@token_required
def logout(user):
    if user in tokens_db:
        del tokens_db[user]
    log_activity(user, "logout", "success")
    return jsonify({"success": True, "message": "Logged out successfully"})

# Tool Routes
@app.route('/api/web_scan', methods=['POST'])
@token_required
@rate_limit
@validate_input({
    'url': {
        'type': str, 
        'required': True,
        'validator': lambda x: validate_domain(x.split('//')[-1].split('/')[0]) or validate_ip(x.split('//')[-1].split('/')[0]),
        'message': 'Invalid URL format'
    }
})
def web_scan(user):
    data = request.get_json()
    target_url = data['url']
    scan_id = hashlib.sha256(f"{target_url}{time.time()}".encode()).hexdigest()
    
    # Validate target URL
    try:
        domain = target_url.split('//')[-1].split('/')[0]
        if not (validate_domain(domain) or validate_ip(domain)):
            return jsonify({
                "success": False,
                "message": "Invalid target URL"
            }), 400
    except Exception as e:
        return jsonify({
            "success": False,
            "message": "Invalid target URL format"
        }), 400
    
    # Simulate scan in background
    def run_scan():
        time.sleep(5)  # Simulate scan time
        
        vulnerabilities = []
        if random.random() > 0.3:
            vulnerabilities.append({
                'type': 'SQL Injection',
                'severity': 'High',
                'parameter': 'username',
                'description': 'Possible SQL injection vulnerability found in login form',
                'solution': 'Use parameterized queries or ORM'
            })
        
        if random.random() > 0.5:
            vulnerabilities.append({
                'type': 'XSS',
                'severity': 'Medium',
                'parameter': 'search',
                'description': 'Cross-site scripting vulnerability detected in search parameter',
                'solution': 'Implement proper output encoding'
            })
        
        if not vulnerabilities:
            vulnerabilities.append({
                'type': 'Info',
                'severity': 'Low',
                'description': 'No critical vulnerabilities found',
                'solution': 'Regular security audits recommended'
            })
        
        scan_results[scan_id] = {
            'status': 'completed',
            'target': target_url,
            'timestamp': datetime.utcnow().isoformat(),
            'vulnerabilities': vulnerabilities,
            'scan_by': user
        }
    
    threading.Thread(target=run_scan).start()
    
    scan_results[scan_id] = {
        'status': 'scanning',
        'target': target_url,
        'timestamp': datetime.utcnow().isoformat(),
        'scan_by': user
    }
    
    log_activity(user, "web_scan", "started", f"Target: {target_url}")
    return jsonify({
        'success': True,
        'scan_id': scan_id,
        'message': 'Scan initiated'
    })

@app.route('/api/scan_status/<scan_id>', methods=['GET'])
@token_required
def scan_status(user, scan_id):
    if scan_id not in scan_results:
        return jsonify({'success': False, 'message': 'Scan ID not found'}), 404
    
    # Verify user has access to this scan
    if scan_results[scan_id].get('scan_by') != user:
        return jsonify({'success': False, 'message': 'Unauthorized access'}), 403
    
    return jsonify({
        'success': True,
        'status': scan_results[scan_id]['status'],
        'result': scan_results[scan_id] if scan_results[scan_id]['status'] == 'completed' else None
    })

@app.route('/api/ddos', methods=['POST'])
@token_required
@rate_limit
@validate_input({
    'target': {
        'type': str,
        'required': True,
        'validator': lambda x: validate_ip(x) or validate_domain(x),
        'message': 'Invalid target IP or domain'
    },
    'port': {
        'type': int,
        'required': True,
        'validator': validate_port,
        'message': 'Invalid port number'
    },
    'intensity': {
        'type': int,
        'required': True,
        'validator': lambda x: 1 <= x <= 100,
        'message': 'Intensity must be between 1 and 100'
    }
})
def ddos(user):
    data = request.get_json()
    target = data['target']
    port = data['port']
    intensity = data['intensity']
    attack_id = hashlib.sha256(f"{target}{port}{time.time()}".encode()).hexdigest()
    
    # Validate target is not in restricted list
    restricted_targets = ['example.com', '192.168.1.1']  # Add your restricted targets
    if target in restricted_targets:
        log_activity(user, "ddos", "blocked", f"Restricted target: {target}")
        return jsonify({
            'success': False,
            'message': 'Target is restricted'
        }), 403
    
    # Simulate attack
    def simulate_attack():
        attack_status[attack_id] = {
            'status': 'running',
            'target': target,
            'port': port,
            'start_time': datetime.utcnow().isoformat(),
            'packets_sent': 0,
            'initiated_by': user
        }
        
        duration = intensity * 0.1  # Simulate duration based on intensity
        end_time = time.time() + duration
        
        while time.time() < end_time:
            time.sleep(0.1)
            attack_status[attack_id]['packets_sent'] += random.randint(10, 100)
        
        attack_status[attack_id]['status'] = 'completed'
        attack_status[attack_id]['end_time'] = datetime.utcnow().isoformat()
    
    threading.Thread(target=simulate_attack).start()
    
    log_activity(user, "ddos", "started", f"Target: {target}:{port}")
    return jsonify({
        'success': True,
        'attack_id': attack_id,
        'message': 'DDoS simulation started (for educational purposes only)'
    })

# ... (similar implementations for other tools with proper validation and security)

# Error Handlers
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({
        "success": False,
        "message": "Resource not found"
    }), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"Server error: {error}")
    return jsonify({
        "success": False,
        "message": "Internal server error"
    }), 500

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({
        "success": False,
        "message": "Method not allowed"
    }), 405

if __name__ == '__main__':
    # Production configuration
    from gevent.pywsgi import WSGIServer
    from werkzeug.middleware.proxy_fix import ProxyFix
    
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
    
    http_server = WSGIServer(('0.0.0.0', 5000), app)
    app.logger.info("Server started on port 5000")
    http_server.serve_forever()