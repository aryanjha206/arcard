"""
AR Card System - Main Flask Application
Comprehensive AR card management system with MongoDB integration
"""

from flask import Flask, request, jsonify, render_template, redirect, url_for, session, send_file, send_from_directory, g
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import jwt
import qrcode
import io
import base64
import secrets
import os
from datetime import datetime, timedelta
from bson.objectid import ObjectId
from functools import wraps
import logging
from flask_cors import CORS
from flask import make_response

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(
    __name__,
    template_folder='templates'  # Use the correct template folder
)
CORS(app)  # Enable CORS for all routes

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['MONGO_URI'] = os.environ.get(
    'MONGO_URI',
    'mongodb+srv://aryankr:jhakunar1@carshowcase.j4vkf.mongodb.net/carshowcase?retryWrites=true&w=majority'
)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['JWT_SECRET'] = os.environ.get('JWT_SECRET', secrets.token_hex(32))
# Remove the default BASE_URL, will set dynamically
# app.config['BASE_URL'] = os.environ.get('BASE_URL', 'https://yourdomain.com')

# Initialize MongoDB
mongo = PyMongo(app)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Allowed file extensions for photos
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_jwt_token(user_id):
    """Generate JWT token for user authentication"""
    payload = {
        'user_id': str(user_id),
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, app.config['JWT_SECRET'], algorithm='HS256')

def verify_jwt_token(token):
    """Verify JWT token and return user_id"""
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET'], algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def login_required(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if token:
            token = token.replace('Bearer ', '')
            user_id = verify_jwt_token(token)
            if user_id:
                request.user_id = user_id
                return f(*args, **kwargs)
        
        # Check session for web interface
        if 'user_id' in session:
            request.user_id = session['user_id']
            return f(*args, **kwargs)
            
        return jsonify({'error': 'Authentication required'}), 401
    return decorated_function

@app.before_request
def set_base_url():
    # Dynamically set BASE_URL for each request if not set in env
    if not app.config.get('BASE_URL') or app.config['BASE_URL'] == 'https://yourdomain.com':
        app.config['BASE_URL'] = request.host_url.rstrip('/')

@app.route('/')
def index():
    """Main landing page"""
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'GET':
        return render_template('register.html')
    try:
        logger.info("Register endpoint hit")
        # Accept both JSON and form data
        if request.is_json:
            data = request.get_json(force=True)
        else:
            data = request.form.to_dict()
        logger.info(f"Register POST data: {data}")

        # Validate input
        required_fields = ['username', 'email', 'password']
        for field in required_fields:
            if not data.get(field):
                logger.warning(f"Registration failed: Missing field {field}")
                return jsonify({'error': f'{field} is required'}), 400

        # Check MongoDB connection
        try:
            mongo.cx.server_info()
            logger.info("MongoDB connection OK in register")
        except Exception as db_err:
            logger.error(f"MongoDB connection error in register: {db_err}")
            return jsonify({'error': f'MongoDB connection error: {str(db_err)}'}), 500

        # Check if user already exists
        existing = mongo.db.users.find_one({'$or': [
            {'username': data['username']},
            {'email': data['email']}
        ]})
        logger.info(f"Existing user lookup result: {existing}")
        if existing:
            logger.warning(f"Registration failed: User already exists ({data['username']}, {data['email']})")
            return jsonify({'error': 'User already exists'}), 400

        # Create user
        user_data = {
            'username': data['username'],
            'email': data['email'],
            'password': generate_password_hash(data['password']),
            'created_at': datetime.utcnow(),
            'is_active': True
        }
        result = mongo.db.users.insert_one(user_data)
        logger.info(f"User insert result: {result.inserted_id}")
        user_id = str(result.inserted_id)

        # Generate JWT token
        token = generate_jwt_token(user_id)

        # Set session for web interface
        session['user_id'] = user_id

        logger.info(f"New user registered: {data['username']}")

        return jsonify({
            'message': 'User registered successfully',
            'token': token,
            'user_id': user_id
        }, 201)

    except Exception as e:
        logger.error(f"Registration error: {str(e)}", exc_info=True)
        return jsonify({'error': f'Registration failed: {str(e)}'}), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'GET':
        return render_template('login.html')
    try:
        logger.info("Login endpoint hit")
        # Accept both JSON and form data
        if request.is_json:
            data = request.get_json(force=True)
        else:
            data = request.form.to_dict()
        logger.info(f"Login POST data: {data}")

        # Validate input
        if not data.get('username') or not data.get('password'):
            logger.warning("Login failed: Username and password required")
            return jsonify({'error': 'Username and password required'}), 400

        # Check MongoDB connection
        try:
            mongo.cx.server_info()
            logger.info("MongoDB connection OK in login")
        except Exception as db_err:
            logger.error(f"MongoDB connection error in login: {db_err}")
            return jsonify({'error': f'MongoDB connection error: {str(db_err)}'}), 500

        # Find user
        user = mongo.db.users.find_one({
            '$or': [
                {'username': data['username']},
                {'email': data['username']}
            ]
        })
        logger.info(f"User lookup result: {user}")

        if not user or not check_password_hash(user['password'], data['password']):
            logger.warning(f"Login failed: Invalid credentials for {data.get('username')}")
            return jsonify({'error': 'Invalid credentials'}), 401

        if not user.get('is_active', True):
            logger.warning(f"Login failed: Account disabled for {data.get('username')}")
            return jsonify({'error': 'Account is disabled'}), 401

        user_id = str(user['_id'])

        # Generate JWT token
        token = generate_jwt_token(user_id)

        # Set session for web interface
        session['user_id'] = user_id

        logger.info(f"User logged in: {user['username']}")

        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user_id': user_id
        }), 200

    except Exception as e:
        logger.error(f"Login error: {str(e)}", exc_info=True)
        return jsonify({'error': f'Login failed: {str(e)}'}), 500

@app.route('/logout', methods=['POST'])
def logout():
    """User logout"""
    session.clear()
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard with cards and QR sharing"""
    try:
        cards = list(mongo.db.cards.find({'user_id': ObjectId(request.user_id)}))
        for card in cards:
            card['_id'] = str(card['_id'])
            card['user_id'] = str(card['user_id'])
            # Add photo_url as data URL if photo_base64 exists
            if card.get('photo_base64'):
                card['photo_url'] = f"data:image/jpeg;base64,{card['photo_base64']}"
            # Ensure qr_code and qr_url are present for sharing
            card['qr_code'] = card.get('qr_code')
            card['qr_url'] = card.get('qr_url', f"{app.config['BASE_URL']}/ar/{card['card_id']}")
        return render_template('dashboard.html', cards=cards)
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        return render_template('error.html', error=str(e)), 500

@app.route('/api/profile', methods=['GET'])
@login_required
def get_profile():
    """Get user profile"""
    try:
        user = mongo.db.users.find_one({'_id': ObjectId(request.user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Remove password from response
        user.pop('password', None)
        user['_id'] = str(user['_id'])
        
        return jsonify(user), 200
        
    except Exception as e:
        logger.error(f"Profile fetch error: {str(e)}")
        return jsonify({'error': 'Failed to fetch profile'}), 500

@app.route('/api/cards', methods=['GET', 'POST'])
@login_required
def manage_cards():
    """Get all user cards or create a new card"""
    if request.method == 'GET':
        try:
            cards = list(mongo.db.cards.find({'user_id': ObjectId(request.user_id)}))
            
            # Convert ObjectIds to strings
            for card in cards:
                card['_id'] = str(card['_id'])
                card['user_id'] = str(card['user_id'])
                # Add photo_url as data URL if photo_base64 exists
                if card.get('photo_base64'):
                    card['photo_url'] = f"data:image/jpeg;base64,{card['photo_base64']}"
            
            return jsonify(cards), 200
            
        except Exception as e:
            logger.error(f"Cards fetch error: {str(e)}")
            return jsonify({'error': 'Failed to fetch cards'}), 500
    
    elif request.method == 'POST':
        try:
            logger.info("AR card creation endpoint hit")
            # Always use request.form for multipart/form-data (file upload)
            if request.content_type and request.content_type.startswith('multipart/form-data'):
                data = request.form.to_dict()
            elif request.is_json:
                data = request.get_json(force=True)
            else:
                data = {}
            logger.info(f"AR card creation POST data: {data}")

            # Validate required fields (must be present and not empty)
            required_fields = ['name', 'title', 'company']
            for field in required_fields:
                if not data.get(field) or data.get(field).strip() == "":
                    logger.warning(f"AR card creation failed: Missing field {field}")
                    return jsonify({'error': f'{field} is required'}), 400

            # Ensure user_id is present and valid
            user_id = getattr(request, 'user_id', None)
            if not user_id:
                logger.error("AR card creation failed: User not authenticated")
                return jsonify({'error': 'User not authenticated'}), 401

            # Handle photo upload (store as base64 in MongoDB)
            photo_base64 = None
            if 'photo' in request.files:
                file = request.files['photo']
                if file and file.filename and allowed_file(file.filename):
                    file_content = file.read()
                    photo_base64 = base64.b64encode(file_content).decode('utf-8')
                elif file and file.filename:
                    logger.warning("AR card creation failed: Invalid file type")
                    return jsonify({'error': 'Invalid file type'}), 400

            # Generate unique card ID
            card_id = secrets.token_urlsafe(16)

            # Create card document
            card_data = {
                'card_id': card_id,
                'user_id': ObjectId(user_id),
                'name': data['name'],
                'title': data['title'],
                'company': data['company'],
                'email': data.get('email', ''),
                'phone': data.get('phone', ''),
                'website': data.get('website', ''),
                'linkedin': data.get('linkedin', ''),
                'bio': data.get('bio', ''),
                'photo_base64': photo_base64,  # Store base64 image
                'created_at': datetime.utcnow(),
                'updated_at': datetime.utcnow(),
                'is_active': True
            }

            result = mongo.db.cards.insert_one(card_data)
            logger.info(f"AR card inserted with id: {result.inserted_id}")

            # Generate QR code
            qr_url = f"{app.config['BASE_URL']}/ar/{card_id}"
            qr_code = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr_code.add_data(qr_url)
            qr_code.make(fit=True)

            # Create QR code image
            qr_img = qr_code.make_image(fill_color="black", back_color="white")

            # Save QR code as base64
            buffer = io.BytesIO()
            qr_img.save(buffer, format='PNG')
            qr_base64 = base64.b64encode(buffer.getvalue()).decode()

            # Update card with QR code data
            mongo.db.cards.update_one(
                {'_id': result.inserted_id},
                {'$set': {'qr_code': qr_base64, 'qr_url': qr_url}}
            )

            # Fetch the created card
            created_card = mongo.db.cards.find_one({'_id': result.inserted_id})
            created_card['_id'] = str(created_card['_id'])
            created_card['user_id'] = str(created_card['user_id'])

            logger.info(f"New AR card created: {card_id} for user: {user_id}")

            return jsonify({
                'message': 'Card created successfully',
                'card': created_card
            }), 201

        except Exception as e:
            logger.error(f"AR card creation error: {str(e)}", exc_info=True)
            return jsonify({'error': f'Failed to create card: {str(e)}'}), 500

@app.route('/api/cards/<card_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def manage_single_card(card_id):
    """Get, update, or delete a specific card"""
    try:
        card = mongo.db.cards.find_one({
            'card_id': card_id,
            'user_id': ObjectId(request.user_id)
        })
        if not card:
            return jsonify({'error': 'Card not found'}), 404

        if request.method == 'GET':
            card['_id'] = str(card['_id'])
            card['user_id'] = str(card['user_id'])
            # Add photo_url as data URL if photo_base64 exists
            if card.get('photo_base64'):
                card['photo_url'] = f"data:image/jpeg;base64,{card['photo_base64']}"
            return jsonify(card), 200

        elif request.method == 'PUT':
            # Accept both JSON and multipart/form-data
            if request.content_type and request.content_type.startswith('multipart/form-data'):
                data = request.form.to_dict()
            elif request.is_json:
                data = request.get_json(force=True)
            else:
                data = {}
            update_data = {
                'updated_at': datetime.utcnow()
            }
            allowed_fields = ['name', 'title', 'company', 'email', 'phone', 'website', 'linkedin', 'bio']
            for field in allowed_fields:
                if field in data:
                    update_data[field] = data[field]
            # Handle photo update (store as base64)
            if 'photo' in request.files:
                file = request.files['photo']
                if file and file.filename and allowed_file(file.filename):
                    file_content = file.read()
                    update_data['photo_base64'] = base64.b64encode(file_content).decode('utf-8')
            mongo.db.cards.update_one(
                {'card_id': card_id, 'user_id': ObjectId(request.user_id)},
                {'$set': update_data}
            )
            logger.info(f"Card updated: {card_id}")
            return jsonify({'message': 'Card updated successfully'}), 200

        elif request.method == 'DELETE':
            # Delete photo file if exists
            if card.get('photo_url'):
                photo_path = os.path.join('static', card['photo_url'].lstrip('/static/'))
                if os.path.exists(photo_path):
                    os.remove(photo_path)
            
            mongo.db.cards.delete_one({
                'card_id': card_id,
                'user_id': ObjectId(request.user_id)
            })
            
            logger.info(f"Card deleted: {card_id}")
            
            return jsonify({'message': 'Card deleted successfully'}), 200
            
    except Exception as e:
        logger.error(f"Single card management error: {str(e)}")
        return jsonify({'error': 'Operation failed'}), 500

@app.route('/ar/<card_id>')
def ar_view(card_id):
    """AR view page for a specific card"""
    try:
        card = mongo.db.cards.find_one({'card_id': card_id, 'is_active': True})
        if not card:
            return render_template('card_not_found.html'), 404
        # Add photo_url as data URL if photo_base64 exists
        if card.get('photo_base64'):
            card['photo_url'] = f"data:image/jpeg;base64,{card['photo_base64']}"
        return render_template('ar_view.html', card=card)
    except Exception as e:
        logger.error(f"AR view error: {str(e)}")
        return render_template('error.html'), 500  # Optional: create templates/error.html

@app.route('/api/ar/<card_id>')
def get_card_data(card_id):
    """API endpoint to get card data for AR view"""
    try:
        card = mongo.db.cards.find_one({'card_id': card_id, 'is_active': True})
        if not card:
            return jsonify({'error': 'Card not found'}), 404
        # Remove sensitive data
        card.pop('_id', None)
        card.pop('user_id', None)
        card.pop('qr_code', None)
        card.pop('created_at', None)
        card.pop('updated_at', None)
        # Add photo_url as data URL if photo_base64 exists
        if card.get('photo_base64'):
            card['photo_url'] = f"data:image/jpeg;base64,{card['photo_base64']}"
        return jsonify(card), 200
    except Exception as e:
        logger.error(f"Card data fetch error: {str(e)}")
        return jsonify({'error': 'Failed to fetch card data'}), 500

@app.route('/api/qr/<card_id>')
@login_required
def get_qr_code(card_id):
    """Get QR code for a specific card"""
    try:
        card = mongo.db.cards.find_one({
            'card_id': card_id,
            'user_id': ObjectId(request.user_id)
        })
        
        if not card:
            return jsonify({'error': 'Card not found'}), 404
        
        if not card.get('qr_code'):
            return jsonify({'error': 'QR code not available'}), 404
        
        return jsonify({
            'qr_code': card['qr_code'],
            'qr_url': card.get('qr_url')
        }), 200
        
    except Exception as e:
        logger.error(f"QR code fetch error: {str(e)}")
        return jsonify({'error': 'Failed to fetch QR code'}), 500

@app.route('/api/qr/<card_id>/download')
@login_required
def download_qr_code(card_id):
    """Download QR code image for a specific card"""
    try:
        card = mongo.db.cards.find_one({
            'card_id': card_id,
            'user_id': ObjectId(request.user_id)
        })
        if not card or not card.get('qr_code'):
            return jsonify({'error': 'QR code not available'}), 404

        qr_bytes = base64.b64decode(card['qr_code'])
        response = make_response(qr_bytes)
        response.headers.set('Content-Type', 'image/png')
        response.headers.set('Content-Disposition', f'attachment; filename=qr_{card_id}.png')
        return response
    except Exception as e:
        logger.error(f"QR code download error: {str(e)}")
        return jsonify({'error': 'Failed to download QR code'}), 500

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404  # Optional: create templates/404.html

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500  # Optional: create templates/500.html

if __name__ == '__main__':
    # MongoDB connectivity check
    try:
        mongo.cx.server_info()
        logger.info("MongoDB connection successful")
    except Exception as e:
        logger.error(f"MongoDB connection failed: {str(e)}")
        raise SystemExit("MongoDB connection failed. Check your MONGO_URI.")

    # Create indexes for better performance
    try:
        mongo.db.users.create_index('username', unique=True)
        mongo.db.users.create_index('email', unique=True)
        mongo.db.cards.create_index('card_id', unique=True)
        mongo.db.cards.create_index('user_id')
        logger.info("Database indexes created successfully")
    except Exception as e:
        logger.error(f"Index creation error: {str(e)}")
    
    # On Vercel, the app will be served via wsgi.py, so this block is ignored.