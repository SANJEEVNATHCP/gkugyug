# Smart IoT Water Monitoring System - Backend API
# Flask REST API with SQLite Database

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import jwt
import os
from functools import wraps

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///water_monitoring.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Enable CORS
CORS(app)

# Initialize database
db = SQLAlchemy(app)

# ==================== DATABASE MODELS ====================

class User(db.Model):
    """User model for authentication"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')  # user, admin, health_worker
    phone = db.Column(db.String(15))
    village = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class WaterQualityData(db.Model):
    """Water quality readings from IoT sensors"""
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    
    # Water parameters
    ph_level = db.Column(db.Float)
    turbidity = db.Column(db.Float)
    tds = db.Column(db.Float)  # Total Dissolved Solids
    temperature = db.Column(db.Float)
    dissolved_oxygen = db.Column(db.Float)
    
    # Contamination status
    is_contaminated = db.Column(db.Boolean, default=False)
    contamination_level = db.Column(db.String(20))  # safe, warning, danger
    ai_prediction_score = db.Column(db.Float)
    
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Alert(db.Model):
    """Water contamination alerts"""
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    alert_type = db.Column(db.String(50))  # contamination, sensor_error, low_battery
    severity = db.Column(db.String(20))  # low, medium, high, critical
    message = db.Column(db.Text)
    is_resolved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)

class Device(db.Model):
    """IoT monitoring devices/boats"""
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(50), unique=True, nullable=False)
    device_name = db.Column(db.String(100))
    location = db.Column(db.String(100))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    status = db.Column(db.String(20), default='active')  # active, inactive, maintenance
    battery_level = db.Column(db.Float)
    last_sync = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ContactRequest(db.Model):
    """Contact form submissions"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(15))
    interest = db.Column(db.String(50))
    message = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')  # pending, contacted, resolved
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ==================== AUTHENTICATION DECORATOR ====================

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token.split(' ')[1]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
        except:
            return jsonify({'message': 'Token is invalid'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

# ==================== SETUP ROUTE ====================

@app.route('/api/setup', methods=['POST'])
def setup_database():
    """Initialize database with admin user and sample data"""
    try:
        # Check if already setup
        if User.query.count() > 0:
            return jsonify({'message': 'Database already initialized', 'status': 'already_setup'}), 200
        
        # Create admin user
        admin = User(
            username='admin',
            email='admin@smartwater.com',
            role='admin',
            village='Tech Hub'
        )
        admin.set_password('admin123')
        db.session.add(admin)
        
        # Create sample devices
        devices = [
            Device(device_id='BOAT001', device_name='Ganga Monitor 1', location='Varanasi', 
                   latitude=25.3176, longitude=82.9739, battery_level=95),
            Device(device_id='BOAT002', device_name='Krishna Monitor 1', location='Vijayawada', 
                   latitude=16.5062, longitude=80.6480, battery_level=88),
            Device(device_id='BOAT003', device_name='Yamuna Monitor 1', location='Delhi', 
                   latitude=28.7041, longitude=77.1025, battery_level=92)
        ]
        for device in devices:
            db.session.add(device)
        
        # Create sample water data
        sample_data = [
            WaterQualityData(device_id='BOAT001', location='Varanasi', ph_level=7.2, turbidity=3.5, 
                            tds=450, temperature=25.5, dissolved_oxygen=7.8, contamination_level='safe'),
            WaterQualityData(device_id='BOAT002', location='Vijayawada', ph_level=6.8, turbidity=8.2, 
                            tds=620, temperature=27.3, dissolved_oxygen=5.5, contamination_level='warning', 
                            is_contaminated=True),
            WaterQualityData(device_id='BOAT003', location='Delhi', ph_level=8.9, turbidity=12.5, 
                            tds=780, temperature=28.1, dissolved_oxygen=4.2, contamination_level='danger', 
                            is_contaminated=True)
        ]
        for data in sample_data:
            db.session.add(data)
        
        # Create sample alert
        alert = Alert(
            device_id='BOAT003',
            location='Delhi',
            alert_type='contamination',
            severity='high',
            message='High contamination detected. pH: 8.9, Turbidity: 12.5 NTU'
        )
        db.session.add(alert)
        
        db.session.commit()
        
        return jsonify({
            'message': 'Database initialized successfully',
            'status': 'success',
            'admin_username': 'admin',
            'admin_password': 'admin123'
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Setup failed: {str(e)}'}), 500

# ==================== AUTHENTICATION ROUTES ====================

@app.route('/api/register', methods=['POST'])
def register():
    """Register a new user"""
    data = request.get_json()
    
    # Validate input
    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing required fields'}), 400
    
    # Check if user already exists
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Username already exists'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email already exists'}), 400
    
    # Create new user
    user = User(
        username=data['username'],
        email=data['email'],
        phone=data.get('phone'),
        village=data.get('village'),
        role=data.get('role', 'user')
    )
    user.set_password(data['password'])
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({
        'message': 'User registered successfully',
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email
        }
    }), 201

@app.route('/api/login', methods=['POST'])
def login():
    """User login"""
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Missing credentials'}), 400
    
    user = User.query.filter_by(username=data['username']).first()
    
    if not user or not user.check_password(data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401
    
    # Generate JWT token
    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm="HS256")
    
    return jsonify({
        'message': 'Login successful',
        'token': token,
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role
        }
    }), 200

# ==================== WATER QUALITY DATA ROUTES ====================

@app.route('/api/water-data', methods=['GET'])
def get_water_data():
    """Get all water quality data with optional filters"""
    # Query parameters
    location = request.args.get('location')
    device_id = request.args.get('device_id')
    limit = request.args.get('limit', 100, type=int)
    
    query = WaterQualityData.query
    
    if location:
        query = query.filter_by(location=location)
    if device_id:
        query = query.filter_by(device_id=device_id)
    
    data = query.order_by(WaterQualityData.timestamp.desc()).limit(limit).all()
    
    return jsonify({
        'count': len(data),
        'data': [{
            'id': d.id,
            'device_id': d.device_id,
            'location': d.location,
            'ph_level': d.ph_level,
            'turbidity': d.turbidity,
            'tds': d.tds,
            'temperature': d.temperature,
            'dissolved_oxygen': d.dissolved_oxygen,
            'is_contaminated': d.is_contaminated,
            'contamination_level': d.contamination_level,
            'ai_prediction_score': d.ai_prediction_score,
            'timestamp': d.timestamp.isoformat()
        } for d in data]
    }), 200

@app.route('/api/water-data', methods=['POST'])
@token_required
def add_water_data(current_user):
    """Add new water quality reading (IoT device endpoint)"""
    data = request.get_json()
    
    # AI prediction simulation (replace with actual ML model)
    ai_score = predict_contamination(data)
    contamination_level = get_contamination_level(data, ai_score)
    
    reading = WaterQualityData(
        device_id=data.get('device_id'),
        location=data.get('location'),
        latitude=data.get('latitude'),
        longitude=data.get('longitude'),
        ph_level=data.get('ph_level'),
        turbidity=data.get('turbidity'),
        tds=data.get('tds'),
        temperature=data.get('temperature'),
        dissolved_oxygen=data.get('dissolved_oxygen'),
        is_contaminated=contamination_level in ['warning', 'danger'],
        contamination_level=contamination_level,
        ai_prediction_score=ai_score
    )
    
    db.session.add(reading)
    
    # Create alert if contamination detected
    if contamination_level in ['warning', 'danger']:
        alert = Alert(
            device_id=data.get('device_id'),
            location=data.get('location'),
            alert_type='contamination',
            severity='high' if contamination_level == 'danger' else 'medium',
            message=f'Water contamination detected. AI prediction score: {ai_score:.2f}'
        )
        db.session.add(alert)
    
    db.session.commit()
    
    return jsonify({
        'message': 'Data added successfully',
        'contamination_level': contamination_level,
        'ai_score': ai_score
    }), 201

@app.route('/api/water-data/latest', methods=['GET'])
def get_latest_readings():
    """Get latest readings from all devices"""
    subquery = db.session.query(
        WaterQualityData.device_id,
        db.func.max(WaterQualityData.timestamp).label('max_timestamp')
    ).group_by(WaterQualityData.device_id).subquery()
    
    latest_readings = db.session.query(WaterQualityData).join(
        subquery,
        db.and_(
            WaterQualityData.device_id == subquery.c.device_id,
            WaterQualityData.timestamp == subquery.c.max_timestamp
        )
    ).all()
    
    return jsonify({
        'count': len(latest_readings),
        'data': [{
            'device_id': d.device_id,
            'location': d.location,
            'ph_level': d.ph_level,
            'turbidity': d.turbidity,
            'tds': d.tds,
            'temperature': d.temperature,
            'contamination_level': d.contamination_level,
            'timestamp': d.timestamp.isoformat()
        } for d in latest_readings]
    }), 200

# ==================== ALERTS ROUTES ====================

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get all alerts"""
    status = request.args.get('status')  # active or resolved
    
    query = Alert.query
    
    if status == 'active':
        query = query.filter_by(is_resolved=False)
    elif status == 'resolved':
        query = query.filter_by(is_resolved=True)
    
    alerts = query.order_by(Alert.created_at.desc()).all()
    
    return jsonify({
        'count': len(alerts),
        'alerts': [{
            'id': a.id,
            'device_id': a.device_id,
            'location': a.location,
            'alert_type': a.alert_type,
            'severity': a.severity,
            'message': a.message,
            'is_resolved': a.is_resolved,
            'created_at': a.created_at.isoformat(),
            'resolved_at': a.resolved_at.isoformat() if a.resolved_at else None
        } for a in alerts]
    }), 200

@app.route('/api/alerts/<int:alert_id>/resolve', methods=['PUT'])
@token_required
def resolve_alert(current_user, alert_id):
    """Mark an alert as resolved"""
    alert = Alert.query.get_or_404(alert_id)
    alert.is_resolved = True
    alert.resolved_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({'message': 'Alert resolved successfully'}), 200

# ==================== DEVICES ROUTES ====================

@app.route('/api/devices', methods=['GET'])
def get_devices():
    """Get all registered devices"""
    devices = Device.query.all()
    
    return jsonify({
        'count': len(devices),
        'devices': [{
            'id': d.id,
            'device_id': d.device_id,
            'device_name': d.device_name,
            'location': d.location,
            'latitude': d.latitude,
            'longitude': d.longitude,
            'status': d.status,
            'battery_level': d.battery_level,
            'last_sync': d.last_sync.isoformat() if d.last_sync else None
        } for d in devices]
    }), 200

@app.route('/api/devices', methods=['POST'])
@token_required
def register_device(current_user):
    """Register a new monitoring device"""
    data = request.get_json()
    
    device = Device(
        device_id=data.get('device_id'),
        device_name=data.get('device_name'),
        location=data.get('location'),
        battery_level=data.get('battery_level', 100)
    )
    
    db.session.add(device)
    db.session.commit()
    
    return jsonify({'message': 'Device registered successfully'}), 201

@app.route('/api/devices/<device_id>/sync', methods=['PUT'])
def sync_device(device_id):
    """Update device last sync time"""
    device = Device.query.filter_by(device_id=device_id).first_or_404()
    device.last_sync = datetime.utcnow()
    device.battery_level = request.json.get('battery_level', device.battery_level)
    db.session.commit()
    
    return jsonify({'message': 'Device synced successfully'}), 200

# ==================== CONTACT ROUTES ====================

@app.route('/api/contact', methods=['POST'])
def submit_contact():
    """Submit contact form"""
    data = request.get_json()
    
    contact = ContactRequest(
        name=data.get('name'),
        email=data.get('email'),
        phone=data.get('phone'),
        interest=data.get('interest'),
        message=data.get('message')
    )
    
    db.session.add(contact)
    db.session.commit()
    
    return jsonify({'message': 'Contact request submitted successfully'}), 201

@app.route('/api/contact', methods=['GET'])
@token_required
def get_contacts(current_user):
    """Get all contact requests (admin only)"""
    if current_user.role != 'admin':
        return jsonify({'message': 'Admin access required'}), 403
    
    contacts = ContactRequest.query.order_by(ContactRequest.created_at.desc()).all()
    
    return jsonify({
        'count': len(contacts),
        'contacts': [{
            'id': c.id,
            'name': c.name,
            'email': c.email,
            'phone': c.phone,
            'interest': c.interest,
            'message': c.message,
            'status': c.status,
            'created_at': c.created_at.isoformat()
        } for c in contacts]
    }), 200

# ==================== STATISTICS ROUTES ====================

@app.route('/api/stats', methods=['GET'])
def get_statistics():
    """Get system statistics"""
    total_devices = Device.query.count()
    active_alerts = Alert.query.filter_by(is_resolved=False).count()
    total_readings = WaterQualityData.query.count()
    contaminated_sites = WaterQualityData.query.filter(
        WaterQualityData.contamination_level.in_(['warning', 'danger'])
    ).count()
    
    # Recent readings
    recent_readings = WaterQualityData.query.order_by(
        WaterQualityData.timestamp.desc()
    ).limit(10).all()
    
    return jsonify({
        'total_devices': total_devices,
        'active_alerts': active_alerts,
        'total_readings': total_readings,
        'contaminated_sites': contaminated_sites,
        'recent_activity': [{
            'location': r.location,
            'contamination_level': r.contamination_level,
            'timestamp': r.timestamp.isoformat()
        } for r in recent_readings]
    }), 200

# ==================== HELPER FUNCTIONS ====================

def predict_contamination(data):
    """
    AI contamination prediction (simplified simulation)
    In production, replace with actual ML model
    """
    score = 0.0
    
    # pH should be between 6.5 and 8.5
    ph = data.get('ph_level', 7.0)
    if ph < 6.5 or ph > 8.5:
        score += 0.3
    
    # Turbidity should be low (< 5 NTU)
    turbidity = data.get('turbidity', 0)
    if turbidity > 5:
        score += 0.25
    
    # TDS should be < 500 ppm
    tds = data.get('tds', 0)
    if tds > 500:
        score += 0.25
    
    # Dissolved oxygen should be > 6 mg/L
    do = data.get('dissolved_oxygen', 10)
    if do < 6:
        score += 0.2
    
    return min(score, 1.0)

def get_contamination_level(data, ai_score):
    """Determine contamination level based on AI score"""
    if ai_score < 0.3:
        return 'safe'
    elif ai_score < 0.6:
        return 'warning'
    else:
        return 'danger'

# ==================== STATIC FILES ====================

@app.route('/')
def serve_index():
    """Serve the dashboard HTML page"""
    return send_from_directory('.', 'dashboard.html')

@app.route('/<path:path>')
def serve_static(path):
    """Serve static files"""
    return send_from_directory('.', path)

# ==================== INITIALIZE DATABASE ====================

@app.before_request
def create_tables():
    """Create database tables if they don't exist"""
    db.create_all()
    app.before_request_funcs[None].remove(create_tables)

# ==================== RUN APPLICATION ====================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("Database initialized successfully!")
        
        # Create sample data if database is empty
        if User.query.count() == 0:
            # Create admin user
            admin = User(
                username='admin',
                email='admin@smartwater.com',
                role='admin',
                village='Tech Hub'
            )
            admin.set_password('admin123')
            db.session.add(admin)
            
            # Create sample devices
            devices = [
                Device(device_id='BOAT001', device_name='Ganga Monitor 1', location='Varanasi', 
                       latitude=25.3176, longitude=82.9739, battery_level=95),
                Device(device_id='BOAT002', device_name='Krishna Monitor 1', location='Vijayawada', 
                       latitude=16.5062, longitude=80.6480, battery_level=88),
                Device(device_id='BOAT003', device_name='Yamuna Monitor 1', location='Delhi', 
                       latitude=28.7041, longitude=77.1025, battery_level=92)
            ]
            for device in devices:
                db.session.add(device)
            
            # Create sample water data
            sample_data = [
                WaterQualityData(device_id='BOAT001', location='Varanasi', ph_level=7.2, turbidity=3.5, 
                                tds=450, temperature=25.5, dissolved_oxygen=7.8, contamination_level='safe'),
                WaterQualityData(device_id='BOAT002', location='Vijayawada', ph_level=6.8, turbidity=8.2, 
                                tds=620, temperature=27.3, dissolved_oxygen=5.5, contamination_level='warning', 
                                is_contaminated=True),
                WaterQualityData(device_id='BOAT003', location='Delhi', ph_level=8.9, turbidity=12.5, 
                                tds=780, temperature=28.1, dissolved_oxygen=4.2, contamination_level='danger', 
                                is_contaminated=True)
            ]
            for data in sample_data:
                db.session.add(data)
            
            # Create sample alert
            alert = Alert(
                device_id='BOAT003',
                location='Delhi',
                alert_type='contamination',
                severity='high',
                message='High contamination detected. pH: 8.9, Turbidity: 12.5 NTU'
            )
            db.session.add(alert)
            
            db.session.commit()
            print("Sample data created successfully!")
    
    print("\n" + "="*60)
    print("🚀 Smart IoT Water Monitoring System - Backend API")
    print("="*60)
    print("Server running on: http://localhost:5000")
    print("\nAPI Endpoints:")
    print("  POST /api/register        - Register new user")
    print("  POST /api/login           - User login")
    print("  GET  /api/water-data      - Get water quality data")
    print("  POST /api/water-data      - Add water reading (auth required)")
    print("  GET  /api/alerts          - Get alerts")
    print("  GET  /api/devices         - Get all devices")
    print("  POST /api/contact         - Submit contact form")
    print("  GET  /api/stats           - Get statistics")
    print("\nDefault Admin Login:")
    print("  Username: admin")
    print("  Password: admin123")
    print("="*60 + "\n")
    
    # Get local IP address
    import socket
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    
    print(f"\n🌐 ACCESS DASHBOARD FROM OTHER DEVICES:")
    print(f"   Local IP: http://{local_ip}:5000")
    print(f"   Localhost: http://localhost:5000")
    print(f"   Network: http://0.0.0.0:5000\n")
    
    # host='0.0.0.0' makes the server accessible from other devices on the network
    app.run(debug=True, host='0.0.0.0', port=5000)
