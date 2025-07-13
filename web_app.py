#!/usr/bin/env python3
"""
PUCP Cloud Orchestrator - Web Application
Aplicación web completa con menú interactivo para gestión de slices
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, g
from flask_cors import CORS
import requests
import json
import os
import logging
import sqlite3
import hashlib
import uuid
from datetime import datetime, timedelta
from functools import wraps
from microservicios.openstack_config_ssh import SSH_TUNNEL_CONFIG

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)
app.secret_key = 'pucp-cloud-orchestrator-web-secret-2025'

# Configuración
DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'pucp_cloud.db')
WEB_PORT = int(os.getenv('WEB_PORT', '8080'))

# Database functions
def get_db():
    """Obtiene conexión a la base de datos"""
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    """Cierra la conexión a la base de datos"""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Inicializa la base de datos"""
    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1
            );
            
            CREATE TABLE IF NOT EXISTS openstack_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                auth_url TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                project_name TEXT NOT NULL,
                user_domain_name TEXT DEFAULT 'Default',
                project_domain_name TEXT DEFAULT 'Default',
                region_name TEXT DEFAULT 'RegionOne',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users (id)
            );
            
            CREATE TABLE IF NOT EXISTS slices (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                topology_type TEXT,
                status TEXT DEFAULT 'draft',
                config_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            );
            
            CREATE TABLE IF NOT EXISTS openstack_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                cache_key TEXT NOT NULL,
                cache_data TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                UNIQUE(user_id, cache_key),
                FOREIGN KEY (user_id) REFERENCES users (id)
            );
        ''')
        
        # Crear usuario admin por defecto
        password_hash = hashlib.sha256('admin'.encode()).hexdigest()
        try:
            conn.execute('''
                INSERT INTO users (username, password_hash, email, role)
                VALUES (?, ?, ?, ?)
            ''', ('admin', password_hash, 'admin@pucp.edu.pe', 'admin'))
            conn.commit()
            logger.info("Default admin user created")
        except sqlite3.IntegrityError:
            logger.info("Admin user already exists")

def hash_password(password):
    """Hash de contraseña"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, password_hash):
    """Verificar contraseña"""
    return hashlib.sha256(password.encode()).hexdigest() == password_hash

def get_cached_data(cache_key, cache_ttl_minutes=30):
    """Obtiene datos del cache si están vigentes"""
    if 'user' not in session:
        return None
    
    db = get_db()
    cache_entry = db.execute('''
        SELECT cache_data FROM openstack_cache 
        WHERE user_id = ? AND cache_key = ? 
        AND datetime(expires_at) > datetime('now')
    ''', (session['user']['id'], cache_key)).fetchone()
    
    if cache_entry:
        return json.loads(cache_entry['cache_data'])
    return None

def set_cached_data(cache_key, data, cache_ttl_minutes=30):
    """Guarda datos en cache con TTL"""
    if 'user' not in session:
        return
    
    expires_at = datetime.utcnow() + timedelta(minutes=cache_ttl_minutes)
    db = get_db()
    
    db.execute('''
        INSERT OR REPLACE INTO openstack_cache 
        (user_id, cache_key, cache_data, expires_at)
        VALUES (?, ?, ?, ?)
    ''', (session['user']['id'], cache_key, json.dumps(data), expires_at.isoformat()))
    db.commit()

def clear_user_cache():
    """Limpia el cache del usuario actual"""
    if 'user' not in session:
        return
    
    db = get_db()
    db.execute('DELETE FROM openstack_cache WHERE user_id = ?', (session['user']['id'],))
    db.commit()

def create_openstack_project_for_user(username, user_id):
    """Crea un proyecto en OpenStack para el nuevo usuario usando credenciales admin"""
    try:
        # Usar credenciales de admin para crear el proyecto
        admin_credentials = {
            'auth_url': 'http://localhost:15000/v3',  # Usar túnel SSH
            'username': 'admin',
            'password': 'c3240d029b8f1374076ba9e5c88fc34e',  # Contraseña real del admin
            'project_name': 'admin',
            'user_domain_name': 'Default',
            'project_domain_name': 'Default',
            'region_name': 'RegionOne'
        }
        
        # Obtener token de admin
        auth_data = {
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": admin_credentials['username'],
                            "domain": {"name": admin_credentials['user_domain_name']},
                            "password": admin_credentials['password']
                        }
                    }
                },
                "scope": {
                    "project": {
                        "name": admin_credentials['project_name'],
                        "domain": {"name": admin_credentials['project_domain_name']}
                    }
                }
            }
        }
        
        # Obtener token de admin
        response = requests.post(
            f"{admin_credentials['auth_url']}/auth/tokens",
            json=auth_data,
            headers={'Content-Type': 'application/json'},
            timeout=30
        )
        
        if response.status_code != 201:
            logger.error(f"Failed to get admin token: {response.status_code}")
            return False
        
        admin_token = response.headers.get('X-Subject-Token')
        
        # Crear el proyecto
        project_name = f"user-{username}"
        project_data = {
            "project": {
                "name": project_name,
                "description": f"Proyecto personal para {username}",
                "enabled": True,
                "domain_id": "default"
            }
        }
        
        headers = {
            'X-Auth-Token': admin_token,
            'Content-Type': 'application/json'
        }
        
        # Crear proyecto
        project_response = requests.post(
            f"{admin_credentials['auth_url']}/projects",
            json=project_data,
            headers=headers,
            timeout=30
        )
        
        if project_response.status_code == 201:
            project_info = project_response.json()
            project_id = project_info['project']['id']
            
            # Crear usuario en OpenStack
            user_data = {
                "user": {
                    "name": username,
                    "email": f"{username}@pucp.edu.pe",
                    "password": "defaultpass123",  # Contraseña temporal
                    "enabled": True,
                    "domain_id": "default"
                }
            }
            
            user_response = requests.post(
                f"{admin_credentials['auth_url']}/users",
                json=user_data,
                headers=headers,
                timeout=30
            )
            
            if user_response.status_code == 201:
                openstack_user_info = user_response.json()
                openstack_user_id = openstack_user_info['user']['id']
                
                # Asignar rol de miembro al usuario en el proyecto
                role_assignment = requests.put(
                    f"{admin_credentials['auth_url']}/projects/{project_id}/users/{openstack_user_id}/roles/member",
                    headers=headers,
                    timeout=30
                )
                
                # Guardar credenciales de OpenStack del usuario en la base de datos
                db = get_db()
                db.execute('''
                    INSERT INTO openstack_credentials 
                    (user_id, auth_url, username, password, project_name, user_domain_name, project_domain_name, region_name)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    user_id, 
                    admin_credentials['auth_url'],
                    username,
                    "defaultpass123",  # El usuario debe cambiar esto
                    project_name,
                    'Default',
                    'Default',
                    'RegionOne'
                ))
                db.commit()
                
                logger.info(f"Created OpenStack project '{project_name}' and user '{username}'")
                return True
            else:
                logger.error(f"Failed to create OpenStack user: {user_response.status_code}")
                return False
        else:
            logger.error(f"Failed to create OpenStack project: {project_response.status_code}")
            return False
            
    except Exception as e:
        logger.error(f"Error creating OpenStack project for user {username}: {e}")
        return False

# Topologías predefinidas
PREDEFINED_TOPOLOGIES = {
    'linear': {
        'name': 'Topología Lineal',
        'description': 'Nodos conectados en serie (A → B → C → D)',
        'icon': '○—○—○—○',
        'min_nodes': 2,
        'max_nodes': 10,
        'use_cases': ['Pipelines de datos', 'Procesamiento secuencial', 'Cadenas de servicios']
    },
    'mesh': {
        'name': 'Topología Malla',
        'description': 'Todos los nodos conectados entre sí',
        'icon': '○⟷○\n⟨⟩⟨⟩\n○⟷○',
        'min_nodes': 3,
        'max_nodes': 8,
        'use_cases': ['Alta disponibilidad', 'Sistemas distribuidos', 'Redundancia completa']
    },
    'tree': {
        'name': 'Topología Árbol',
        'description': 'Estructura jerárquica en árbol',
        'icon': '    ○\n   ╱ ╲\n  ○   ○\n ╱╲  ╱╲\n○  ○ ○  ○',
        'min_nodes': 3,
        'max_nodes': 15,
        'use_cases': ['Arquitecturas jerárquicas', 'DNS', 'Sistemas de archivos']
    },
    'ring': {
        'name': 'Topología Anillo',
        'description': 'Nodos conectados en círculo',
        'icon': '○—○\n│   │\n○—○',
        'min_nodes': 3,
        'max_nodes': 12,
        'use_cases': ['Token Ring', 'Sistemas de respaldo', 'Distribución circular']
    },
    'bus': {
        'name': 'Topología Bus',
        'description': 'Todos los nodos conectados a un bus central',
        'icon': '○\n│\n○═══○═══○\n│\n○',
        'min_nodes': 3,
        'max_nodes': 20,
        'use_cases': ['Sistemas de mensajería', 'Arquitecturas centralizadas', 'Ethernet clásico']
    }
}

# VM Flavors disponibles
VM_FLAVORS = {
    'nano': {
        'vcpus': 1,
        'ram': 512,
        'disk': 1,
        'description': 'Nano (1 vCPU, 512MB RAM, 1GB disk)',
        'price': '$5/mes'
    },
    'micro': {
        'vcpus': 1,
        'ram': 1024,
        'disk': 5,
        'description': 'Micro (1 vCPU, 1GB RAM, 5GB disk)',
        'price': '$10/mes'
    },
    'small': {
        'vcpus': 1,
        'ram': 1536,
        'disk': 10,
        'description': 'Small (1 vCPU, 1.5GB RAM, 10GB disk)',
        'price': '$20/mes'
    },
    'medium': {
        'vcpus': 2,
        'ram': 2560,
        'disk': 20,
        'description': 'Medium (2 vCPU, 2.5GB RAM, 20GB disk)',
        'price': '$40/mes'
    },
    'large': {
        'vcpus': 4,
        'ram': 6144,
        'disk': 40,
        'description': 'Large (4 vCPU, 6GB RAM, 40GB disk)',
        'price': '$80/mes'
    }
}

def login_required(f):
    """Decorador para requerir login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'token' not in session or 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_user_openstack_credentials():
    """Obtiene las credenciales de OpenStack del usuario actual"""
    if 'user' not in session:
        return None
    
    db = get_db()
    credentials = db.execute(
        'SELECT * FROM openstack_credentials WHERE user_id = ? AND is_active = 1',
        (session['user']['id'],)
    ).fetchone()
    
    if credentials:
        return {
            'auth_url': credentials['auth_url'],
            'username': credentials['username'],
            'password': credentials['password'],
            'project_name': credentials['project_name'],
            'user_domain_name': credentials['user_domain_name'],
            'project_domain_name': credentials['project_domain_name'],
            'region_name': credentials['region_name']
        }
    return None

def get_openstack_token():
    """Obtiene token de autenticación de OpenStack"""
    credentials = get_user_openstack_credentials()
    if not credentials:
        return None
    
    auth_data = {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": credentials['username'],
                        "domain": {"name": credentials['user_domain_name']},
                        "password": credentials['password']
                    }
                }
            },
            "scope": {
                "project": {
                    "name": credentials['project_name'],
                    "domain": {"name": credentials['project_domain_name']}
                }
            }
        }
    }
    
    try:
        response = requests.post(
            f"{credentials['auth_url']}/auth/tokens",
            json=auth_data,
            headers={'Content-Type': 'application/json'},
            timeout=30
        )
        
        if response.status_code == 201:
            return response.headers.get('X-Subject-Token')
        else:
            logger.error(f"Failed to get OpenStack token: {response.status_code} - {response.text}")
            return None
            
    except Exception as e:
        logger.error(f"Error getting OpenStack token: {e}")
        return None

def make_openstack_request(method, service, endpoint, data=None):
    """Hace request a OpenStack API"""
    credentials = get_user_openstack_credentials()
    token = get_openstack_token()
    
    if not credentials or not token:
        logger.warning("No OpenStack credentials or token available")
        return None
    
    # URLs base para servicios OpenStack usando túneles SSH
    if credentials['auth_url'].startswith('http://localhost:15000'):
        # Usando túneles SSH - importar configuración de puertos
        from microservicios.openstack_config_ssh import OPENSTACK_SERVICE_PORTS
        service_urls = {
            'compute': f"http://localhost:{OPENSTACK_SERVICE_PORTS['nova']['local']}/v2.1",
            'image': f"http://localhost:{OPENSTACK_SERVICE_PORTS['glance']['local']}/v2",
            'network': f"http://localhost:{OPENSTACK_SERVICE_PORTS['neutron']['local']}/v2.0",
            'identity': credentials['auth_url']
        }
    else:
        # Conexión directa
        service_urls = {
            'compute': credentials['auth_url'].replace(':5000', ':8774').replace('/v3', '/v2.1'),
            'image': credentials['auth_url'].replace(':5000', ':9292').replace('/v3', '/v2'),
            'network': credentials['auth_url'].replace(':5000', ':9696').replace('/v3', '/v2.0'),
            'identity': credentials['auth_url']
        }
    
    if service not in service_urls:
        logger.error(f"Unknown service: {service}")
        return None
    
    url = f"{service_urls[service]}{endpoint}"
    headers = {
        'X-Auth-Token': token,
        'Content-Type': 'application/json'
    }
    
    try:
        if method == 'GET':
            response = requests.get(url, headers=headers, timeout=30)
        elif method == 'POST':
            response = requests.post(url, headers=headers, json=data, timeout=30)
        elif method == 'PUT':
            response = requests.put(url, headers=headers, json=data, timeout=30)
        elif method == 'DELETE':
            response = requests.delete(url, headers=headers, timeout=30)
        else:
            return None
        
        logger.info(f"OpenStack API {method} {url}: {response.status_code}")
        return response
        
    except Exception as e:
        logger.error(f"Error making OpenStack request: {e}")
        return None

def fetch_openstack_data_with_cache(endpoint, cache_key, cache_ttl=30):
    """Obtiene datos de OpenStack con cache"""
    # Intentar obtener del cache primero
    cached_data = get_cached_data(cache_key, cache_ttl)
    if cached_data:
        logger.info(f"Using cached data for {cache_key}")
        return cached_data
    
    # Si no hay cache, obtener de OpenStack
    logger.info(f"Fetching fresh data from OpenStack for {cache_key}")
    
    if endpoint == '/images':
        response = make_openstack_request('GET', 'image', '/images')
        if response and response.status_code == 200:
            data = response.json().get('images', [])
            set_cached_data(cache_key, data, cache_ttl)
            return data
            
    elif endpoint == '/flavors':
        response = make_openstack_request('GET', 'compute', '/flavors/detail')
        if response and response.status_code == 200:
            data = response.json().get('flavors', [])
            set_cached_data(cache_key, data, cache_ttl)
            return data
            
    elif endpoint == '/quotas':
        response = make_openstack_request('GET', 'compute', '/limits')
        if response and response.status_code == 200:
            limits = response.json().get('limits', {}).get('absolute', {})
            data = {
                'total_vcpus': limits.get('maxTotalCores', 0),
                'used_vcpus': limits.get('totalCoresUsed', 0),
                'total_ram': limits.get('maxTotalRAMSize', 0),
                'used_ram': limits.get('totalRAMUsed', 0),
                'total_instances': limits.get('maxTotalInstances', 0),
                'used_instances': limits.get('totalInstancesUsed', 0)
            }
            set_cached_data(cache_key, data, cache_ttl)
            return data
            
    elif endpoint == '/servers':
        response = make_openstack_request('GET', 'compute', '/servers/detail')
        if response and response.status_code == 200:
            data = response.json().get('servers', [])
            set_cached_data(cache_key, data, cache_ttl)
            return data
            
    elif endpoint == '/networks':
        response = make_openstack_request('GET', 'network', '/networks')
        if response and response.status_code == 200:
            data = response.json().get('networks', [])
            set_cached_data(cache_key, data, cache_ttl)
            return data
    
    # Si no se pudo obtener datos reales, devolver lista vacía
    logger.warning(f"Could not fetch OpenStack data for {endpoint}")
    return []

def make_api_request(method, endpoint, data=None, params=None):
    """Maneja requests a APIs internas y OpenStack con cache"""
    logger.info(f"API request: {method} {endpoint}")
    
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code
        
        def json(self):
            return self.json_data
    
    # Mapear endpoints a OpenStack APIs con cache
    if endpoint == '/images':
        data = fetch_openstack_data_with_cache('/images', 'images', 60)  # Cache por 1 hora
        return MockResponse(data, 200)
    
    elif endpoint == '/openstack/quotas/admin':
        data = fetch_openstack_data_with_cache('/quotas', 'quotas', 15)  # Cache por 15 min
        return MockResponse(data, 200)
        
    elif endpoint == '/flavors':
        data = fetch_openstack_data_with_cache('/flavors', 'flavors', 60)  # Cache por 1 hora
        return MockResponse(data, 200)
        
    elif endpoint == '/servers':
        data = fetch_openstack_data_with_cache('/servers', 'servers', 5)  # Cache por 5 min
        return MockResponse(data, 200)
        
    elif endpoint == '/networks':
        data = fetch_openstack_data_with_cache('/networks', 'networks', 30)  # Cache por 30 min
        return MockResponse(data, 200)
    
    # Para endpoints internos (slices), usar base de datos local
    if endpoint == '/slices':
        db = get_db()
        slices = db.execute(
            'SELECT * FROM slices WHERE user_id = ? ORDER BY created_at DESC',
            (session['user']['id'],)
        ).fetchall()
        return MockResponse([dict(s) for s in slices], 200)
    elif endpoint.startswith('/slices/') and endpoint.endswith('/nodes'):
        return MockResponse([], 200)
    
    return MockResponse({}, 200)

@app.route('/')
def index():
    """Página principal - redirige al dashboard si está logueado"""
    if 'token' in session and 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Página de login"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Usuario y contraseña son requeridos', 'error')
            return render_template('login.html')
        
        # Autenticación con base de datos
        db = get_db()
        user = db.execute(
            'SELECT * FROM users WHERE username = ? AND is_active = 1',
            (username,)
        ).fetchone()
        
        if user and verify_password(password, user['password_hash']):
            session['token'] = str(uuid.uuid4())
            session['user'] = {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'role': user['role']
            }
            flash(f'Bienvenido, {username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Credenciales inválidas', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Página de registro de usuarios"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        email = request.form.get('email')
        
        # Validaciones
        if not username or not password or not email:
            flash('Todos los campos son requeridos', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Las contraseñas no coinciden', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('La contraseña debe tener al menos 6 caracteres', 'error')
            return render_template('register.html')
        
        db = get_db()
        
        # Verificar si el usuario ya existe
        existing_user = db.execute(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            (username, email)
        ).fetchone()
        
        if existing_user:
            flash('El usuario o email ya existe', 'error')
            return render_template('register.html')
        
        try:
            # Crear usuario en base de datos
            password_hash = hash_password(password)
            cursor = db.execute('''
                INSERT INTO users (username, password_hash, email, role)
                VALUES (?, ?, ?, ?)
            ''', (username, password_hash, email, 'user'))
            
            user_id = cursor.lastrowid
            db.commit()
            
            # Crear proyecto en OpenStack para el nuevo usuario
            project_created = create_openstack_project_for_user(username, user_id)
            
            if project_created:
                flash(f'Usuario {username} creado exitosamente con proyecto OpenStack', 'success')
            else:
                flash(f'Usuario {username} creado, pero hubo un problema creando el proyecto OpenStack', 'warning')
            
            return redirect(url_for('login'))
            
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            flash('Error al crear el usuario', 'error')
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    """Cerrar sesión"""
    session.clear()
    flash('Sesión cerrada exitosamente', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard principal"""
    # Obtener estadísticas reales del usuario desde base de datos
    db = get_db()
    slices = db.execute(
        'SELECT * FROM slices WHERE user_id = ?',
        (session['user']['id'],)
    ).fetchall()
    
    user_stats = {
        'total_slices': len(slices),
        'active_slices': len([s for s in slices if s['status'] == 'active']),
        'draft_slices': len([s for s in slices if s['status'] == 'draft']),
        'total_vms': 0,
        'total_vcpus': 0,
        'total_ram': 0,
        'total_disk': 0
    }
    
    # Obtener VMs reales del proyecto del usuario en OpenStack
    servers = fetch_openstack_data_with_cache('/servers', 'user_servers', 5)
    if servers:
        user_stats['total_vms'] = len(servers)
        user_stats['total_vcpus'] = sum(s.get('vcpus', 0) for s in servers)
        user_stats['total_ram'] = sum(s.get('ram', 0) for s in servers)
        user_stats['total_disk'] = sum(s.get('disk', 0) for s in servers)
    
    # Obtener recursos del sistema
    system_resources = get_system_resources()
    
    # Obtener imágenes y flavors disponibles para el dashboard
    images = fetch_openstack_data_with_cache('/images', 'images', 60)
    flavors = fetch_openstack_data_with_cache('/flavors', 'flavors', 60)
    
    return render_template('dashboard.html', 
                         user=session['user'],
                         user_stats=user_stats,
                         system_resources=system_resources,
                         topologies=PREDEFINED_TOPOLOGIES,
                         recent_images=images[:5] if images else [],
                         available_flavors=flavors[:10] if flavors else [])

@app.route('/slices')
@login_required
def list_slices():
    """Listar slices del usuario"""
    response = make_api_request('GET', '/slices')
    slices = []
    
    if response and response.status_code == 200:
        slices = response.json()
    
    return render_template('slices_list.html', slices=slices)

@app.route('/slice/create')
@login_required
def create_slice_form():
    """Formulario para crear slice"""
    topology = request.args.get('topology', 'linear')
    return render_template('slice_create.html', 
                         topology=topology,
                         topologies=PREDEFINED_TOPOLOGIES,
                         flavors=VM_FLAVORS)

@app.route('/slice/create', methods=['POST'])
@login_required
def create_slice():
    """Crear nuevo slice"""
    try:
        data = request.get_json()
        
        response = make_api_request('POST', '/slices', data)
        
        if response and response.status_code == 201:
            return jsonify({'success': True, 'data': response.json()})
        else:
            error_msg = response.json().get('error', 'Error desconocido') if response else 'Error de conexión'
            return jsonify({'success': False, 'error': error_msg}), 400
            
    except Exception as e:
        logger.error(f"Error creating slice: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/slice/<slice_id>')
@login_required
def slice_detail(slice_id):
    """Detalle de un slice"""
    # Obtener información del slice
    response = make_api_request('GET', f'/slices/{slice_id}')
    if not response or response.status_code != 200:
        flash('Slice no encontrado', 'error')
        return redirect(url_for('list_slices'))
    
    slice_data = response.json()
    
    # Obtener nodos del slice
    nodes_response = make_api_request('GET', f'/slices/{slice_id}/nodes')
    nodes = nodes_response.json() if nodes_response and nodes_response.status_code == 200 else []
    
    return render_template('slice_detail.html', slice=slice_data, nodes=nodes)

@app.route('/slice/<slice_id>/edit')
@login_required
def edit_slice_form(slice_id):
    """Formulario para editar slice"""
    response = make_api_request('GET', f'/slices/{slice_id}')
    if not response or response.status_code != 200:
        flash('Slice no encontrado', 'error')
        return redirect(url_for('list_slices'))
    
    slice_data = response.json()
    return render_template('slice_edit.html', 
                         slice=slice_data,
                         flavors=VM_FLAVORS)

@app.route('/slice/<slice_id>/deploy', methods=['POST'])
@login_required
def deploy_slice(slice_id):
    """Desplegar slice"""
    response = make_api_request('POST', f'/slices/{slice_id}/deploy')
    
    if response and response.status_code == 200:
        return jsonify({'success': True, 'message': 'Slice desplegado exitosamente'})
    else:
        error_msg = response.json().get('error', 'Error de deployment') if response else 'Error de conexión'
        return jsonify({'success': False, 'error': error_msg}), 400

@app.route('/slice/<slice_id>/delete', methods=['POST'])
@login_required
def delete_slice(slice_id):
    """Eliminar slice"""
    response = make_api_request('DELETE', f'/slices/{slice_id}')
    
    if response and response.status_code == 200:
        return jsonify({'success': True, 'message': 'Slice eliminado exitosamente'})
    else:
        error_msg = response.json().get('error', 'Error al eliminar') if response else 'Error de conexión'
        return jsonify({'success': False, 'error': error_msg}), 400

@app.route('/images')
@login_required
def list_images():
    """Listar imágenes disponibles"""
    response = make_api_request('GET', '/images')
    images = response.json() if response and response.status_code == 200 else []
    
    return render_template('images_list.html', images=images)

@app.route('/images/upload')
@login_required
def upload_image_form():
    """Formulario para subir imagen"""
    return render_template('image_upload.html')

@app.route('/console/<vm_id>')
@login_required
def vm_console(vm_id):
    """Acceso a consola de VM"""
    # Obtener URL de consola y credenciales
    console_data = get_vm_console_access(vm_id)
    
    if not console_data:
        flash('No se pudo acceder a la consola de la VM', 'error')
        return redirect(url_for('list_slices'))
    
    return render_template('vm_console.html', 
                         vm_id=vm_id,
                         console_data=console_data)

@app.route('/settings')
@login_required
def settings():
    """Página de configuración del usuario"""
    db = get_db()
    credentials = db.execute(
        'SELECT * FROM openstack_credentials WHERE user_id = ? AND is_active = 1',
        (session['user']['id'],)
    ).fetchone()
    
    return render_template('settings.html', credentials=credentials)

@app.route('/settings/openstack', methods=['POST'])
@login_required
def save_openstack_credentials():
    """Guardar credenciales de OpenStack"""
    try:
        data = request.get_json()
        db = get_db()
        
        # Verificar si ya existen credenciales
        existing = db.execute(
            'SELECT id FROM openstack_credentials WHERE user_id = ? AND is_active = 1',
            (session['user']['id'],)
        ).fetchone()
        
        if existing:
            # Actualizar credenciales existentes
            db.execute('''
                UPDATE openstack_credentials 
                SET auth_url = ?, username = ?, password = ?, project_name = ?,
                    user_domain_name = ?, project_domain_name = ?, region_name = ?
                WHERE user_id = ? AND is_active = 1
            ''', (
                data['auth_url'], data['username'], data['password'],
                data['project_name'], data.get('user_domain_name', 'Default'),
                data.get('project_domain_name', 'Default'), data.get('region_name', 'RegionOne'),
                session['user']['id']
            ))
        else:
            # Crear nuevas credenciales
            db.execute('''
                INSERT INTO openstack_credentials 
                (user_id, auth_url, username, password, project_name, user_domain_name, project_domain_name, region_name)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                session['user']['id'], data['auth_url'], data['username'], data['password'],
                data['project_name'], data.get('user_domain_name', 'Default'),
                data.get('project_domain_name', 'Default'), data.get('region_name', 'RegionOne')
            ))
        
        db.commit()
        
        # Limpiar cache cuando se actualizan las credenciales
        clear_user_cache()
        
        return jsonify({'success': True, 'message': 'Credenciales guardadas exitosamente'})
        
    except Exception as e:
        logger.error(f"Error saving OpenStack credentials: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/openstack/test', methods=['POST'])
@login_required
def test_openstack_connection():
    """Probar conexión a OpenStack"""
    try:
        token = get_openstack_token()
        if token:
            # Probar una llamada simple para verificar conectividad
            response = make_openstack_request('GET', 'identity', '/auth/projects')
            if response and response.status_code == 200:
                return jsonify({
                    'success': True, 
                    'message': 'Conexión exitosa con OpenStack',
                    'projects_count': len(response.json().get('projects', []))
                })
            else:
                return jsonify({
                    'success': False, 
                    'error': 'No se pudo obtener información de proyectos'
                }), 400
        else:
            return jsonify({
                'success': False, 
                'error': 'No se pudo obtener token de autenticación'
            }), 400
            
    except Exception as e:
        logger.error(f"Error testing OpenStack connection: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/cache/clear', methods=['POST'])
@login_required
def clear_cache():
    """Limpiar cache del usuario"""
    try:
        clear_user_cache()
        return jsonify({'success': True, 'message': 'Cache limpiado exitosamente'})
    except Exception as e:
        logger.error(f"Error clearing cache: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/resources')
@login_required
def system_resources():
    """Página de recursos del sistema"""
    resources = get_system_resources()
    return render_template('system_resources.html', resources=resources)

@app.route('/api/topology/generate', methods=['POST'])
@login_required
def generate_topology():
    """Generar topología predefinida"""
    try:
        data = request.get_json()
        topology_type = data.get('topology')
        node_count = data.get('node_count', 3)
        
        if topology_type not in PREDEFINED_TOPOLOGIES:
            return jsonify({'success': False, 'error': 'Topología no válida'}), 400
        
        topology_config = generate_topology_config(topology_type, node_count)
        return jsonify({'success': True, 'topology': topology_config})
        
    except Exception as e:
        logger.error(f"Error generating topology: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

def generate_topology_config(topology_type, node_count):
    """Generar configuración de topología"""
    nodes = []
    networks = []
    
    if topology_type == 'linear':
        # Topología lineal: A → B → C → D
        for i in range(node_count):
            nodes.append({
                'name': f'node-{i+1}',
                'image': 'ubuntu-20.04',
                'flavor': 'small',
                'internet_access': i == 0  # Solo el primer nodo tiene internet
            })
        
        for i in range(node_count - 1):
            networks.append({
                'name': f'net-{i+1}',
                'cidr': f'192.168.{i+1}.0/24',
                'network_type': 'data'
            })
    
    elif topology_type == 'mesh':
        # Topología malla: todos conectados con todos
        for i in range(node_count):
            nodes.append({
                'name': f'node-{i+1}',
                'image': 'ubuntu-20.04',
                'flavor': 'small',
                'internet_access': True
            })
        
        networks.append({
            'name': 'mesh-network',
            'cidr': '192.168.100.0/24',
            'network_type': 'data'
        })
    
    elif topology_type == 'tree':
        # Topología árbol: 1 root, ramas y hojas
        nodes.append({
            'name': 'root',
            'image': 'ubuntu-20.04',
            'flavor': 'medium',
            'internet_access': True
        })
        
        branch_count = max(2, node_count // 3)
        for i in range(branch_count):
            nodes.append({
                'name': f'branch-{i+1}',
                'image': 'ubuntu-20.04',
                'flavor': 'small',
                'internet_access': False
            })
        
        remaining = node_count - 1 - branch_count
        for i in range(remaining):
            nodes.append({
                'name': f'leaf-{i+1}',
                'image': 'ubuntu-20.04',
                'flavor': 'micro',
                'internet_access': False
            })
        
        networks.append({
            'name': 'tree-network',
            'cidr': '192.168.200.0/24',
            'network_type': 'data'
        })
    
    elif topology_type == 'ring':
        # Topología anillo: cada nodo conectado al siguiente
        for i in range(node_count):
            nodes.append({
                'name': f'node-{i+1}',
                'image': 'ubuntu-20.04',
                'flavor': 'small',
                'internet_access': i == 0
            })
        
        networks.append({
            'name': 'ring-network',
            'cidr': '192.168.150.0/24',
            'network_type': 'data'
        })
    
    elif topology_type == 'bus':
        # Topología bus: un nodo central y clientes
        nodes.append({
            'name': 'bus-server',
            'image': 'ubuntu-20.04',
            'flavor': 'medium',
            'internet_access': True
        })
        
        for i in range(node_count - 1):
            nodes.append({
                'name': f'client-{i+1}',
                'image': 'ubuntu-20.04',
                'flavor': 'small',
                'internet_access': False
            })
        
        networks.append({
            'name': 'bus-network',
            'cidr': '192.168.180.0/24',
            'network_type': 'data'
        })
    
    return {
        'nodes': nodes,
        'networks': networks,
        'topology_type': topology_type,
        'description': PREDEFINED_TOPOLOGIES[topology_type]['description']
    }

def get_system_resources():
    """Obtener recursos del sistema"""
    # Obtener recursos de Linux cluster
    linux_resources = get_linux_resources()
    
    # Obtener recursos de OpenStack
    openstack_resources = get_openstack_resources()
    
    return {
        'linux': linux_resources,
        'openstack': openstack_resources,
        'timestamp': datetime.utcnow().isoformat()
    }

def get_linux_resources():
    """Obtener recursos del cluster Linux"""
    # Simulado - en producción haría requests a la API
    return {
        'total_vcpus': 16,
        'used_vcpus': 8,
        'total_ram': 32768,  # MB
        'used_ram': 16384,
        'total_disk': 400,   # GB
        'used_disk': 200,
        'servers': [
            {'name': 'server1', 'status': 'active', 'vcpus': 4, 'ram': 8192},
            {'name': 'server2', 'status': 'active', 'vcpus': 4, 'ram': 8192},
            {'name': 'server3', 'status': 'active', 'vcpus': 4, 'ram': 8192},
            {'name': 'server4', 'status': 'active', 'vcpus': 4, 'ram': 8192}
        ]
    }

def get_openstack_resources():
    """Obtener recursos de OpenStack"""
    # Obtener datos reales con cache
    quotas = fetch_openstack_data_with_cache('/quotas', 'quotas', 15)
    servers = fetch_openstack_data_with_cache('/servers', 'servers', 5)
    
    # Calcular estadísticas de uso real
    used_vcpus = sum(server.get('vcpus', 0) for server in servers if server.get('status') == 'ACTIVE')
    used_ram = sum(server.get('ram', 0) for server in servers if server.get('status') == 'ACTIVE')
    used_instances = len([s for s in servers if s.get('status') == 'ACTIVE'])
    
    return {
        'total_vcpus': quotas.get('total_vcpus', 0),
        'used_vcpus': used_vcpus,
        'total_ram': quotas.get('total_ram', 0),
        'used_ram': used_ram,
        'total_instances': quotas.get('total_instances', 0),
        'used_instances': used_instances,
        'servers': servers,
        'last_updated': datetime.utcnow().isoformat()
    }

def get_vm_console_access(vm_id):
    """Obtener acceso a consola de VM"""
    # Simular generación de token y URL de consola
    import secrets
    
    console_token = secrets.token_urlsafe(32)
    
    return {
        'vm_id': vm_id,
        'console_url': f'http://localhost:6080/vnc.html?token={console_token}',
        'console_type': 'novnc',
        'token': console_token,
        'expires_at': (datetime.utcnow() + timedelta(hours=1)).isoformat(),
        'username': 'ubuntu',
        'instructions': 'Use las credenciales por defecto de la imagen para acceder.'
    }

# Registrar función de cierre de DB
app.teardown_appcontext(close_db)

if __name__ == '__main__':
    # Inicializar base de datos
    init_db()
    logger.info(f"Starting web application on port {WEB_PORT}")
    app.run(host='0.0.0.0', port=WEB_PORT, debug=True)