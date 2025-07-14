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
from microservicios.openstack_config_ssh import SSH_TUNNEL_CONFIG, OPENSTACK_SERVICE_PORTS

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
                
                # Primero obtener el ID del rol de admin
                roles_response = requests.get(
                    f"{admin_credentials['auth_url']}/roles?name=admin",
                    headers=headers,
                    timeout=30
                )
                
                admin_role_id = None
                if roles_response.status_code == 200:
                    roles_data = roles_response.json()
                    if roles_data['roles']:
                        admin_role_id = roles_data['roles'][0]['id']
                
                # Si no existe rol admin, usar member como fallback
                if not admin_role_id:
                    member_roles_response = requests.get(
                        f"{admin_credentials['auth_url']}/roles?name=member",
                        headers=headers,
                        timeout=30
                    )
                    if member_roles_response.status_code == 200:
                        member_roles_data = member_roles_response.json()
                        if member_roles_data['roles']:
                            admin_role_id = member_roles_data['roles'][0]['id']
                
                # Asignar rol de admin al usuario en el proyecto
                if admin_role_id:
                    role_assignment = requests.put(
                        f"{admin_credentials['auth_url']}/projects/{project_id}/users/{openstack_user_id}/roles/{admin_role_id}",
                        headers=headers,
                        timeout=30
                    )
                    
                    if role_assignment.status_code in [200, 204]:
                        logger.info(f"Successfully assigned admin role to user {username} in project {project_name}")
                    else:
                        logger.error(f"Failed to assign admin role: {role_assignment.status_code}")
                        logger.error(f"Response: {role_assignment.text}")
                else:
                    logger.error("Could not find admin or member role in OpenStack")
                
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
    
    try:
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
    except Exception as e:
        logger.error(f"Error getting OpenStack credentials: {e}")
    
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
    print(f"[FETCH] Starting fetch for {endpoint} (cache_key: {cache_key})")
    
    try:
        # Intentar obtener del cache primero
        cached_data = get_cached_data(cache_key, cache_ttl)
        if cached_data:
            print(f"[FETCH] Using cached data for {cache_key}")
            logger.info(f"Using cached data for {cache_key}")
            return cached_data
        
        # Si no hay cache, obtener de OpenStack
        print(f"[FETCH] No cache found, fetching fresh data from OpenStack for {cache_key}")
        logger.info(f"Fetching fresh data from OpenStack for {cache_key}")
        
        # Verificar credenciales primero
        credentials = get_user_openstack_credentials()
        token = get_openstack_token()
        print(f"[FETCH] Credentials available: {credentials is not None}")
        print(f"[FETCH] Token available: {token is not None}")
        
        if not credentials or not token:
            print(f"[FETCH] Missing credentials or token - cannot make OpenStack request")
            return []
        
        if endpoint == '/images':
            print(f"[FETCH] Making request to OpenStack images API...")
            response = make_openstack_request('GET', 'image', '/images')
            print(f"[FETCH] Images response: {response}")
            if response and response.status_code == 200:
                data = response.json().get('images', [])
                print(f"[FETCH] Retrieved {len(data)} images from OpenStack")
                if isinstance(data, list):
                    set_cached_data(cache_key, data, cache_ttl)
                    return data
                
        elif endpoint == '/flavors':
            print(f"[FETCH] Making request to OpenStack flavors API...")
            response = make_openstack_request('GET', 'compute', '/flavors/detail')
            print(f"[FETCH] Flavors response: {response}")
            if response and response.status_code == 200:
                data = response.json().get('flavors', [])
                print(f"[FETCH] Retrieved {len(data)} flavors from OpenStack")
                if isinstance(data, list):
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
                if isinstance(data, list):
                    set_cached_data(cache_key, data, cache_ttl)
                    return data
                
        elif endpoint == '/networks':
            response = make_openstack_request('GET', 'network', '/networks')
            if response and response.status_code == 200:
                data = response.json().get('networks', [])
                if isinstance(data, list):
                    set_cached_data(cache_key, data, cache_ttl)
                    return data
        
        print(f"[FETCH] No valid response received for {endpoint}")
        
    except Exception as e:
        print(f"[FETCH] Exception occurred: {e}")
        logger.error(f"Error fetching OpenStack data for {endpoint}: {e}")
    
    # Si no se pudo obtener datos reales, devolver estructura apropiada con valores seguros
    print(f"[FETCH] Returning fallback data for {endpoint}")
    if endpoint == '/quotas':
        return {'total_vcpus': 1, 'used_vcpus': 0, 'total_ram': 1024, 'used_ram': 0, 'total_instances': 1, 'used_instances': 0}
    else:
        return []

def get_flavor_vcpus(flavor_id):
    """Obtener vCPUs de un flavor"""
    flavor_info = VM_FLAVORS.get(flavor_id, VM_FLAVORS['small'])
    return flavor_info.get('vcpus', 1)

def get_flavor_ram(flavor_id):
    """Obtener RAM de un flavor"""
    flavor_info = VM_FLAVORS.get(flavor_id, VM_FLAVORS['small'])
    return flavor_info.get('ram', 1536)

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
        
        # Procesar slices para agregar métricas calculadas
        processed_slices = []
        for slice_row in slices:
            slice_dict = dict(slice_row)
            
            # Parsear configuración JSON
            config_data = json.loads(slice_dict.get('config_data', '{}'))
            nodes = config_data.get('nodes', [])
            
            # Calcular métricas
            slice_dict['node_count'] = len(nodes)
            slice_dict['total_vcpus'] = sum(get_flavor_vcpus(node.get('flavor', 'small')) for node in nodes)
            slice_dict['total_ram'] = sum(get_flavor_ram(node.get('flavor', 'small')) for node in nodes)
            slice_dict['infrastructure'] = config_data.get('infrastructure', 'linux')
            
            processed_slices.append(slice_dict)
        
        return MockResponse(processed_slices, 200)
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
    
    # Obtener VMs reales del proyecto del usuario en OpenStack (solo si tiene credenciales)
    if get_user_openstack_credentials():
        servers = fetch_openstack_data_with_cache('/servers', 'user_servers', 5)
        if servers and isinstance(servers, list):
            user_stats['total_vms'] = len(servers)
            # Los servidores de OpenStack tienen diferentes campos según la API
            user_stats['total_vcpus'] = sum(s.get('vcpus', s.get('flavor', {}).get('vcpus', 0)) if isinstance(s, dict) else 0 for s in servers)
            user_stats['total_ram'] = sum(s.get('ram', s.get('flavor', {}).get('ram', 0)) if isinstance(s, dict) else 0 for s in servers)
            user_stats['total_disk'] = sum(s.get('disk', s.get('flavor', {}).get('disk', 0)) if isinstance(s, dict) else 0 for s in servers)
    
    # Obtener recursos del sistema con valores seguros
    system_resources = safe_system_resources()
    
    # Obtener imágenes y flavors disponibles para el dashboard (solo si tiene credenciales)
    images = []
    flavors = []
    if get_user_openstack_credentials():
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
    """Crear nuevo slice de OpenStack con VMs reales"""
    try:
        data = request.get_json()
        logger.info("=== SLICE CREATION START ===")
        logger.info(f"User: {session['user']['username']} (ID: {session['user']['id']})")
        logger.info(f"Data received: {data}")
        
        # Validar datos requeridos
        required_fields = ['name', 'topology_type', 'node_count', 'flavor', 'image', 'network_name', 'network_cidr']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'error': f'Campo requerido: {field}'}), 400
        
        # Validar número de nodos
        node_count = int(data.get('node_count', 0))
        if node_count < 2 or node_count > 20:
            return jsonify({'success': False, 'error': 'Número de VMs debe estar entre 2 y 20'}), 400
        
        # Obtener credenciales de OpenStack
        credentials = get_user_openstack_credentials()
        if not credentials:
            return jsonify({
                'success': False, 
                'error': 'Configure las credenciales de OpenStack primero en Configuración'
            }), 400
        
        # Generar ID único para el slice
        slice_id = str(uuid.uuid4())
        
        # Preparar configuración del slice
        vm_prefix = data.get('vm_prefix', data['name'].replace(' ', '-').lower())
        
        # Crear configuración de VMs para el slice
        vms_config = []
        for i in range(1, node_count + 1):
            vm_name = f"{slice_id[:8]}-{vm_prefix}-{i}"
            vms_config.append({
                'name': vm_name,
                'flavor_id': data['flavor'],
                'image_id': data['image'],
                'cloud_init': data.get('cloud_init', ''),
                'number': i
            })
        
        # Configuración de red del slice
        network_config = {
            'name': f"{slice_id[:8]}-{data['network_name']}",
            'cidr': data['network_cidr'],
            'enable_dhcp': data.get('enable_dhcp', True),
            'description': f"Red privada para slice {data['name']}"
        }
        
        slice_config = {
            'slice_id': slice_id,
            'topology_type': data['topology_type'],
            'node_count': node_count,
            'vms': vms_config,
            'network': network_config,
            'flavor_id': data['flavor'],
            'image_id': data['image'],
            'cloud_init': data.get('cloud_init', ''),
            'created_at': datetime.utcnow().isoformat()
        }
        
        # Guardar slice en base de datos
        db = get_db()
        db.execute('''
            INSERT INTO slices (id, user_id, name, description, topology_type, status, config_data)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            slice_id,
            session['user']['id'],
            data['name'],
            data.get('description', ''),
            data['topology_type'],
            'creating',
            json.dumps(slice_config)
        ))
        db.commit()
        
        # Crear recursos en OpenStack
        logger.info(f"Creating OpenStack resources for slice {slice_id}")
        logger.info(f"Slice config structure: {slice_config}")
        # Intentar primero con la nueva función, sino usar fallback
        logger.info("Attempting to create slice with topology-aware function...")
        try:
            success = create_openstack_slice(slice_id, slice_config, credentials)
        except Exception as e:
            logger.warning(f"Topology-aware creation failed: {e}")
            logger.info("Falling back to simple slice creation...")
            success = create_simple_openstack_slice(slice_id, slice_config, credentials)
        
        if success:
            # Actualizar estado del slice
            db.execute('UPDATE slices SET status = ? WHERE id = ?', ('created', slice_id))
            db.commit()
            logger.info(f"Slice {slice_id} created successfully with OpenStack resources")
            
            return jsonify({
                'success': True, 
                'slice_id': slice_id,
                'message': f'Slice "{data["name"]}" creado exitosamente con {node_count} VMs'
            })
        else:
            # Marcar como fallido pero mantener en BD para debugging
            db.execute('UPDATE slices SET status = ? WHERE id = ?', ('failed', slice_id))
            db.commit()
            logger.error(f"Failed to create OpenStack resources for slice {slice_id}")
            
            return jsonify({
                'success': False,
                'error': 'Error al crear recursos en OpenStack. Revise los logs para más detalles.'
            }), 500
            
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        logger.error(f"Error creating slice: {e}")
        logger.error(f"Full traceback: {error_details}")
        return jsonify({'success': False, 'error': str(e), 'details': error_details}), 500

def create_openstack_slice(slice_id, config, credentials):
    """Crea un slice completo en OpenStack con topología específica"""
    try:
        # Obtener token de autenticación
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
        
        response = requests.post(
            f"{credentials['auth_url']}/auth/tokens",
            json=auth_data,
            headers={'Content-Type': 'application/json'},
            timeout=30
        )
        
        if response.status_code != 201:
            logger.error(f"Failed to authenticate with OpenStack: {response.status_code}")
            return False
        
        token = response.headers.get('X-Subject-Token')
        headers = {
            'X-Auth-Token': token,
            'Content-Type': 'application/json'
        }
        
        # Obtener topología específica
        topology_type = config.get('topology_type', 'linear')
        logger.info(f"Creating slice with topology: {topology_type}")
        
        # Paso 1: Obtener red pública/externa
        public_network_id = get_public_network_id(headers)
        if not public_network_id:
            logger.error("No se encontró red pública disponible")
            return False
        
        # Paso 2: Crear redes según la topología
        try:
            network_configs = create_topology_networks(topology_type, config, slice_id)
            created_networks = []
            
            for net_config in network_configs:
                network_id = create_slice_network(net_config, headers, slice_id)
                if network_id:
                    created_networks.append({
                        'id': network_id,
                        'name': net_config['name'],
                        'type': net_config.get('network_type', 'data')
                    })
            
            if not created_networks:
                logger.error("No se pudo crear ninguna red para el slice")
                return False
            
            # Usar la primera red como principal
            primary_network_id = created_networks[0]['id']
        except Exception as e:
            logger.error(f"Error creating networks: {e}")
            # Fallback a creación simple
            if 'network' in config:
                primary_network_id = create_slice_network(config['network'], headers, slice_id)
            else:
                # Crear red básica
                basic_network = {
                    'name': f"{slice_id[:8]}-network",
                    'cidr': '192.168.100.0/24',
                    'enable_dhcp': True,
                    'description': f"Red básica para slice {slice_id}"
                }
                primary_network_id = create_slice_network(basic_network, headers, slice_id)
            
            if not primary_network_id:
                logger.error("Error creando red básica del slice")
                return False
                
            created_networks = [{'id': primary_network_id, 'name': f"{slice_id[:8]}-network", 'type': 'data'}]
        
        # Paso 3: Crear router y conectar redes
        router_id = create_slice_router(slice_id, primary_network_id, public_network_id, headers)
        if not router_id:
            logger.error("Error creando router del slice")
            return False
        
        # Paso 4: Crear VMs según la topología
        vm_ids = []
        try:
            vm_configs = create_topology_vms(topology_type, config, created_networks)
            
            for vm_config in vm_configs:
                # Determinar a qué redes conectar la VM según la topología
                vm_networks = get_vm_networks_for_topology(topology_type, vm_config, created_networks, public_network_id)
                
                vm_id = create_slice_vm_with_networks(vm_config, vm_networks, headers, slice_id)
                if vm_id:
                    vm_ids.append(vm_id)
                else:
                    logger.warning(f"Error creando VM {vm_config['name']}")
        except Exception as e:
            logger.error(f"Error creating VMs with topology: {e}")
            # Fallback a creación simple usando la función original
            for vm_config in config.get('vms', []):
                vm_id = create_slice_vm(vm_config, primary_network_id, public_network_id, headers, slice_id)
                if vm_id:
                    vm_ids.append(vm_id)
                else:
                    logger.warning(f"Error creando VM {vm_config['name']}")
        
        if len(vm_ids) > 0:
            logger.info(f"Slice {slice_id} created successfully with {topology_type} topology: {len(vm_ids)} VMs, {len(created_networks)} networks, router")
            return True
        else:
            logger.error(f"No se pudo crear ninguna VM para el slice {slice_id}")
            return False
        
    except Exception as e:
        logger.error(f"Error creating OpenStack slice: {e}")
        return False

def get_public_network_id(headers):
    """Buscar red pública/externa disponible"""
    try:
        # Usar configuración de túnel SSH
        from microservicios.openstack_config_ssh import OPENSTACK_SERVICE_PORTS
        neutron_port = OPENSTACK_SERVICE_PORTS['neutron']['local']
        
        response = requests.get(
            f"http://localhost:{neutron_port}/v2.0/networks?router:external=true",
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 200:
            networks = response.json().get('networks', [])
            for network in networks:
                if network.get('status') == 'ACTIVE':
                    return network['id']
        
        return None
    except Exception as e:
        logger.error(f"Error finding public network: {e}")
        return None

def create_slice_network(network_config, headers, slice_id):
    """Crear red privada para el slice"""
    try:
        # Crear red
        network_data = {
            "network": {
                "name": network_config['name'],
                "admin_state_up": True,
                "description": network_config['description']
            }
        }
        
        # Usar configuración de túnel SSH
        from microservicios.openstack_config_ssh import OPENSTACK_SERVICE_PORTS
        neutron_port = OPENSTACK_SERVICE_PORTS['neutron']['local']
        
        response = requests.post(
            f"http://localhost:{neutron_port}/v2.0/networks",
            json=network_data,
            headers=headers,
            timeout=30
        )
        
        if response.status_code != 201:
            logger.error(f"Failed to create network: {response.status_code}")
            return None
        
        network = response.json()['network']
        network_id = network['id']
        
        # Crear subnet
        subnet_data = {
            "subnet": {
                "name": f"{network_config['name']}-subnet",
                "network_id": network_id,
                "ip_version": 4,
                "cidr": network_config['cidr'],
                "enable_dhcp": network_config['enable_dhcp']
            }
        }
        
        subnet_response = requests.post(
            f"http://localhost:{neutron_port}/v2.0/subnets",
            json=subnet_data,
            headers=headers,
            timeout=30
        )
        
        if subnet_response.status_code == 201:
            logger.info(f"Created network {network_config['name']} for slice {slice_id}")
            return network_id
        else:
            logger.error(f"Failed to create subnet: {subnet_response.status_code}")
            return None
            
    except Exception as e:
        logger.error(f"Error creating slice network: {e}")
        return None

def create_slice_router(slice_id, private_network_id, public_network_id, headers):
    """Crear router para conectar red privada con pública"""
    try:
        # Crear router
        router_data = {
            "router": {
                "name": f"{slice_id[:8]}-router",
                "admin_state_up": True,
                "external_gateway_info": {
                    "network_id": public_network_id
                }
            }
        }
        
        # Usar configuración de túnel SSH  
        from microservicios.openstack_config_ssh import OPENSTACK_SERVICE_PORTS
        neutron_port = OPENSTACK_SERVICE_PORTS['neutron']['local']
        
        response = requests.post(
            f"http://localhost:{neutron_port}/v2.0/routers",
            json=router_data,
            headers=headers,
            timeout=30
        )
        
        if response.status_code != 201:
            logger.error(f"Failed to create router: {response.status_code}")
            return None
        
        router = response.json()['router']
        router_id = router['id']
        
        # Obtener subnet de la red privada
        subnets_response = requests.get(
            f"http://localhost:{neutron_port}/v2.0/subnets?network_id={private_network_id}",
            headers=headers,
            timeout=30
        )
        
        if subnets_response.status_code != 200:
            logger.error("Failed to get private network subnets")
            return None
        
        subnets = subnets_response.json().get('subnets', [])
        if not subnets:
            logger.error("No subnets found for private network")
            return None
        
        subnet_id = subnets[0]['id']
        
        # Conectar router a la subnet privada
        router_interface_data = {
            "subnet_id": subnet_id
        }
        
        interface_response = requests.put(
            f"http://localhost:{neutron_port}/v2.0/routers/{router_id}/add_router_interface",
            json=router_interface_data,
            headers=headers,
            timeout=30
        )
        
        if interface_response.status_code == 200:
            logger.info(f"Created router {slice_id[:8]}-router")
            return router_id
        else:
            logger.error(f"Failed to add router interface: {interface_response.status_code}")
            return None
            
    except Exception as e:
        logger.error(f"Error creating slice router: {e}")
        return None

def create_slice_vm_with_networks(vm_config, vm_networks, headers, slice_id):
    """Crear VM conectada a redes específicas según topología"""
    try:
        # Preparar cloud-init si existe
        user_data = None
        if vm_config.get('cloud_init'):
            import base64
            cloud_init_script = vm_config['cloud_init']
            user_data = base64.b64encode(cloud_init_script.encode()).decode()
        
        # Crear instancia
        instance_data = {
            "server": {
                "name": vm_config['name'],
                "imageRef": vm_config['image_id'],
                "flavorRef": vm_config['flavor_id'],
                "networks": vm_networks,
                "security_groups": [{"name": "default"}],
                "description": f"VM {vm_config['number']} del slice {slice_id} (topología: {vm_config.get('topology_role', 'node')})",
                "metadata": {
                    "slice_id": slice_id,
                    "vm_number": str(vm_config['number']),
                    "topology_role": vm_config.get('topology_role', 'node'),
                    "created_by": "pucp-cloud-orchestrator"
                }
            }
        }
        
        # Agregar cloud-init si existe
        if user_data:
            instance_data["server"]["user_data"] = user_data
        
        # Usar configuración de túnel SSH
        from microservicios.openstack_config_ssh import OPENSTACK_SERVICE_PORTS
        nova_port = OPENSTACK_SERVICE_PORTS['nova']['local']
        
        response = requests.post(
            f"http://localhost:{nova_port}/v2.1/servers",
            json=instance_data,
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 202:
            vm = response.json()['server']
            logger.info(f"Created VM {vm_config['name']} for slice {slice_id} with {len(vm_networks)} network interfaces")
            return vm['id']
        else:
            logger.error(f"Failed to create VM {vm_config['name']}: {response.status_code}")
            logger.error(f"Response: {response.text}")
            return None
            
    except Exception as e:
        logger.error(f"Error creating VM {vm_config['name']}: {e}")
        return None

def create_topology_networks(topology_type, config, slice_id):
    """Crear configuración de redes específica según topología"""
    networks = []
    # Extraer información de red del config
    if 'network' in config and isinstance(config['network'], dict):
        base_name = config['network']['name']
        base_cidr = config['network']['cidr']
    else:
        # Fallback para el formato actual
        base_name = slice_id[:8] + "-net"
        base_cidr = "192.168.100.0/24"
    
    if topology_type == 'linear':
        # Red única para comunicación secuencial
        networks.append({
            'name': f"{base_name}-linear",
            'cidr': base_cidr,
            'network_type': 'data',
            'description': f"Red lineal para slice {slice_id}"
        })
    
    elif topology_type == 'ring':
        # Red principal para el anillo
        networks.append({
            'name': f"{base_name}-ring",
            'cidr': base_cidr,
            'network_type': 'data', 
            'description': f"Red en anillo para slice {slice_id}"
        })
    
    elif topology_type == 'mesh':
        # Red única donde todos se conectan
        networks.append({
            'name': f"{base_name}-mesh",
            'cidr': base_cidr,
            'network_type': 'data',
            'description': f"Red malla para slice {slice_id}"
        })
    
    elif topology_type == 'tree':
        # Red principal + red de gestión
        networks.append({
            'name': f"{base_name}-tree-main",
            'cidr': base_cidr,
            'network_type': 'data',
            'description': f"Red principal del árbol para slice {slice_id}"
        })
        networks.append({
            'name': f"{base_name}-tree-mgmt",
            'cidr': '192.168.101.0/24',
            'network_type': 'management',
            'description': f"Red de gestión del árbol para slice {slice_id}"
        })
    
    elif topology_type == 'bus':
        # Red de bus principal
        networks.append({
            'name': f"{base_name}-bus",
            'cidr': base_cidr,
            'network_type': 'data',
            'description': f"Red de bus para slice {slice_id}"
        })
    
    return networks

def create_topology_vms(topology_type, config, networks):
    """Crear configuración de VMs específica según topología"""
    vms = []
    node_count = config['node_count']
    
    for i in range(node_count):
        # Usar la lista de VMs si existe, sino crear configuración básica
        if 'vms' in config and len(config['vms']) > i:
            vm_base = config['vms'][i]
            vm_config = {
                'name': vm_base['name'],
                'image_id': vm_base['image_id'],
                'flavor_id': vm_base['flavor_id'],
                'number': i + 1,
                'cloud_init': vm_base.get('cloud_init', ''),
                'topology_role': get_topology_role(topology_type, i, node_count)
            }
        else:
            # Crear configuración básica
            vm_config = {
                'name': f"{config.get('slice_id', 'slice')[:8]}-vm-{i+1}",
                'image_id': config.get('image_id', 'ubuntu-20.04'),
                'flavor_id': config.get('flavor_id', 'm1.small'),
                'number': i + 1,
                'cloud_init': config.get('cloud_init', ''),
                'topology_role': get_topology_role(topology_type, i, node_count)
            }
        vms.append(vm_config)
    
    return vms

def get_topology_role(topology_type, vm_index, total_nodes):
    """Determinar el rol de una VM en la topología"""
    if topology_type == 'linear':
        if vm_index == 0:
            return 'head'
        elif vm_index == total_nodes - 1:
            return 'tail'
        else:
            return 'middle'
    
    elif topology_type == 'ring':
        return 'ring_node'
    
    elif topology_type == 'mesh':
        return 'mesh_node'
    
    elif topology_type == 'tree':
        if vm_index == 0:
            return 'root'
        elif vm_index < (total_nodes // 2):
            return 'branch'
        else:
            return 'leaf'
    
    elif topology_type == 'bus':
        if vm_index == 0:
            return 'master'
        else:
            return 'slave'
    
    return 'node'

def get_vm_networks_for_topology(topology_type, vm_config, created_networks, public_network_id):
    """Determinar a qué redes conectar una VM según su rol en la topología"""
    vm_networks = []
    vm_role = vm_config.get('topology_role', 'node')
    
    # Todas las VMs se conectan a la red pública para acceso externo
    vm_networks.append({"uuid": public_network_id})
    
    if topology_type in ['linear', 'ring', 'mesh', 'bus']:
        # Para estas topologías, todas las VMs van a la red principal
        main_network = next((n for n in created_networks if n['type'] == 'data'), None)
        if main_network:
            vm_networks.append({"uuid": main_network['id']})
    
    elif topology_type == 'tree':
        # Root y branch van a ambas redes, leaf solo a la principal
        main_network = next((n for n in created_networks if 'main' in n['name']), None)
        mgmt_network = next((n for n in created_networks if 'mgmt' in n['name']), None)
        
        if main_network:
            vm_networks.append({"uuid": main_network['id']})
        
        # Solo root y branch van a la red de gestión
        if vm_role in ['root', 'branch'] and mgmt_network:
            vm_networks.append({"uuid": mgmt_network['id']})
    
    return vm_networks

# Mantener la función original para compatibilidad
def create_slice_vm(vm_config, private_network_id, public_network_id, headers, slice_id):
    """Wrapper para compatibilidad - usar create_slice_vm_with_networks"""
    vm_networks = [
        {"uuid": private_network_id},
        {"uuid": public_network_id}
    ]
    return create_slice_vm_with_networks(vm_config, vm_networks, headers, slice_id)

def create_simple_openstack_slice(slice_id, config, credentials):
    """Crear slice simple en OpenStack - función de fallback"""
    try:
        logger.info(f"Creating simple slice {slice_id}")
        
        # Obtener token de autenticación
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
        
        response = requests.post(
            f"{credentials['auth_url']}/auth/tokens",
            json=auth_data,
            headers={'Content-Type': 'application/json'},
            timeout=30
        )
        
        if response.status_code != 201:
            logger.error(f"Failed to authenticate with OpenStack: {response.status_code}")
            return False
        
        token = response.headers.get('X-Subject-Token')
        headers = {
            'X-Auth-Token': token,
            'Content-Type': 'application/json'
        }
        
        # Paso 1: Obtener red pública
        public_network_id = get_public_network_id(headers)
        if not public_network_id:
            logger.error("No se encontró red pública disponible")
            return False
        
        # Paso 2: Crear red privada simple
        network_config = config['network']
        private_network_id = create_slice_network(network_config, headers, slice_id)
        if not private_network_id:
            logger.error("Error creando red privada del slice")
            return False
        
        # Paso 3: Crear router
        router_id = create_slice_router(slice_id, private_network_id, public_network_id, headers)
        if not router_id:
            logger.error("Error creando router del slice")
            return False
        
        # Paso 4: Crear VMs simples
        vm_ids = []
        for vm_config in config['vms']:
            vm_id = create_slice_vm(vm_config, private_network_id, public_network_id, headers, slice_id)
            if vm_id:
                vm_ids.append(vm_id)
            else:
                logger.warning(f"Error creando VM {vm_config['name']}")
        
        if len(vm_ids) > 0:
            logger.info(f"Simple slice {slice_id} created successfully: {len(vm_ids)} VMs")
            return True
        else:
            logger.error(f"No se pudo crear ninguna VM para el slice {slice_id}")
            return False
        
    except Exception as e:
        logger.error(f"Error creating simple OpenStack slice: {e}")
        return False

def create_network_in_openstack(network_config, headers, credentials, slice_id):
    """Crea una red en OpenStack"""
    try:
        network_data = {
            "network": {
                "name": f"{slice_id}-{network_config['name']}",
                "admin_state_up": True,
                "description": f"Red para slice {slice_id}"
            }
        }
        
        # Crear red (usar puerto 15002 para Neutron según configuración SSH)
        network_response = requests.post(
            f"http://localhost:{OPENSTACK_SERVICE_PORTS['neutron']['local']}/v2.0/networks",
            json=network_data,
            headers=headers,
            timeout=30
        )
        
        if network_response.status_code == 201:
            network_info = network_response.json()
            network_id = network_info['network']['id']
            
            # Crear subnet
            subnet_data = {
                "subnet": {
                    "name": f"{slice_id}-{network_config['name']}-subnet",
                    "network_id": network_id,
                    "ip_version": 4,
                    "cidr": network_config.get('cidr', '192.168.100.0/24'),
                    "enable_dhcp": True
                }
            }
            
            if network_config.get('gateway'):
                subnet_data['subnet']['gateway_ip'] = network_config['gateway']
            
            subnet_response = requests.post(
                f"http://localhost:{OPENSTACK_SERVICE_PORTS['neutron']['local']}/v2.0/subnets",
                json=subnet_data,
                headers=headers,
                timeout=30
            )
            
            if subnet_response.status_code == 201:
                logger.info(f"Created network {network_config['name']} for slice {slice_id}")
                return True
            else:
                logger.error(f"Failed to create subnet: {subnet_response.status_code}")
        else:
            logger.error(f"Failed to create network: {network_response.status_code}")
        
        return False
        
    except Exception as e:
        logger.error(f"Error creating network in OpenStack: {e}")
        return False

def create_instance_in_openstack(node_config, headers, credentials, slice_id):
    """Crea una instancia en OpenStack"""
    try:
        # Obtener imágenes disponibles (usar puerto 15003 para Glance)
        images_response = requests.get(
            f"http://localhost:{OPENSTACK_SERVICE_PORTS['glance']['local']}/v2/images",
            headers=headers,
            timeout=30
        )
        
        if images_response.status_code != 200:
            logger.error("Failed to get images from OpenStack")
            return False
        
        images = images_response.json().get('images', [])
        
        # Buscar imagen compatible
        image_id = None
        image_name = node_config.get('image', 'ubuntu')
        for image in images:
            if image.get('status') == 'active' and image_name.lower() in image.get('name', '').lower():
                image_id = image['id']
                break
        
        if not image_id and images:
            # Usar primera imagen activa disponible
            for image in images:
                if image.get('status') == 'active':
                    image_id = image['id']
                    break
        
        if not image_id:
            logger.error("No suitable image found in OpenStack")
            return False
        
        # Obtener flavors (usar puerto 15001 para Nova)
        flavors_response = requests.get(
            f"http://localhost:{OPENSTACK_SERVICE_PORTS['nova']['local']}/v2.1/flavors",
            headers=headers,
            timeout=30
        )
        
        if flavors_response.status_code != 200:
            logger.error("Failed to get flavors from OpenStack")
            return False
        
        flavors = flavors_response.json().get('flavors', [])
        
        # Buscar flavor compatible
        flavor_id = None
        flavor_name = node_config.get('flavor', 'small')
        
        # Mapear nuestros flavors a flavors de OpenStack
        flavor_mapping = {
            'nano': ['m1.nano', 'nano'],
            'micro': ['m1.micro', 'micro'],
            'small': ['m1.small', 'small'],
            'medium': ['m1.medium', 'medium'],
            'large': ['m1.large', 'large']
        }
        
        target_flavors = flavor_mapping.get(flavor_name, ['m1.small', 'small'])
        
        for target in target_flavors:
            for flavor in flavors:
                if target in flavor.get('name', '').lower():
                    flavor_id = flavor['id']
                    break
            if flavor_id:
                break
        
        if not flavor_id and flavors:
            # Usar primer flavor disponible
            flavor_id = flavors[0]['id']
        
        if not flavor_id:
            logger.error("No suitable flavor found in OpenStack")
            return False
        
        # Crear instancia
        instance_data = {
            "server": {
                "name": f"{slice_id}-{node_config['name']}",
                "imageRef": image_id,
                "flavorRef": flavor_id,
                "description": f"Nodo para slice {slice_id}",
                "metadata": {
                    "slice_id": slice_id,
                    "node_type": node_config.get('name', 'node')
                }
            }
        }
        
        instance_response = requests.post(
            f"http://localhost:{OPENSTACK_SERVICE_PORTS['nova']['local']}/v2.1/servers",
            json=instance_data,
            headers=headers,
            timeout=30
        )
        
        if instance_response.status_code == 202:
            logger.info(f"Created instance {node_config['name']} for slice {slice_id}")
            return True
        else:
            logger.error(f"Failed to create instance: {instance_response.status_code}")
            return False
        
    except Exception as e:
        logger.error(f"Error creating instance in OpenStack: {e}")
        return False

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
    try:
        db = get_db()
        
        # Verificar que el slice pertenece al usuario
        slice_data = db.execute(
            'SELECT * FROM slices WHERE id = ? AND user_id = ?',
            (slice_id, session['user']['id'])
        ).fetchone()
        
        if not slice_data:
            return jsonify({'success': False, 'error': 'Slice no encontrado'}), 404
        
        # Eliminar slice de la base de datos
        db.execute('DELETE FROM slices WHERE id = ? AND user_id = ?', (slice_id, session['user']['id']))
        db.commit()
        
        return jsonify({'success': True, 'message': 'Slice eliminado exitosamente'})
        
    except Exception as e:
        logger.error(f"Error deleting slice: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/topology/generate', methods=['POST'])
@login_required
def generate_topology():
    """Generar configuración automática de topología"""
    try:
        data = request.get_json()
        topology_type = data.get('topology')
        node_count = data.get('node_count', 3)
        
        if topology_type not in PREDEFINED_TOPOLOGIES:
            return jsonify({'success': False, 'error': 'Tipo de topología no válido'}), 400
        
        topology_info = PREDEFINED_TOPOLOGIES[topology_type]
        
        # Validar número de nodos
        if node_count < topology_info['min_nodes'] or node_count > topology_info['max_nodes']:
            return jsonify({
                'success': False, 
                'error': f'Número de nodos debe estar entre {topology_info["min_nodes"]} y {topology_info["max_nodes"]}'
            }), 400
        
        # Generar configuración de nodos
        nodes = []
        for i in range(node_count):
            nodes.append({
                'name': f'node-{i + 1}',
                'image': 'ubuntu-20.04',
                'flavor': 'small',
                'internet_access': i == 0,  # Solo el primer nodo tiene acceso a internet por defecto
                'management_ip': ''
            })
        
        # Generar configuración de redes según topología
        networks = []
        
        if topology_type == 'linear':
            # Red principal para comunicación secuencial
            networks.append({
                'name': 'linear-network',
                'cidr': '192.168.100.0/24',
                'network_type': 'data',
                'internet_access': True,
                'gateway': '192.168.100.1'
            })
        
        elif topology_type == 'mesh':
            # Red principal donde todos se comunican
            networks.append({
                'name': 'mesh-network',
                'cidr': '192.168.100.0/24',
                'network_type': 'data',
                'internet_access': True,
                'gateway': '192.168.100.1'
            })
        
        elif topology_type == 'tree':
            # Red principal para el árbol
            networks.append({
                'name': 'tree-network',
                'cidr': '192.168.100.0/24',
                'network_type': 'data',
                'internet_access': True,
                'gateway': '192.168.100.1'
            })
            
            # Red de gestión adicional
            networks.append({
                'name': 'management-network',
                'cidr': '192.168.101.0/24',
                'network_type': 'management',
                'internet_access': False,
                'gateway': '192.168.101.1'
            })
        
        elif topology_type == 'ring':
            # Red circular
            networks.append({
                'name': 'ring-network',
                'cidr': '192.168.100.0/24',
                'network_type': 'data',
                'internet_access': True,
                'gateway': '192.168.100.1'
            })
        
        elif topology_type == 'bus':
            # Red de bus principal
            networks.append({
                'name': 'bus-network',
                'cidr': '192.168.100.0/24',
                'network_type': 'data',
                'internet_access': True,
                'gateway': '192.168.100.1'
            })
        
        # Agregar red de gestión común
        if len(networks) == 1:
            networks.append({
                'name': 'management-network',
                'cidr': '192.168.200.0/24',
                'network_type': 'management',
                'internet_access': False,
                'gateway': '192.168.200.1'
            })
        
        topology_config = {
            'nodes': nodes,
            'networks': networks,
            'topology_type': topology_type,
            'total_nodes': node_count
        }
        
        return jsonify({
            'success': True,
            'topology': topology_config,
            'message': f'Topología {topology_info["name"]} generada con {node_count} nodos'
        })
        
    except Exception as e:
        logger.error(f"Error generating topology: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

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

@app.route('/debug/slices')
@login_required
def debug_slices():
    """Debug endpoint para ver slices en la base de datos"""
    try:
        db = get_db()
        slices = db.execute('SELECT * FROM slices WHERE user_id = ?', (session['user']['id'],)).fetchall()
        return jsonify({
            'user_id': session['user']['id'],
            'slices': [dict(s) for s in slices]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/test/slice/create', methods=['POST'])
@login_required
def test_create_slice():
    """Test endpoint para crear slice simple"""
    try:
        data = {
            'name': 'test-slice-' + str(int(datetime.utcnow().timestamp())),
            'description': 'Slice de prueba',
            'infrastructure': 'linux',
            'topology_type': 'linear',
            'nodes': [
                {'name': 'node-1', 'image': 'ubuntu-20.04', 'flavor': 'small', 'internet_access': True},
                {'name': 'node-2', 'image': 'ubuntu-20.04', 'flavor': 'small', 'internet_access': False}
            ],
            'networks': [
                {'name': 'test-network', 'cidr': '192.168.100.0/24', 'network_type': 'data'}
            ]
        }
        
        slice_id = str(uuid.uuid4())
        db = get_db()
        
        slice_config = {
            'topology_type': data.get('topology_type', 'linear'),
            'infrastructure': data.get('infrastructure', 'linux'),
            'nodes': data.get('nodes', []),
            'networks': data.get('networks', [])
        }
        
        db.execute('''
            INSERT INTO slices (id, user_id, name, description, topology_type, status, config_data)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            slice_id,
            session['user']['id'],
            data['name'],
            data['description'],
            data['topology_type'],
            'created',
            json.dumps(slice_config)
        ))
        db.commit()
        
        return jsonify({
            'success': True,
            'slice_id': slice_id,
            'message': 'Test slice creado exitosamente'
        })
        
    except Exception as e:
        logger.error(f"Error creating test slice: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/openstack/flavors')
def get_openstack_flavors():
    """Obtener flavors disponibles en OpenStack"""
    print("=" * 50)
    print("FLAVORS ENDPOINT CALLED - GETTING REAL DATA")
    print("=" * 50)
    
    try:
        # Intentar obtener datos reales de OpenStack
        flavors_data = fetch_openstack_data_with_cache('/flavors', 'flavors', 60)
        print(f"Raw flavors from OpenStack: {flavors_data}")
        
        if isinstance(flavors_data, list) and len(flavors_data) > 0:
            # Procesar flavors reales
            processed_flavors = []
            for flavor in flavors_data:
                if isinstance(flavor, dict):
                    is_public = flavor.get('os-flavor-access:is_public', True)
                    if is_public:
                        processed_flavors.append({
                            'id': flavor.get('id'),
                            'name': flavor.get('name'),
                            'vcpus': flavor.get('vcpus', 1),
                            'ram': flavor.get('ram', 1024),
                            'disk': flavor.get('disk', 10),
                            'public': is_public
                        })
            
            if len(processed_flavors) > 0:
                print(f"RETURNING {len(processed_flavors)} REAL FLAVORS")
                return jsonify({
                    'success': True,
                    'flavors': processed_flavors,
                    'source': 'openstack_real'
                })
        
        # Si no hay datos reales, usar fallback
        print("NO REAL FLAVORS FOUND - USING FALLBACK")
        fallback_flavors = [
            {'id': 'fallback-tiny', 'name': 'Fallback Tiny', 'vcpus': 1, 'ram': 512, 'disk': 1},
            {'id': 'fallback-small', 'name': 'Fallback Small', 'vcpus': 1, 'ram': 2048, 'disk': 20}
        ]
        
        return jsonify({
            'success': True,
            'flavors': fallback_flavors,
            'source': 'fallback',
            'debug': 'No real OpenStack flavors available'
        })
        
    except Exception as e:
        print(f"ERROR GETTING FLAVORS: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'source': 'error'
        }), 500

@app.route('/api/openstack/images')
def get_openstack_images():
    """Obtener imágenes disponibles en OpenStack"""
    print("=" * 50)
    print("IMAGES ENDPOINT CALLED - GETTING REAL DATA")
    print("=" * 50)
    
    try:
        # Intentar obtener datos reales de OpenStack
        images_data = fetch_openstack_data_with_cache('/images', 'images', 60)
        print(f"Raw images from OpenStack: {images_data}")
        
        if isinstance(images_data, list) and len(images_data) > 0:
            # Procesar imágenes reales
            processed_images = []
            for image in images_data:
                if isinstance(image, dict):
                    status = image.get('status', '').lower()
                    visibility = image.get('visibility', 'private')
                    
                    # Incluir imágenes activas y públicas/compartidas
                    if status == 'active' and visibility in ['public', 'shared', 'community']:
                        processed_images.append({
                            'id': image.get('id'),
                            'name': image.get('name', 'Unknown'),
                            'status': status,
                            'size': image.get('size', 0),
                            'disk_format': image.get('disk_format'),
                            'container_format': image.get('container_format'),
                            'visibility': visibility,
                            'os_type': image.get('os_type', 'unknown'),
                            'created_at': image.get('created_at')
                        })
            
            if len(processed_images) > 0:
                print(f"RETURNING {len(processed_images)} REAL IMAGES")
                return jsonify({
                    'success': True,
                    'images': processed_images,
                    'source': 'openstack_real'
                })
        
        # Si no hay datos reales, usar fallback
        print("NO REAL IMAGES FOUND - USING FALLBACK")
        fallback_images = [
            {'id': 'fallback-ubuntu', 'name': 'Fallback Ubuntu', 'status': 'active', 'size': 2147483648},
            {'id': 'fallback-centos', 'name': 'Fallback CentOS', 'status': 'active', 'size': 2147483648}
        ]
        
        return jsonify({
            'success': True,
            'images': fallback_images,
            'source': 'fallback',
            'debug': 'No real OpenStack images available'
        })
        
    except Exception as e:
        print(f"ERROR GETTING IMAGES: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'source': 'error'
        }), 500

@app.route('/api/test')
def test_endpoint():
    """Endpoint de testing simple"""
    print("TEST ENDPOINT CALLED")
    return jsonify({
        'success': True,
        'message': 'Test endpoint working',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/debug/slice-config', methods=['POST'])
@login_required
def debug_slice_config():
    """Debug endpoint para revisar configuración de slice"""
    try:
        data = request.get_json()
        logger.info(f"Debug slice config: {data}")
        
        # Validar datos básicos
        validation_errors = []
        required_fields = ['name', 'topology_type', 'node_count', 'flavor', 'image', 'network_name', 'network_cidr']
        for field in required_fields:
            if not data.get(field):
                validation_errors.append(f'Campo requerido faltante: {field}')
        
        # Verificar credenciales OpenStack
        credentials = get_user_openstack_credentials()
        has_credentials = credentials is not None
        
        # Verificar token
        token = None
        if has_credentials:
            token = get_openstack_token()
        
        debug_info = {
            'received_data': data,
            'validation_errors': validation_errors,
            'has_openstack_credentials': has_credentials,
            'has_openstack_token': token is not None,
            'user_id': session['user']['id'],
            'user_name': session['user']['username']
        }
        
        return jsonify({
            'success': True,
            'debug_info': debug_info
        })
        
    except Exception as e:
        import traceback
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

@app.route('/api/debug/openstack-test', methods=['POST'])
@login_required
def test_openstack_apis():
    """Probar todas las APIs de OpenStack paso a paso"""
    try:
        logger.info("=== TESTING OPENSTACK APIS ===")
        
        # Paso 1: Verificar credenciales
        credentials = get_user_openstack_credentials()
        if not credentials:
            return jsonify({'success': False, 'error': 'No OpenStack credentials configured'}), 400
        
        logger.info(f"Credentials: {credentials['auth_url']}, user: {credentials['username']}, project: {credentials['project_name']}")
        
        # Paso 2: Obtener token
        logger.info("Step 1: Getting OpenStack token...")
        token = get_openstack_token()
        if not token:
            return jsonify({'success': False, 'error': 'Failed to get OpenStack token'}), 400
        
        logger.info(f"✅ Token obtained: {token[:20]}...")
        
        # Paso 3: Probar API de Nova (Compute)
        logger.info("Step 2: Testing Nova API...")
        nova_response = make_openstack_request('GET', 'compute', '/flavors')
        nova_success = nova_response and nova_response.status_code == 200
        logger.info(f"Nova API: {'✅' if nova_success else '❌'} - Status: {nova_response.status_code if nova_response else 'No response'}")
        
        # Paso 4: Probar API de Glance (Images)
        logger.info("Step 3: Testing Glance API...")
        glance_response = make_openstack_request('GET', 'image', '/images')
        glance_success = glance_response and glance_response.status_code == 200
        logger.info(f"Glance API: {'✅' if glance_success else '❌'} - Status: {glance_response.status_code if glance_response else 'No response'}")
        
        # Paso 5: Probar API de Neutron (Network)
        logger.info("Step 4: Testing Neutron API...")
        neutron_response = make_openstack_request('GET', 'network', '/networks')
        neutron_success = neutron_response and neutron_response.status_code == 200
        logger.info(f"Neutron API: {'✅' if neutron_success else '❌'} - Status: {neutron_response.status_code if neutron_response else 'No response'}")
        
        # Paso 6: Buscar red pública
        logger.info("Step 5: Finding public network...")
        headers = {
            'X-Auth-Token': token,
            'Content-Type': 'application/json'
        }
        public_network_id = get_public_network_id(headers)
        logger.info(f"Public network: {'✅' if public_network_id else '❌'} - ID: {public_network_id}")
        
        test_results = {
            'credentials': bool(credentials),
            'token': bool(token),
            'nova_api': nova_success,
            'glance_api': glance_success,
            'neutron_api': neutron_success,
            'public_network': bool(public_network_id),
            'details': {
                'nova_status': nova_response.status_code if nova_response else None,
                'glance_status': glance_response.status_code if glance_response else None,
                'neutron_status': neutron_response.status_code if neutron_response else None,
                'public_network_id': public_network_id
            }
        }
        
        logger.info(f"=== TEST RESULTS: {test_results} ===")
        
        return jsonify({
            'success': True,
            'test_results': test_results
        })
        
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        logger.error(f"OpenStack test error: {e}")
        logger.error(f"Full traceback: {error_details}")
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': error_details
        }), 500

@app.route('/api/openstack/public-networks')
@login_required
def get_public_networks():
    """Obtener redes públicas disponibles en OpenStack"""
    try:
        networks_data = fetch_openstack_data_with_cache('/networks', 'networks', 30)
        
        if isinstance(networks_data, list):
            # Filtrar solo redes públicas/externas
            public_networks = []
            for network in networks_data:
                if isinstance(network, dict):
                    # Buscar redes externas o públicas
                    is_external = network.get('router:external', False)
                    is_shared = network.get('shared', False)
                    status = network.get('status', 'DOWN')
                    
                    if (is_external or is_shared) and status == 'ACTIVE':
                        public_networks.append({
                            'id': network.get('id'),
                            'name': network.get('name'),
                            'status': status,
                            'external': is_external,
                            'shared': is_shared,
                            'subnets': network.get('subnets', [])
                        })
            
            return jsonify({
                'success': True,
                'networks': public_networks
            })
        else:
            return jsonify({
                'success': False,
                'error': 'No se pudieron obtener las redes'
            }), 500
            
    except Exception as e:
        logger.error(f"Error getting public networks: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/resources')
@login_required
def system_resources():
    """Página de recursos del sistema"""
    resources = get_system_resources()
    return render_template('system_resources.html', resources=resources)

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
    """Obtener recursos de OpenStack específicos del usuario"""
    try:
        # Verificar si el usuario tiene credenciales de OpenStack
        credentials = get_user_openstack_credentials()
        if not credentials:
            return {
                'total_vcpus': 0,
                'used_vcpus': 0,
                'total_ram': 0,
                'used_ram': 0,
                'total_instances': 0,
                'used_instances': 0,
                'servers': [],
                'quotas_available': False,
                'message': 'Configure credenciales de OpenStack para ver recursos',
                'last_updated': datetime.utcnow().isoformat()
            }
        
        # Obtener datos reales con cache del proyecto del usuario
        quotas = fetch_openstack_data_with_cache('/quotas', 'quotas', 15)
        servers = fetch_openstack_data_with_cache('/servers', 'servers', 5)
        
        # Calcular estadísticas de uso real
        used_vcpus = 0
        used_ram = 0
        used_instances = 0
        active_servers = []
        
        if isinstance(servers, list):
            for server in servers:
                if isinstance(server, dict):
                    status = server.get('status', 'UNKNOWN')
                    server_info = {
                        'id': server.get('id'),
                        'name': server.get('name'),
                        'status': status,
                        'created': server.get('created'),
                        'flavor': server.get('flavor', {}),
                        'image': server.get('image', {}),
                        'addresses': server.get('addresses', {}),
                        'metadata': server.get('metadata', {})
                    }
                    active_servers.append(server_info)
                    
                    if status == 'ACTIVE':
                        used_instances += 1
                        # Obtener información del flavor para calcular recursos
                        flavor_info = server.get('flavor', {})
                        if 'id' in flavor_info:
                            # Si tenemos el ID del flavor, usar valores por defecto razonables
                            vcpus = 1  # Valor por defecto
                            ram = 1024  # Valor por defecto
                        else:
                            vcpus = 1
                            ram = 1024
                        
                        used_vcpus += vcpus
                        used_ram += ram
        
        # Procesar quotas del proyecto
        if isinstance(quotas, dict):
            # Los datos vienen directamente del endpoint de limits
            total_vcpus = quotas.get('total_vcpus', 10)
            total_ram = quotas.get('total_ram', 10240)
            total_instances = quotas.get('total_instances', 10)
            
            # Los datos de uso también vienen en la respuesta
            used_vcpus_from_quota = quotas.get('used_vcpus', 0)
            used_ram_from_quota = quotas.get('used_ram', 0)
            used_instances_from_quota = quotas.get('used_instances', 0)
            
            # Usar los datos de quotas si están disponibles
            if used_vcpus_from_quota > 0:
                used_vcpus = used_vcpus_from_quota
            if used_ram_from_quota > 0:
                used_ram = used_ram_from_quota
            if used_instances_from_quota > 0:
                used_instances = used_instances_from_quota
        else:
            # Valores por defecto si no hay quotas
            total_vcpus = 10
            total_ram = 10240
            total_instances = 10
        
        # Asegurar que los valores totales nunca sean 0 para evitar división por cero
        total_vcpus = max(total_vcpus, 1)
        total_ram = max(total_ram, 1024)
        total_instances = max(total_instances, 1)
        
        return {
            'total_vcpus': total_vcpus,
            'used_vcpus': min(used_vcpus, total_vcpus),
            'total_ram': total_ram,
            'used_ram': min(used_ram, total_ram),
            'total_instances': total_instances,
            'used_instances': min(used_instances, total_instances),
            'servers': active_servers,
            'quotas_available': True,
            'project_name': credentials.get('project_name', 'Unknown'),
            'region': credentials.get('region_name', 'RegionOne'),
            'last_updated': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting OpenStack resources: {e}")
        return {
            'total_vcpus': 1,
            'used_vcpus': 0,
            'total_ram': 1024,
            'used_ram': 0,
            'total_instances': 1,
            'used_instances': 0,
            'servers': [],
            'quotas_available': False,
            'message': f'Error obteniendo recursos: {str(e)}',
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

# Filtro personalizado para divisiones seguras
@app.template_filter('safe_divide')
def safe_divide(numerator, denominator, default=0):
    """División segura que evita ZeroDivisionError"""
    try:
        if denominator == 0:
            return default
        return (numerator / denominator)
    except (TypeError, ValueError):
        return default

@app.template_filter('percentage')
def percentage(numerator, denominator, default=0):
    """Calcula porcentaje de forma segura"""
    try:
        numerator = float(numerator or 0)
        denominator = float(denominator or 1)
        if denominator == 0:
            return default
        result = (numerator / denominator) * 100
        return min(round(result), 100)  # No puede ser más del 100%
    except (TypeError, ValueError, ZeroDivisionError):
        return default

def safe_system_resources():
    """Obtiene recursos del sistema con valores seguros"""
    try:
        resources = get_system_resources()
        
        # Asegurar estructura segura para OpenStack
        if 'openstack' in resources:
            openstack = resources['openstack']
            openstack['total_vcpus'] = max(openstack.get('total_vcpus', 1), 1)
            openstack['total_ram'] = max(openstack.get('total_ram', 1024), 1)
            openstack['total_instances'] = max(openstack.get('total_instances', 1), 1)
            openstack['used_vcpus'] = max(openstack.get('used_vcpus', 0), 0)
            openstack['used_ram'] = max(openstack.get('used_ram', 0), 0)
            openstack['used_instances'] = max(openstack.get('used_instances', 0), 0)
        
        return resources
    except Exception as e:
        logger.error(f"Error getting system resources: {e}")
        return {
            'openstack': {
                'total_vcpus': 1, 'used_vcpus': 0,
                'total_ram': 1024, 'used_ram': 0,
                'total_instances': 1, 'used_instances': 0,
                'servers': []
            },
            'linux': {
                'total_vcpus': 1, 'used_vcpus': 0,
                'total_ram': 1024, 'used_ram': 0,
                'servers': []
            }
        }

if __name__ == '__main__':
    # Inicializar base de datos
    init_db()
    logger.info(f"Starting web application on port {WEB_PORT}")
    app.run(host='0.0.0.0', port=WEB_PORT, debug=True)