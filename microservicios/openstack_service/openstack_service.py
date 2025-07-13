#!/usr/bin/env python3
"""
PUCP Cloud Orchestrator - OpenStack Service (Microservicio)
Servicio dedicado para gestión de recursos OpenStack con APIs completas
"""

from flask import Flask, request, jsonify, g
from flask_cors import CORS
import sqlite3
import os
import uuid
import datetime
import json
import logging
from functools import wraps
from typing import Dict, List, Any, Optional
import jwt
from .drivers.openstack_driver import OpenStackDriver
from .api.openstack_api import OpenStackAPI
from .config.openstack_config import OPENSTACK_CONFIG
from .drivers.flavor_manager import FlavorManager
from .drivers.availability_zone_manager import AvailabilityZoneManager
from microservicios.ssh_tunnel_manager import tunnel_manager, start_openstack_tunnels, is_openstack_accessible
from microservicios.edits.openstack_config_ssh import SSH_CONFIG, SSH_TUNNEL_CONFIG

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Configuración
app.config['DATABASE'] = os.path.join(os.path.dirname(__file__), 'openstack_service.db')
app.config['SECRET_KEY'] = 'pucp-cloud-secret-2025'

def get_db():
    """Obtiene conexión a la base de datos"""
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Inicializa la base de datos con esquema OpenStack"""
    with app.app_context():
        db = get_db()
        
        # Tabla de proyectos OpenStack
        db.execute('''
            CREATE TABLE IF NOT EXISTS openstack_projects (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                project_name TEXT NOT NULL,
                project_id TEXT UNIQUE NOT NULL,
                description TEXT,
                quota_vcpus INTEGER DEFAULT 20,
                quota_ram INTEGER DEFAULT 51200,
                quota_disk INTEGER DEFAULT 100,
                used_vcpus INTEGER DEFAULT 0,
                used_ram INTEGER DEFAULT 0,
                used_disk INTEGER DEFAULT 0,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Tabla de instancias OpenStack
        db.execute('''
            CREATE TABLE IF NOT EXISTS openstack_instances (
                id TEXT PRIMARY KEY,
                slice_id TEXT,
                user_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                instance_name TEXT NOT NULL,
                instance_id TEXT UNIQUE NOT NULL,
                image_id TEXT NOT NULL,
                flavor_id TEXT NOT NULL,
                status TEXT NOT NULL,
                ip_address TEXT,
                fixed_ip TEXT,
                floating_ip TEXT,
                console_url TEXT,
                host_server TEXT,
                availability_zone TEXT,
                security_groups TEXT,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (project_id) REFERENCES openstack_projects (project_id)
            )
        ''')
        
        # Tabla de redes OpenStack
        db.execute('''
            CREATE TABLE IF NOT EXISTS openstack_networks (
                id TEXT PRIMARY KEY,
                slice_id TEXT,
                user_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                network_name TEXT NOT NULL,
                network_id TEXT UNIQUE NOT NULL,
                subnet_id TEXT,
                router_id TEXT,
                cidr TEXT NOT NULL,
                gateway_ip TEXT,
                vlan_id INTEGER,
                network_type TEXT DEFAULT 'private',
                is_external BOOLEAN DEFAULT 0,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (project_id) REFERENCES openstack_projects (project_id)
            )
        ''')
        
        # Tabla de volúmenes OpenStack
        db.execute('''
            CREATE TABLE IF NOT EXISTS openstack_volumes (
                id TEXT PRIMARY KEY,
                slice_id TEXT,
                user_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                volume_name TEXT NOT NULL,
                volume_id TEXT UNIQUE NOT NULL,
                size INTEGER NOT NULL,
                volume_type TEXT DEFAULT 'standard',
                status TEXT NOT NULL,
                attached_to TEXT,
                availability_zone TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (project_id) REFERENCES openstack_projects (project_id)
            )
        ''')
        
        # Tabla de imágenes OpenStack
        db.execute('''
            CREATE TABLE IF NOT EXISTS openstack_images (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                image_name TEXT NOT NULL,
                image_id TEXT UNIQUE NOT NULL,
                image_type TEXT DEFAULT 'qcow2',
                size INTEGER,
                status TEXT NOT NULL,
                visibility TEXT DEFAULT 'private',
                os_type TEXT,
                os_version TEXT,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        db.commit()
        create_default_data(db)

def create_default_data(db):
    """Crear datos por defecto"""
    try:
        # Crear proyecto por defecto si no existe
        existing_project = db.execute(
            'SELECT id FROM openstack_projects WHERE project_name = ?', 
            ('pucp-default',)
        ).fetchone()
        
        if not existing_project:
            default_project_id = str(uuid.uuid4())
            db.execute('''
                INSERT INTO openstack_projects (
                    id, user_id, project_name, project_id, description
                )
                VALUES (?, ?, ?, ?, ?)
            ''', (
                default_project_id,
                'system',
                'pucp-default',
                'pucp-default-project',
                'Proyecto por defecto para PUCP Cloud Orchestrator'
            ))
            
            logger.info("Default OpenStack project created")
        
        db.commit()
        
    except Exception as e:
        logger.error(f"Error creating default data: {e}")

def token_required(f):
    """Decorador para requerir autenticación"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing authorization header'}), 401
        
        try:
            token = auth_header.split(' ')[1]
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            g.current_user = payload
        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        return f(*args, **kwargs)
    return decorated

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'openstack',
        'timestamp': datetime.datetime.utcnow().isoformat()
    })

@app.route('/api/openstack/projects', methods=['GET'])
@token_required
def list_projects():
    """Lista proyectos OpenStack del usuario"""
    try:
        db = get_db()
        user_id = g.current_user['user_id']
        
        projects = db.execute('''
            SELECT * FROM openstack_projects 
            WHERE user_id = ? OR user_id = 'system'
            ORDER BY created_at DESC
        ''', (user_id,)).fetchall()
        
        result = [dict(project) for project in projects]
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"List projects error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/openstack/projects', methods=['POST'])
@token_required
def create_project():
    """Crear nuevo proyecto OpenStack"""
    try:
        data = request.get_json()
        if not data or not data.get('project_name'):
            return jsonify({'error': 'Project name required'}), 400
        
        # Inicializar driver OpenStack
        openstack_driver = OpenStackDriver()
        
        # Crear proyecto en OpenStack
        project_result = openstack_driver.create_project(
            name=data['project_name'],
            description=data.get('description', ''),
            domain_id='default'
        )
        
        if not project_result['success']:
            return jsonify({
                'error': 'Failed to create OpenStack project',
                'details': project_result.get('error')
            }), 500
        
        # Guardar en BD local
        project_id = str(uuid.uuid4())
        db = get_db()
        
        db.execute('''
            INSERT INTO openstack_projects (
                id, user_id, project_name, project_id, description,
                quota_vcpus, quota_ram, quota_disk
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            project_id,
            g.current_user['user_id'],
            data['project_name'],
            project_result['project']['id'],
            data.get('description', ''),
            data.get('quota_vcpus', 20),
            data.get('quota_ram', 51200),
            data.get('quota_disk', 100)
        ))
        
        db.commit()
        
        logger.info(f"OpenStack project created: {project_id}")
        
        return jsonify({
            'id': project_id,
            'project_name': data['project_name'],
            'openstack_project_id': project_result['project']['id'],
            'message': 'Project created successfully'
        }), 201
        
    except Exception as e:
        logger.error(f"Create project error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/openstack/instances', methods=['GET'])
@token_required
def list_instances():
    """Lista instancias OpenStack del usuario"""
    try:
        db = get_db()
        user_id = g.current_user['user_id']
        project_id = request.args.get('project_id')
        slice_id = request.args.get('slice_id')
        
        query = '''
            SELECT i.*, p.project_name 
            FROM openstack_instances i
            JOIN openstack_projects p ON i.project_id = p.project_id
            WHERE i.user_id = ?
        '''
        params = [user_id]
        
        if project_id:
            query += ' AND i.project_id = ?'
            params.append(project_id)
            
        if slice_id:
            query += ' AND i.slice_id = ?'
            params.append(slice_id)
        
        query += ' ORDER BY i.created_at DESC'
        
        instances = db.execute(query, params).fetchall()
        
        result = []
        for instance in instances:
            instance_dict = dict(instance)
            
            # Parsear metadata si existe
            if instance['metadata']:
                try:
                    instance_dict['metadata'] = json.loads(instance['metadata'])
                except:
                    instance_dict['metadata'] = {}
            
            # Parsear security groups si existe
            if instance['security_groups']:
                try:
                    instance_dict['security_groups'] = json.loads(instance['security_groups'])
                except:
                    instance_dict['security_groups'] = []
            
            result.append(instance_dict)
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"List instances error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/openstack/instances', methods=['POST'])
@token_required
def create_instance():
    """Crear nueva instancia OpenStack"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400
        
        required_fields = ['instance_name', 'project_id', 'image_id', 'flavor_id']
        missing = [f for f in required_fields if not data.get(f)]
        if missing:
            return jsonify({'error': f'Missing fields: {", ".join(missing)}'}), 400
        
        # Inicializar driver OpenStack
        openstack_driver = OpenStackDriver()
        
        # Preparar configuración de la instancia
        instance_config = {
            'name': data['instance_name'],
            'image': data['image_id'],
            'flavor': data['flavor_id'],
            'project_id': data['project_id'],
            'networks': data.get('networks', []),
            'security_groups': data.get('security_groups', ['default']),
            'key_name': data.get('key_name'),
            'availability_zone': data.get('availability_zone'),
            'metadata': data.get('metadata', {})
        }
        
        # Crear instancia en OpenStack
        instance_result = openstack_driver.create_instance(instance_config)
        
        if not instance_result['success']:
            return jsonify({
                'error': 'Failed to create OpenStack instance',
                'details': instance_result.get('error')
            }), 500
        
        # Guardar en BD local
        instance_id = str(uuid.uuid4())
        db = get_db()
        
        db.execute('''
            INSERT INTO openstack_instances (
                id, slice_id, user_id, project_id, instance_name, instance_id,
                image_id, flavor_id, status, availability_zone,
                security_groups, metadata
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            instance_id,
            data.get('slice_id'),
            g.current_user['user_id'],
            data['project_id'],
            data['instance_name'],
            instance_result['instance']['id'],
            data['image_id'],
            data['flavor_id'],
            instance_result['instance']['status'],
            data.get('availability_zone'),
            json.dumps(data.get('security_groups', ['default'])),
            json.dumps(data.get('metadata', {}))
        ))
        
        db.commit()
        
        logger.info(f"OpenStack instance created: {instance_id}")
        
        return jsonify({
            'id': instance_id,
            'instance_name': data['instance_name'],
            'openstack_instance_id': instance_result['instance']['id'],
            'status': instance_result['instance']['status'],
            'message': 'Instance created successfully'
        }), 201
        
    except Exception as e:
        logger.error(f"Create instance error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/openstack/instances/<instance_id>', methods=['DELETE'])
@token_required
def delete_instance(instance_id):
    """Eliminar instancia OpenStack"""
    try:
        db = get_db()
        user_id = g.current_user['user_id']
        
        # Verificar que la instancia pertenece al usuario
        instance = db.execute('''
            SELECT * FROM openstack_instances 
            WHERE id = ? AND user_id = ?
        ''', (instance_id, user_id)).fetchone()
        
        if not instance:
            return jsonify({'error': 'Instance not found'}), 404
        
        # Inicializar driver OpenStack
        openstack_driver = OpenStackDriver()
        
        # Eliminar instancia en OpenStack
        delete_result = openstack_driver.delete_instance(
            instance['instance_id'],
            instance['project_id']
        )
        
        if not delete_result['success']:
            return jsonify({
                'error': 'Failed to delete OpenStack instance',
                'details': delete_result.get('error')
            }), 500
        
        # Eliminar de BD local
        db.execute('DELETE FROM openstack_instances WHERE id = ?', (instance_id,))
        db.commit()
        
        logger.info(f"OpenStack instance deleted: {instance_id}")
        
        return jsonify({'message': 'Instance deleted successfully'})
        
    except Exception as e:
        logger.error(f"Delete instance error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/openstack/networks', methods=['GET'])
@token_required
def list_networks():
    """Lista redes OpenStack del usuario"""
    try:
        db = get_db()
        user_id = g.current_user['user_id']
        project_id = request.args.get('project_id')
        slice_id = request.args.get('slice_id')
        
        query = '''
            SELECT n.*, p.project_name 
            FROM openstack_networks n
            JOIN openstack_projects p ON n.project_id = p.project_id
            WHERE n.user_id = ?
        '''
        params = [user_id]
        
        if project_id:
            query += ' AND n.project_id = ?'
            params.append(project_id)
            
        if slice_id:
            query += ' AND n.slice_id = ?'
            params.append(slice_id)
        
        query += ' ORDER BY n.created_at DESC'
        
        networks = db.execute(query, params).fetchall()
        result = [dict(network) for network in networks]
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"List networks error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/openstack/networks', methods=['POST'])
@token_required
def create_network():
    """Crear nueva red OpenStack"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400
        
        required_fields = ['network_name', 'project_id', 'cidr']
        missing = [f for f in required_fields if not data.get(f)]
        if missing:
            return jsonify({'error': f'Missing fields: {", ".join(missing)}'}), 400
        
        # Inicializar driver OpenStack
        openstack_driver = OpenStackDriver()
        
        # Crear red en OpenStack
        network_config = {
            'name': data['network_name'],
            'project_id': data['project_id'],
            'cidr': data['cidr'],
            'gateway_ip': data.get('gateway_ip'),
            'enable_dhcp': data.get('enable_dhcp', True),
            'dns_nameservers': data.get('dns_nameservers', ['8.8.8.8', '8.8.4.4']),
            'external': data.get('is_external', False)
        }
        
        network_result = openstack_driver.create_network(network_config)
        
        if not network_result['success']:
            return jsonify({
                'error': 'Failed to create OpenStack network',
                'details': network_result.get('error')
            }), 500
        
        # Guardar en BD local
        network_id = str(uuid.uuid4())
        db = get_db()
        
        db.execute('''
            INSERT INTO openstack_networks (
                id, slice_id, user_id, project_id, network_name, network_id,
                subnet_id, cidr, gateway_ip, network_type, is_external
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            network_id,
            data.get('slice_id'),
            g.current_user['user_id'],
            data['project_id'],
            data['network_name'],
            network_result['network']['id'],
            network_result['subnet']['id'],
            data['cidr'],
            data.get('gateway_ip'),
            data.get('network_type', 'private'),
            data.get('is_external', False)
        ))
        
        db.commit()
        
        logger.info(f"OpenStack network created: {network_id}")
        
        return jsonify({
            'id': network_id,
            'network_name': data['network_name'],
            'openstack_network_id': network_result['network']['id'],
            'subnet_id': network_result['subnet']['id'],
            'message': 'Network created successfully'
        }), 201
        
    except Exception as e:
        logger.error(f"Create network error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/openstack/images', methods=['GET'])
@token_required
def list_images():
    """Lista imágenes OpenStack disponibles"""
    try:
        # Inicializar driver OpenStack
        openstack_driver = OpenStackDriver()
        
        # Obtener imágenes de OpenStack
        images_result = openstack_driver.list_images()
        
        if not images_result['success']:
            return jsonify({
                'error': 'Failed to retrieve OpenStack images',
                'details': images_result.get('error')
            }), 500
        
        return jsonify(images_result['images'])
        
    except Exception as e:
        logger.error(f"List images error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/openstack/flavors', methods=['GET'])
@token_required
def list_flavors():
    """Lista flavors OpenStack disponibles"""
    try:
        # Inicializar driver OpenStack
        openstack_driver = OpenStackDriver()
        
        # Obtener flavors de OpenStack
        flavors_result = openstack_driver.list_flavors()
        
        if not flavors_result['success']:
            return jsonify({
                'error': 'Failed to retrieve OpenStack flavors',
                'details': flavors_result.get('error')
            }), 500
        
        return jsonify(flavors_result['flavors'])
        
    except Exception as e:
        logger.error(f"List flavors error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/openstack/quotas/<project_id>', methods=['GET'])
@token_required
def get_quotas(project_id):
    """Obtiene quotas de un proyecto OpenStack"""
    try:
        # Inicializar driver OpenStack
        openstack_driver = OpenStackDriver()
        
        # Obtener quotas de OpenStack
        quotas_result = openstack_driver.get_project_quotas(project_id)
        
        if not quotas_result['success']:
            return jsonify({
                'error': 'Failed to retrieve OpenStack quotas',
                'details': quotas_result.get('error')
            }), 500
        
        return jsonify(quotas_result['quotas'])
        
    except Exception as e:
        logger.error(f"Get quotas error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/openstack/deploy-slice', methods=['POST'])
@token_required
def deploy_slice():
    """Despliega un slice completo en OpenStack"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400
        
        slice_config = data.get('slice_config')
        placement = data.get('placement')
        
        if not slice_config or not placement:
            return jsonify({'error': 'slice_config and placement required'}), 400
        
        # Inicializar driver OpenStack
        openstack_driver = OpenStackDriver()
        
        # Desplegar slice
        deployment_result = openstack_driver.deploy_slice(slice_config, placement)
        
        if not deployment_result['success']:
            return jsonify({
                'error': 'Failed to deploy slice in OpenStack',
                'details': deployment_result.get('error'),
                'partial_deployment': deployment_result.get('deployed_vms', [])
            }), 500
        
        # Actualizar BD local con instancias desplegadas
        db = get_db()
        slice_id = slice_config.get('id')
        
        for vm_info in deployment_result.get('deployed_vms', []):
            instance_id = str(uuid.uuid4())
            
            db.execute('''
                INSERT INTO openstack_instances (
                    id, slice_id, user_id, project_id, instance_name, instance_id,
                    image_id, flavor_id, status, ip_address, fixed_ip,
                    availability_zone
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                instance_id,
                slice_id,
                g.current_user['user_id'],
                vm_info.get('project_id', 'default'),
                vm_info['name'],
                vm_info['id'],
                vm_info.get('image_id', ''),
                vm_info.get('flavor_id', ''),
                vm_info.get('status', 'BUILD'),
                vm_info.get('public_ip'),
                vm_info.get('private_ip'),
                vm_info.get('availability_zone')
            ))
        
        db.commit()
        
        logger.info(f"Slice deployed in OpenStack: {slice_id}")
        
        return jsonify({
            'slice_id': slice_id,
            'status': 'deployed',
            'deployed_vms': deployment_result['deployed_vms'],
            'created_networks': deployment_result.get('created_networks', []),
            'message': 'Slice deployed successfully in OpenStack'
        })
        
    except Exception as e:
        logger.error(f"Deploy slice error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/ssh-tunnel/status', methods=['GET'])
@token_required
def get_tunnel_status():
    """Obtiene el estado de los túneles SSH"""
    try:
        status = tunnel_manager.get_tunnel_status()
        tunnel_info = tunnel_manager.get_tunnel_info()
        
        return jsonify({
            'tunnel_status': status,
            'tunnel_info': tunnel_info,
            'openstack_accessible': is_openstack_accessible(),
            'ssh_connection_ok': tunnel_manager.test_ssh_connection()
        })
        
    except Exception as e:
        logger.error(f"Get tunnel status error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/ssh-tunnel/start', methods=['POST'])
@token_required
def start_tunnels():
    """Inicia los túneles SSH para OpenStack"""
    try:
        data = request.get_json() or {}
        service_name = data.get('service_name')  # Optional: start specific service
        
        # Primero verificar conexión SSH básica al jumper
        if not tunnel_manager.test_ssh_connection():
            return jsonify({
                'error': 'Cannot establish SSH connection to jumper host',
                'details': f"Check connection to {SSH_CONFIG['jumper_user']}@{SSH_CONFIG['jumper_host']}:{SSH_CONFIG['jumper_port']}"
            }), 503
        
        # Verificar conectividad al headnode OpenStack
        if not tunnel_manager.test_headnode_connection():
            return jsonify({
                'error': 'Cannot reach OpenStack headnode through jumper',
                'details': f"Check connectivity from jumper to headnode {SSH_CONFIG['openstack_headnode']}:5000"
            }), 503
        
        # Iniciar túneles
        success = tunnel_manager.start_ssh_tunnel(service_name)
        
        if success:
            status = tunnel_manager.get_tunnel_status()
            return jsonify({
                'message': 'SSH tunnels started successfully',
                'tunnel_status': status,
                'openstack_accessible': is_openstack_accessible()
            })
        else:
            return jsonify({
                'error': 'Failed to start SSH tunnels',
                'tunnel_status': tunnel_manager.get_tunnel_status()
            }), 500
            
    except Exception as e:
        logger.error(f"Start tunnels error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/ssh-tunnel/stop', methods=['POST'])
@token_required
def stop_tunnels():
    """Detiene los túneles SSH"""
    try:
        data = request.get_json() or {}
        service_name = data.get('service_name')  # Optional: stop specific service
        
        success = tunnel_manager.stop_ssh_tunnel(service_name)
        
        if success:
            return jsonify({
                'message': 'SSH tunnels stopped successfully',
                'tunnel_status': tunnel_manager.get_tunnel_status()
            })
        else:
            return jsonify({
                'error': 'Failed to stop SSH tunnels'
            }), 500
            
    except Exception as e:
        logger.error(f"Stop tunnels error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/ssh-tunnel/restart', methods=['POST'])
@token_required
def restart_tunnels():
    """Reinicia los túneles SSH"""
    try:
        # Primero detener todos los túneles
        tunnel_manager.stop_ssh_tunnel()
        
        # Esperar un momento
        import time
        time.sleep(2)
        
        # Verificar conexión SSH
        if not tunnel_manager.test_ssh_connection():
            return jsonify({
                'error': 'Cannot establish SSH connection after restart'
            }), 503
        
        # Reiniciar túneles
        success = tunnel_manager.start_ssh_tunnel()
        
        if success:
            return jsonify({
                'message': 'SSH tunnels restarted successfully',
                'tunnel_status': tunnel_manager.get_tunnel_status(),
                'openstack_accessible': is_openstack_accessible()
            })
        else:
            return jsonify({
                'error': 'Failed to restart SSH tunnels',
                'tunnel_status': tunnel_manager.get_tunnel_status()
            }), 500
            
    except Exception as e:
        logger.error(f"Restart tunnels error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/ssh-tunnel/test', methods=['POST'])
@token_required
def test_ssh_connection():
    """Prueba la conexión SSH a OpenStack"""
    try:
        # Probar conexión SSH básica al jumper
        ssh_ok = tunnel_manager.test_ssh_connection()
        
        # Probar conexión al headnode OpenStack
        headnode_ok = tunnel_manager.test_headnode_connection()
        
        # Probar acceso a OpenStack (si hay túneles activos)
        openstack_ok = is_openstack_accessible()
        
        result = {
            'ssh_connection': ssh_ok,
            'headnode_connection': headnode_ok,
            'openstack_accessible': openstack_ok,
            'tunnel_status': tunnel_manager.get_tunnel_status(),
            'tunnel_info': tunnel_manager.get_tunnel_info(),
            'architecture': {
                'app_server': 'localhost',
                'jumper': f"{SSH_CONFIG['jumper_host']}:{SSH_CONFIG['jumper_port']}",
                'headnode': f"{SSH_CONFIG['openstack_headnode']}",
                'flow': 'App Server -> Jumper -> Headnode'
            }
        }
        
        if ssh_ok:
            result['message'] = 'SSH connection to jumper successful'
            if headnode_ok:
                result['message'] += ', headnode reachable'
                if openstack_ok:
                    result['message'] += ', and OpenStack is accessible'
            else:
                result['message'] += ', but headnode is not reachable'
        else:
            result['error'] = 'SSH connection to jumper failed'
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Test SSH connection error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/openstack/flavors', methods=['GET'])
@token_required
def get_flavors():
    """Obtiene los flavors disponibles en OpenStack"""
    try:
        # Obtener token de autenticación si está disponible
        auth_token = request.headers.get('X-OpenStack-Token')
        
        flavor_manager = FlavorManager(
            auth_token=auth_token,
            keystone_endpoint='http://localhost:15000'
        )
        
        sync_openstack = request.args.get('sync', 'true').lower() == 'true'
        flavors = flavor_manager.get_available_flavors(sync_from_openstack=sync_openstack)
        
        # Agregar estadísticas si se solicita
        include_stats = request.args.get('stats', 'false').lower() == 'true'
        result = {'flavors': flavors}
        
        if include_stats:
            result['usage_stats'] = flavor_manager.get_flavor_usage_stats()
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Get flavors error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/openstack/availability-zones', methods=['GET'])
@token_required
def get_availability_zones():
    """Obtiene las zonas de disponibilidad"""
    try:
        auth_token = request.headers.get('X-OpenStack-Token')
        detailed = request.args.get('detailed', 'true').lower() == 'true'
        
        az_manager = AvailabilityZoneManager(
            auth_token=auth_token,
            compute_endpoint='http://localhost:15001'
        )
        
        zones = az_manager.get_availability_zones(detailed=detailed)
        
        # Agregar información de capacidad si se solicita
        include_capacity = request.args.get('capacity', 'false').lower() == 'true'
        result = {'availability_zones': zones}
        
        if include_capacity:
            result['zone_capacity'] = {}
            for zone_name in zones.keys():
                try:
                    result['zone_capacity'][zone_name] = az_manager.get_zone_capacity(zone_name)
                except Exception as e:
                    logger.warning(f"Could not get capacity for zone {zone_name}: {e}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Get availability zones error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# Auto-start SSH tunnels on service startup
@app.before_first_request
def auto_start_tunnels():
    """Inicia automáticamente los túneles SSH al arrancar el servicio"""
    if SSH_TUNNEL_CONFIG.get('auto_establish', False):
        logger.info("Auto-starting SSH tunnels...")
        try:
            if tunnel_manager.test_ssh_connection():
                start_openstack_tunnels()
                logger.info("SSH tunnels auto-started successfully")
            else:
                logger.warning("SSH connection test failed - tunnels not started")
        except Exception as e:
            logger.error(f"Failed to auto-start SSH tunnels: {e}")

if __name__ == '__main__':
    init_db()
    logger.info("Starting OpenStack Service on port 5006...")
    app.run(host='0.0.0.0', port=5006, debug=False)