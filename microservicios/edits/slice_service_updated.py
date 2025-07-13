#!/usr/bin/env python3
"""
PUCP Cloud Orchestrator - Slice Service (UPDATED with OpenStack Service integration)
ARCHIVO ACTUALIZADO para incluir integración con OpenStack Service
"""

from flask import Flask, request, jsonify, g
from flask_cors import CORS
import sqlite3
import os
import uuid
import datetime
import json
import requests
import logging
from functools import wraps
from typing import Dict, List, Any, Optional
import jwt
from .drivers.linux_driver import LinuxClusterDriver
from .drivers.base_driver import BaseDriver
# ACTUALIZADO: Importar orchestrator actualizado
from .orchestrator import Orchestrator, OpenStackServiceClient
import ipaddress

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Configuración
app.config['DATABASE'] = os.path.join(os.path.dirname(__file__), 'slice_service.db')
app.config['SECRET_KEY'] = 'pucp-cloud-secret-2025'

# VM Flavors disponibles (compatibles con OpenStack)
VM_FLAVORS = {
    'nano': {'vcpus': 1, 'ram': 512, 'disk': 1},
    'micro': {'vcpus': 1, 'ram': 1024, 'disk': 5},
    'small': {'vcpus': 1, 'ram': 1536, 'disk': 10},
    'medium': {'vcpus': 2, 'ram': 2560, 'disk': 20},
    'large': {'vcpus': 4, 'ram': 6144, 'disk': 40}
}

def get_db():
    """Obtiene conexión a la base de datos"""
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Inicializa la base de datos con esquema mejorado"""
    with app.app_context():
        db = get_db()
        
        # Tabla principal de slices (ACTUALIZADA con campos OpenStack)
        db.execute('''
            CREATE TABLE IF NOT EXISTS slices (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                template_id TEXT,
                infrastructure TEXT NOT NULL CHECK (infrastructure IN ('linux', 'openstack')),
                availability_zone TEXT,
                status TEXT NOT NULL DEFAULT 'draft',
                placement_policy TEXT DEFAULT 'balanced',
                total_vcpus INTEGER DEFAULT 0,
                total_ram INTEGER DEFAULT 0,
                total_disk INTEGER DEFAULT 0,
                deployment_data TEXT,
                error_message TEXT,
                openstack_project_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                deployed_at TIMESTAMP,
                deleted_at TIMESTAMP
            )
        ''')
        
        # Tabla de nodos (ACTUALIZADA con campos OpenStack)
        db.execute('''
            CREATE TABLE IF NOT EXISTS nodes (
                id TEXT PRIMARY KEY,
                slice_id TEXT NOT NULL,
                name TEXT NOT NULL,
                image TEXT NOT NULL,
                flavor TEXT NOT NULL,
                assigned_host TEXT,
                vm_id TEXT,
                openstack_instance_id TEXT,
                ip_address TEXT,
                management_ip TEXT,
                floating_ip TEXT,
                internet_access BOOLEAN DEFAULT 0,
                status TEXT DEFAULT 'pending',
                console_url TEXT,
                openstack_metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (slice_id) REFERENCES slices (id) ON DELETE CASCADE
            )
        ''')
        
        # Tabla de redes (ACTUALIZADA con campos OpenStack)
        db.execute('''
            CREATE TABLE IF NOT EXISTS slice_networks (
                id TEXT PRIMARY KEY,
                slice_id TEXT NOT NULL,
                name TEXT NOT NULL,
                cidr TEXT NOT NULL,
                vlan_id INTEGER,
                openstack_network_id TEXT,
                openstack_subnet_id TEXT,
                gateway TEXT,
                dns_servers TEXT,
                network_type TEXT DEFAULT 'data',
                internet_access BOOLEAN DEFAULT 0,
                is_management BOOLEAN DEFAULT 0,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (slice_id) REFERENCES slices (id) ON DELETE CASCADE
            )
        ''')
        
        db.commit()

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
            g.auth_token = token  # NUEVO: Guardar token para pasar a servicios
        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        return f(*args, **kwargs)
    return decorated

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint (ACTUALIZADO)"""
    # Verificar disponibilidad de infraestructuras
    orchestrator = Orchestrator()
    available_infrastructures = orchestrator.get_available_infrastructures()
    
    return jsonify({
        'status': 'healthy',
        'service': 'slice',
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'available_infrastructures': available_infrastructures
    })

@app.route('/slices', methods=['POST'])
@token_required
def create_slice():
    """Crea un nuevo slice con soporte OpenStack mejorado"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400
        
        slice_id = str(uuid.uuid4())
        db = get_db()
        
        # Calcular recursos totales
        total_vcpus = total_ram = total_disk = 0
        for node in data.get('nodes', []):
            flavor = VM_FLAVORS.get(node.get('flavor', 'small'), VM_FLAVORS['small'])
            total_vcpus += flavor['vcpus']
            total_ram += flavor['ram']
            total_disk += flavor['disk']
        
        # NUEVO: Si es OpenStack, crear/obtener proyecto
        openstack_project_id = None
        if data['infrastructure'] == 'openstack':
            openstack_client = OpenStackServiceClient(token=g.auth_token)
            
            # Intentar crear proyecto específico para el slice
            project_name = f"pucp-slice-{slice_id[:8]}"
            try:
                project_response = requests.post(
                    f"{openstack_client.service_url}/api/openstack/projects",
                    json={
                        'project_name': project_name,
                        'description': f"Project for slice {data['name']}"
                    },
                    headers=openstack_client.headers,
                    timeout=30
                )
                
                if project_response.status_code == 201:
                    project_data = project_response.json()
                    openstack_project_id = project_data['openstack_project_id']
                    logger.info(f"Created OpenStack project: {openstack_project_id}")
                else:
                    # Usar proyecto por defecto si falla
                    openstack_project_id = 'pucp-default-project'
                    logger.warning(f"Failed to create project, using default: {project_response.text}")
                    
            except Exception as e:
                logger.warning(f"Project creation error, using default: {e}")
                openstack_project_id = 'pucp-default-project'
        
        try:
            # Insertar slice (ACTUALIZADO con campos OpenStack)
            db.execute('''
                INSERT INTO slices (id, user_id, name, description, template_id, 
                                  infrastructure, availability_zone, placement_policy,
                                  total_vcpus, total_ram, total_disk, openstack_project_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                slice_id, g.current_user['user_id'], data['name'],
                data.get('description'), data.get('template_id'),
                data['infrastructure'], data.get('availability_zone'),
                data.get('placement_policy', 'balanced'),
                total_vcpus, total_ram, total_disk, openstack_project_id
            ))
            
            # Insertar nodos (ACTUALIZADO con campos OpenStack)
            for node in data.get('nodes', []):
                db.execute('''
                    INSERT INTO nodes (id, slice_id, name, image, flavor, 
                                     management_ip, internet_access)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    str(uuid.uuid4()), slice_id, node['name'],
                    node['image'], node['flavor'],
                    node.get('management_ip'),
                    node.get('internet_access', False)
                ))
            
            # Insertar redes
            for network in data.get('networks', []):
                db.execute('''
                    INSERT INTO slice_networks (id, slice_id, name, cidr, vlan_id, 
                                               gateway, dns_servers, network_type, 
                                               internet_access, is_management)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    str(uuid.uuid4()), slice_id, network['name'],
                    network['cidr'], network.get('vlan_id'),
                    network.get('gateway'), 
                    json.dumps(network.get('dns_servers', [])),
                    network.get('network_type', 'data'),
                    network.get('internet_access', False),
                    network.get('network_type') == 'management'
                ))
            
            db.commit()
            logger.info(f"Slice created with infrastructure {data['infrastructure']}: {slice_id}")
            
        except Exception as e:
            db.rollback()
            logger.error(f"Database error creating slice: {e}")
            return jsonify({'error': 'Database error'}), 500
        
        response_data = {
            'id': slice_id,
            'message': f'Slice created successfully for {data["infrastructure"]} infrastructure',
            'status': 'draft',
            'infrastructure': data['infrastructure'],
            'resources': {
                'total_vcpus': total_vcpus,
                'total_ram': total_ram,
                'total_disk': total_disk
            }
        }
        
        # NUEVO: Agregar información de proyecto OpenStack si aplica
        if openstack_project_id:
            response_data['openstack_project_id'] = openstack_project_id
        
        return jsonify(response_data), 201
        
    except Exception as e:
        logger.error(f"Create slice error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/slices/<slice_id>/deploy', methods=['POST'])
@token_required
def deploy_slice(slice_id):
    """Despliega un slice (ACTUALIZADO con soporte OpenStack Service)"""
    try:
        db = get_db()
        user_id = g.current_user['user_id']
        
        # Obtener slice
        slice_row = db.execute('''
            SELECT * FROM slices WHERE id = ? AND user_id = ?
        ''', (slice_id, user_id)).fetchone()
        
        if not slice_row:
            return jsonify({'error': 'Slice not found'}), 404
        
        if slice_row['status'] == 'active':
            return jsonify({'error': 'Slice already deployed'}), 400
        
        # Obtener nodos y redes
        nodes = db.execute('''
            SELECT * FROM nodes WHERE slice_id = ?
        ''', (slice_id,)).fetchall()
        
        networks = db.execute('''
            SELECT * FROM slice_networks WHERE slice_id = ?
        ''', (slice_id,)).fetchall()
        
        if not nodes:
            return jsonify({'error': 'No nodes defined in slice'}), 400
        
        # Actualizar estado
        db.execute('''
            UPDATE slices SET status = 'deploying', updated_at = ? 
            WHERE id = ?
        ''', (datetime.datetime.utcnow().isoformat(), slice_id))
        db.commit()
        
        # Preparar configuración del slice
        slice_config = {
            'id': slice_id,
            'name': slice_row['name'],
            'infrastructure': slice_row['infrastructure'],
            'openstack_project_id': slice_row.get('openstack_project_id'),
            'nodes': [dict(node) for node in nodes],
            'networks': [dict(network) for network in networks]
        }
        
        # ACTUALIZADO: Seleccionar orchestrator según infraestructura
        orchestrator = Orchestrator()
        
        try:
            # Obtener driver apropiado (incluye token para OpenStack Service)
            driver = orchestrator.select_driver(
                slice_row['infrastructure'], 
                token=g.auth_token
            )
            
            # Calcular placement (simplificado para este ejemplo)
            placement = {}
            for i, node in enumerate(nodes):
                if slice_row['infrastructure'] == 'linux':
                    server_names = ['server1', 'server2', 'server3', 'server4']
                    placement[node['name']] = {
                        'hostname': server_names[i % len(server_names)]
                    }
                else:  # OpenStack
                    placement[node['name']] = {
                        'availability_zone': slice_row.get('availability_zone', 'nova'),
                        'project_id': slice_row.get('openstack_project_id', 'pucp-default-project')
                    }
            
            # Desplegar slice
            deployment_result = driver.deploy_slice(slice_config, placement)
            
            if deployment_result.get('success', False):
                # Actualizar estado exitoso
                db.execute('''
                    UPDATE slices SET 
                        status = 'active', 
                        deployed_at = ?,
                        deployment_data = ?,
                        updated_at = ?
                    WHERE id = ?
                ''', (
                    datetime.datetime.utcnow().isoformat(),
                    json.dumps(deployment_result),
                    datetime.datetime.utcnow().isoformat(),
                    slice_id
                ))
                
                # Actualizar nodos con información de deployment
                for vm_info in deployment_result.get('deployed_vms', []):
                    vm_name = vm_info.get('name') or vm_info.get('original_name', '').split('-')[-1]
                    
                    update_fields = {
                        'status': 'active',
                        'vm_id': vm_info.get('id'),
                        'ip_address': vm_info.get('private_ip') or vm_info.get('ip_address'),
                        'console_url': vm_info.get('console_url')
                    }
                    
                    # NUEVO: Campos específicos de OpenStack
                    if slice_row['infrastructure'] == 'openstack':
                        update_fields.update({
                            'openstack_instance_id': vm_info.get('id'),
                            'floating_ip': vm_info.get('public_ip'),
                            'openstack_metadata': json.dumps(vm_info.get('metadata', {}))
                        })
                    
                    # Construir query dinámicamente
                    set_clause = ', '.join([f"{k} = ?" for k in update_fields.keys()])
                    values = list(update_fields.values()) + [vm_name, slice_id]
                    
                    db.execute(f'''
                        UPDATE nodes SET {set_clause}
                        WHERE name = ? AND slice_id = ?
                    ''', values)
                
                db.commit()
                
                logger.info(f"Slice {slice_id} deployed successfully on {slice_row['infrastructure']}")
                
                return jsonify({
                    'message': 'Slice deployed successfully',
                    'status': 'active',
                    'infrastructure': slice_row['infrastructure'],
                    'deployed_vms': deployment_result.get('deployed_vms', []),
                    'created_networks': deployment_result.get('created_networks', [])
                })
                
            else:
                # Deployment falló
                error_msg = deployment_result.get('error', 'Unknown deployment error')
                
                db.execute('''
                    UPDATE slices SET 
                        status = 'error', 
                        error_message = ?,
                        updated_at = ?
                    WHERE id = ?
                ''', (error_msg, datetime.datetime.utcnow().isoformat(), slice_id))
                db.commit()
                
                logger.error(f"Slice {slice_id} deployment failed: {error_msg}")
                
                return jsonify({
                    'error': 'Deployment failed',
                    'details': error_msg,
                    'partial_deployment': deployment_result.get('deployed_vms', [])
                }), 500
                
        except Exception as driver_error:
            # Error del driver
            error_msg = str(driver_error)
            
            db.execute('''
                UPDATE slices SET 
                    status = 'error', 
                    error_message = ?,
                    updated_at = ?
                WHERE id = ?
            ''', (error_msg, datetime.datetime.utcnow().isoformat(), slice_id))
            db.commit()
            
            logger.error(f"Driver error for slice {slice_id}: {error_msg}")
            
            return jsonify({
                'error': 'Infrastructure driver error',
                'details': error_msg
            }), 500
        
    except Exception as e:
        logger.error(f"Deploy slice error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# ... (resto de endpoints sin cambios significativos)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5002, debug=False)