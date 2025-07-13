#!/usr/bin/env python3
"""
PUCP Private Cloud Orchestrator - API Gateway (UPDATED with OpenStack Service)
ARCHIVO ACTUALIZADO para incluir integración con OpenStack Service
"""

from flask import Flask, request, jsonify, g
from flask_cors import CORS
import logging
import traceback
import uuid
from slice_service.drivers.openstack_driver import OpenStackDriver
import time
from datetime import datetime
from functools import wraps
import jwt
import os
import requests
from typing import Dict, Any, Optional

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/pucp-orchestrator/api-gateway.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class APIGateway:
    def __init__(self):
        self.app = Flask(__name__)
        CORS(self.app)
        
        self.config = {
            'JWT_SECRET_KEY': os.getenv('JWT_SECRET_KEY', 'pucp-cloud-secret-2025'),
            'AUTH_SERVICE_URL': os.getenv('AUTH_SERVICE_URL', 'http://localhost:5001'),
            'SLICE_SERVICE_URL': os.getenv('SLICE_SERVICE_URL', 'http://localhost:5002'),
            'TEMPLATE_SERVICE_URL': os.getenv('TEMPLATE_SERVICE_URL', 'http://localhost:5003'),
            'NETWORK_SERVICE_URL': os.getenv('NETWORK_SERVICE_URL', 'http://localhost:5004'),
            'IMAGE_SERVICE_URL': os.getenv('IMAGE_SERVICE_URL', 'http://localhost:5005'),
            # NUEVO: OpenStack Service
            'OPENSTACK_SERVICE_URL': os.getenv('OPENSTACK_SERVICE_URL', 'http://localhost:5006'),
        }
        
        self.service_routes = {
            '/api/auth': self.config['AUTH_SERVICE_URL'],
            '/api/slices': self.config['SLICE_SERVICE_URL'],
            '/api/templates': self.config['TEMPLATE_SERVICE_URL'],
            '/api/networks': self.config['NETWORK_SERVICE_URL'],
            '/api/images': self.config['IMAGE_SERVICE_URL'],
            # NUEVO: Rutas OpenStack
            '/api/openstack': self.config['OPENSTACK_SERVICE_URL'],
        }
        
        self.setup_routes()
        self.setup_middleware()
    
    def setup_middleware(self):
        @self.app.before_request
        def before_request():
            g.request_id = str(uuid.uuid4())
            g.start_time = time.time()
            logger.info(f"[{g.request_id}] {request.method} {request.path} from {request.remote_addr}")
            
        @self.app.after_request
        def after_request(response):
            duration = time.time() - g.start_time
            logger.info(f"[{g.request_id}] Response: {response.status_code} in {duration:.3f}s")
            response.headers['X-Request-ID'] = g.request_id
            return response
    
    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        try:
            payload = jwt.decode(token, self.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Invalid token")
            return None
    
    def require_auth(self, f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({'error': 'Missing or invalid authorization header'}), 401
            
            token = auth_header.split(' ')[1]
            user_info = self.validate_token(token)
            if not user_info:
                return jsonify({'error': 'Invalid or expired token'}), 401
            
            g.user = user_info
            return f(*args, **kwargs)
        return decorated_function
    
    def proxy_request(self, service_url: str, path: str):
        """Proxy request con autorización corregida"""
        try:
            # Preparar URL
            if path.startswith('/api/'):
                # Para OpenStack Service, mantener /api/openstack completo
                if 'openstack' in path:
                    clean_path = path  # Mantener /api/openstack
                elif 'images' in path:
                    clean_path = path  # Mantener /api/images
                else:
                    # Para otros servicios, quitar /api/
                    clean_path = path[4:]  # Quita '/api'
            else:
                clean_path = path
                
            target_url = f"{service_url}{clean_path}"
            
            # Preparar headers base
            headers = {
                'Content-Type': 'application/json',
                'X-Request-ID': g.request_id if hasattr(g, 'request_id') else str(uuid.uuid4())
            }
            
            # CRÍTICO: Pasar header Authorization original
            auth_header = request.headers.get('Authorization')
            if auth_header:
                headers['Authorization'] = auth_header
                logger.info(f"Forwarding Authorization header: {auth_header[:20]}...")
            
            # Agregar contexto de usuario si está autenticado
            if hasattr(g, 'user'):
                headers['X-User-ID'] = str(g.user.get('user_id', ''))
                headers['X-User-Role'] = g.user.get('role', 'user')
            
            logger.info(f"Proxying {request.method} to {target_url}")
            
            timeout = 30
            
            if request.method == 'GET':
                response = requests.get(
                    target_url, 
                    params=request.args, 
                    headers=headers,
                    timeout=timeout
                )
            elif request.method == 'POST':
                json_data = request.get_json() if request.is_json else None
                response = requests.post(
                    target_url,
                    json=json_data,
                    headers=headers,
                    timeout=timeout
                )
            elif request.method == 'PUT':
                json_data = request.get_json() if request.is_json else None
                response = requests.put(
                    target_url,
                    json=json_data,
                    headers=headers,
                    timeout=timeout
                )
            elif request.method == 'DELETE':
                response = requests.delete(
                    target_url,
                    headers=headers,
                    timeout=timeout
                )
            else:
                return jsonify({'error': 'Method not supported'}), 405
            
            # Retornar respuesta del servicio
            try:
                response_data = response.json()
            except:
                response_data = {'message': response.text}
            
            return jsonify(response_data), response.status_code
            
        except requests.exceptions.Timeout:
            logger.error(f"Timeout calling {service_url}")
            return jsonify({'error': 'Service timeout'}), 504
        except requests.exceptions.ConnectionError:
            logger.error(f"Connection error to {service_url}")
            return jsonify({'error': 'Service unavailable'}), 503
        except Exception as e:
            logger.error(f"Proxy error: {e}")
            return jsonify({'error': 'Internal gateway error'}), 500
    
    def setup_routes(self):
        """Configura rutas del gateway"""
        
        @self.app.route('/health', methods=['GET'])
        def health():
            return jsonify({
                'status': 'healthy',
                'service': 'api-gateway',
                'timestamp': datetime.utcnow().isoformat(),
                'services': {
                    'auth': self.config['AUTH_SERVICE_URL'],
                    'slice': self.config['SLICE_SERVICE_URL'],
                    'template': self.config['TEMPLATE_SERVICE_URL'],
                    'network': self.config['NETWORK_SERVICE_URL'],
                    'image': self.config['IMAGE_SERVICE_URL'],
                    'openstack': self.config['OPENSTACK_SERVICE_URL']  # NUEVO
                }
            })
        
        # NUEVA RUTA: Health check específico para OpenStack Service
        @self.app.route('/health/openstack', methods=['GET'])
        def health_openstack():
            try:
                response = requests.get(
                    f"{self.config['OPENSTACK_SERVICE_URL']}/health",
                    timeout=10
                )
                if response.status_code == 200:
                    return jsonify({
                        'status': 'healthy',
                        'openstack_service': response.json()
                    })
                else:
                    return jsonify({
                        'status': 'unhealthy',
                        'error': f'OpenStack service returned {response.status_code}'
                    }), 503
            except Exception as e:
                return jsonify({
                    'status': 'unreachable',
                    'error': str(e)
                }), 503
        
        @self.app.route('/api/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
        def api_proxy(path):
            full_path = f"/api/{path}"
            
            # Determinar servicio de destino
            service_url = None
            for route_prefix, url in self.service_routes.items():
                if full_path.startswith(route_prefix):
                    service_url = url
                    break
            
            if not service_url:
                return jsonify({'error': 'Service not found'}), 404
            
            return self.proxy_request(service_url, full_path)
    
    def run(self, host='0.0.0.0', port=5000, debug=False):
        """Ejecuta el gateway"""
        logger.info(f"Starting API Gateway on {host}:{port}")
        logger.info("Registered services:")
        for route, url in self.service_routes.items():
            logger.info(f"  {route} -> {url}")
        self.app.run(host=host, port=port, debug=debug)

if __name__ == '__main__':
    gateway = APIGateway()
    gateway.run(debug=False)