#!/usr/bin/env python3
"""
OpenStack API Client - Cliente para interactuar con APIs de OpenStack
"""

import requests
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class OpenStackAPI:
    """Cliente API para OpenStack con manejo de tokens y endpoints"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.token = None
        self.token_expires = None
        self.catalog = {}
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
    
    def authenticate(self) -> bool:
        """Autenticar con OpenStack y obtener token"""
        try:
            auth_data = {
                "auth": {
                    "identity": {
                        "methods": ["password"],
                        "password": {
                            "user": {
                                "name": self.config['username'],
                                "domain": {"name": self.config['user_domain_name']},
                                "password": self.config['password']
                            }
                        }
                    },
                    "scope": {
                        "project": {
                            "name": self.config['project_name'],
                            "domain": {"name": self.config['project_domain_name']}
                        }
                    }
                }
            }
            
            response = self.session.post(
                f"{self.config['auth_url']}/auth/tokens",
                json=auth_data,
                timeout=30
            )
            
            if response.status_code == 201:
                self.token = response.headers.get('X-Subject-Token')
                token_data = response.json()
                
                # Guardar catálogo de servicios
                self.catalog = {}
                for service in token_data['token']['catalog']:
                    service_type = service['type']
                    for endpoint in service['endpoints']:
                        if endpoint['interface'] == self.config.get('interface', 'public'):
                            self.catalog[service_type] = endpoint['url']
                
                # Calcular expiración del token
                expires_at = token_data['token']['expires_at']
                self.token_expires = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                
                # Actualizar headers de sesión
                self.session.headers['X-Auth-Token'] = self.token
                
                logger.info("OpenStack authentication successful")
                return True
            else:
                logger.error(f"Authentication failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False
    
    def is_token_valid(self) -> bool:
        """Verificar si el token es válido"""
        if not self.token or not self.token_expires:
            return False
        
        # Considerar el token como expirado 5 minutos antes
        return datetime.utcnow() < (self.token_expires - timedelta(minutes=5))
    
    def ensure_authenticated(self) -> bool:
        """Asegurar que estamos autenticados"""
        if not self.is_token_valid():
            return self.authenticate()
        return True
    
    def get_endpoint(self, service_type: str) -> Optional[str]:
        """Obtener endpoint para un tipo de servicio"""
        return self.catalog.get(service_type)
    
    def make_request(self, method: str, service_type: str, path: str, 
                    data: Dict = None, params: Dict = None) -> Dict:
        """Hacer request a un servicio de OpenStack"""
        if not self.ensure_authenticated():
            return {
                'success': False,
                'error': 'Authentication failed'
            }
        
        endpoint = self.get_endpoint(service_type)
        if not endpoint:
            return {
                'success': False,
                'error': f'Endpoint not found for service: {service_type}'
            }
        
        url = f"{endpoint.rstrip('/')}/{path.lstrip('/')}"
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, params=params, timeout=30)
            elif method.upper() == 'POST':
                response = self.session.post(url, json=data, params=params, timeout=30)
            elif method.upper() == 'PUT':
                response = self.session.put(url, json=data, params=params, timeout=30)
            elif method.upper() == 'DELETE':
                response = self.session.delete(url, params=params, timeout=30)
            else:
                return {
                    'success': False,
                    'error': f'Unsupported HTTP method: {method}'
                }
            
            if response.status_code >= 200 and response.status_code < 300:
                try:
                    return {
                        'success': True,
                        'data': response.json() if response.content else {},
                        'status_code': response.status_code
                    }
                except json.JSONDecodeError:
                    return {
                        'success': True,
                        'data': response.text,
                        'status_code': response.status_code
                    }
            else:
                return {
                    'success': False,
                    'error': f'HTTP {response.status_code}: {response.text}',
                    'status_code': response.status_code
                }
                
        except requests.exceptions.Timeout:
            return {
                'success': False,
                'error': 'Request timeout'
            }
        except requests.exceptions.ConnectionError:
            return {
                'success': False,
                'error': 'Connection error'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    # Métodos específicos para diferentes servicios
    
    def nova_request(self, method: str, path: str, data: Dict = None, params: Dict = None) -> Dict:
        """Request a Nova (Compute)"""
        return self.make_request(method, 'compute', path, data, params)
    
    def neutron_request(self, method: str, path: str, data: Dict = None, params: Dict = None) -> Dict:
        """Request a Neutron (Network)"""
        return self.make_request(method, 'network', path, data, params)
    
    def glance_request(self, method: str, path: str, data: Dict = None, params: Dict = None) -> Dict:
        """Request a Glance (Image)"""
        return self.make_request(method, 'image', path, data, params)
    
    def cinder_request(self, method: str, path: str, data: Dict = None, params: Dict = None) -> Dict:
        """Request a Cinder (Volume)"""
        return self.make_request(method, 'volumev3', path, data, params)
    
    def keystone_request(self, method: str, path: str, data: Dict = None, params: Dict = None) -> Dict:
        """Request a Keystone (Identity)"""
        return self.make_request(method, 'identity', path, data, params)
    
    # Métodos de conveniencia para operaciones comunes
    
    def list_servers(self, project_id: str = None) -> Dict:
        """Listar servidores"""
        path = "servers/detail"
        params = {}
        if project_id:
            params['project_id'] = project_id
            
        return self.nova_request('GET', path, params=params)
    
    def create_server(self, server_config: Dict) -> Dict:
        """Crear servidor"""
        return self.nova_request('POST', 'servers', data={'server': server_config})
    
    def delete_server(self, server_id: str) -> Dict:
        """Eliminar servidor"""
        return self.nova_request('DELETE', f'servers/{server_id}')
    
    def get_server(self, server_id: str) -> Dict:
        """Obtener información de servidor"""
        return self.nova_request('GET', f'servers/{server_id}')
    
    def list_networks(self) -> Dict:
        """Listar redes"""
        return self.neutron_request('GET', 'networks')
    
    def create_network(self, network_config: Dict) -> Dict:
        """Crear red"""
        return self.neutron_request('POST', 'networks', data={'network': network_config})
    
    def delete_network(self, network_id: str) -> Dict:
        """Eliminar red"""
        return self.neutron_request('DELETE', f'networks/{network_id}')
    
    def list_subnets(self, network_id: str = None) -> Dict:
        """Listar subredes"""
        params = {}
        if network_id:
            params['network_id'] = network_id
        return self.neutron_request('GET', 'subnets', params=params)
    
    def create_subnet(self, subnet_config: Dict) -> Dict:
        """Crear subred"""
        return self.neutron_request('POST', 'subnets', data={'subnet': subnet_config})
    
    def delete_subnet(self, subnet_id: str) -> Dict:
        """Eliminar subred"""
        return self.neutron_request('DELETE', f'subnets/{subnet_id}')
    
    def list_images(self) -> Dict:
        """Listar imágenes"""
        return self.glance_request('GET', 'images')
    
    def get_image(self, image_id: str) -> Dict:
        """Obtener información de imagen"""
        return self.glance_request('GET', f'images/{image_id}')
    
    def list_flavors(self) -> Dict:
        """Listar flavors"""
        return self.nova_request('GET', 'flavors/detail')
    
    def get_flavor(self, flavor_id: str) -> Dict:
        """Obtener información de flavor"""
        return self.nova_request('GET', f'flavors/{flavor_id}')
    
    def list_volumes(self) -> Dict:
        """Listar volúmenes"""
        return self.cinder_request('GET', 'volumes/detail')
    
    def create_volume(self, volume_config: Dict) -> Dict:
        """Crear volumen"""
        return self.cinder_request('POST', 'volumes', data={'volume': volume_config})
    
    def delete_volume(self, volume_id: str) -> Dict:
        """Eliminar volumen"""
        return self.cinder_request('DELETE', f'volumes/{volume_id}')
    
    def get_quotas(self, project_id: str, service: str = 'compute') -> Dict:
        """Obtener quotas de un proyecto"""
        if service == 'compute':
            return self.nova_request('GET', f'os-quota-sets/{project_id}')
        elif service == 'network':
            return self.neutron_request('GET', f'quotas/{project_id}')
        elif service == 'volume':
            return self.cinder_request('GET', f'os-quota-sets/{project_id}')
        else:
            return {
                'success': False,
                'error': f'Unknown service for quotas: {service}'
            }