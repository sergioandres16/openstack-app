#!/usr/bin/env python3
"""
PUCP Cloud Orchestrator - Orchestrator Module (UPDATED with OpenStack Service integration)
ARCHIVO ACTUALIZADO para incluir integración con OpenStack Service
"""

import logging
from typing import Optional
import requests
import os

try:
    from .drivers.base_driver import BaseDriver
    from .drivers.linux_driver import LinuxClusterDriver
except ImportError:
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from slice_service.drivers.base_driver import BaseDriver
    from slice_service.drivers.linux_driver import LinuxClusterDriver

logger = logging.getLogger(__name__)

# NUEVO: Clase para interactuar con OpenStack Service
class OpenStackServiceClient:
    """Cliente para interactuar con el OpenStack Service"""
    
    def __init__(self, service_url: str = None, token: str = None):
        self.service_url = service_url or os.getenv('OPENSTACK_SERVICE_URL', 'http://localhost:5006')
        self.token = token
        self.headers = {'Content-Type': 'application/json'}
        
        if self.token:
            self.headers['Authorization'] = f'Bearer {self.token}'
    
    def deploy_slice(self, slice_config: dict, placement: dict) -> dict:
        """Despliega slice usando OpenStack Service"""
        try:
            payload = {
                'slice_config': slice_config,
                'placement': placement
            }
            
            response = requests.post(
                f"{self.service_url}/api/openstack/deploy-slice",
                json=payload,
                headers=self.headers,
                timeout=300  # 5 minutos para deployment
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"OpenStack Service deployment failed: {response.text}")
                return {
                    'success': False,
                    'error': f'OpenStack Service error: {response.status_code}'
                }
                
        except Exception as e:
            logger.error(f"Error communicating with OpenStack Service: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def destroy_slice(self, slice_id: str, vm_list: list) -> dict:
        """Destruye slice usando OpenStack Service"""
        try:
            # Para simplificar, eliminamos las instancias individualmente
            success_count = 0
            errors = []
            
            for vm_info in vm_list:
                instance_id = vm_info.get('instance_id') or vm_info.get('id')
                if instance_id:
                    response = requests.delete(
                        f"{self.service_url}/api/openstack/instances/{instance_id}",
                        headers=self.headers,
                        timeout=60
                    )
                    
                    if response.status_code == 200:
                        success_count += 1
                    else:
                        errors.append(f"Failed to delete {vm_info.get('name', instance_id)}")
            
            return {
                'success': len(errors) == 0,
                'deleted_count': success_count,
                'errors': errors
            }
            
        except Exception as e:
            logger.error(f"Error destroying slice in OpenStack Service: {e}")
            return {
                'success': False,
                'error': str(e)
            }

# NUEVA: Clase híbrida que actúa como driver pero usa OpenStack Service
class OpenStackServiceDriver(BaseDriver):
    """Driver que usa OpenStack Service para operaciones"""
    
    def __init__(self, token: str = None):
        super().__init__()
        self.infrastructure_type = "openstack"
        self.service_client = OpenStackServiceClient(token=token)
    
    def create_vm(self, vm_config: dict, server_name: str, 
                  slice_id: str = None, networks: list = None) -> dict:
        """Crear VM usando OpenStack Service"""
        try:
            instance_config = {
                'instance_name': vm_config['name'],
                'project_id': 'pucp-default-project',  # Usar proyecto por defecto
                'image_id': vm_config.get('image', 'ubuntu-20.04'),
                'flavor_id': vm_config.get('flavor', 'small'),
                'slice_id': slice_id,
                'networks': [net.get('network_id') for net in networks] if networks else [],
                'metadata': {
                    'slice_id': slice_id,
                    'created_by': 'pucp-orchestrator'
                }
            }
            
            response = requests.post(
                f"{self.service_client.service_url}/api/openstack/instances",
                json=instance_config,
                headers=self.service_client.headers,
                timeout=120
            )
            
            if response.status_code == 201:
                data = response.json()
                return {
                    'success': True,
                    'vm_info': {
                        'id': data['openstack_instance_id'],
                        'name': vm_config['name'],
                        'status': data['status'],
                        'server': server_name,
                        'instance_id': data['openstack_instance_id']
                    }
                }
            else:
                return {
                    'success': False,
                    'error': f'OpenStack Service error: {response.text}'
                }
                
        except Exception as e:
            logger.error(f"Error creating VM via OpenStack Service: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def delete_vm(self, vm_name: str, server_name: str, cleanup_disk: bool = True) -> bool:
        """Eliminar VM usando OpenStack Service"""
        # Para simplificar, asumimos que vm_name contiene el instance_id
        try:
            response = requests.delete(
                f"{self.service_client.service_url}/api/openstack/instances/{vm_name}",
                headers=self.service_client.headers,
                timeout=60
            )
            
            return response.status_code == 200
            
        except Exception as e:
            logger.error(f"Error deleting VM via OpenStack Service: {e}")
            return False
    
    def deploy_slice(self, slice_config: dict, placement: dict) -> dict:
        """Desplegar slice usando OpenStack Service"""
        return self.service_client.deploy_slice(slice_config, placement)
    
    def destroy_slice(self, slice_id: str, vm_list: list) -> dict:
        """Destruir slice usando OpenStack Service"""
        return self.service_client.destroy_slice(slice_id, vm_list)

class Orchestrator:
    """Orquestador principal para gestión de infraestructuras (ACTUALIZADO)"""
    
    def __init__(self):
        self._driver_cache = {}
        
    def select_driver(self, infrastructure: str, token: Optional[str] = None) -> BaseDriver:
        """Selecciona y retorna el driver apropiado para la infraestructura especificada"""
        
        cache_key = f"{infrastructure}_{token or 'no_token'}"
        
        if cache_key in self._driver_cache:
            logger.debug(f"Using cached driver for {infrastructure}")
            return self._driver_cache[cache_key]
        
        driver = None
        
        try:
            if infrastructure == 'linux':
                driver = LinuxClusterDriver(token=token)
                logger.info(f"✓ Linux driver initialized")
                
            elif infrastructure == 'openstack':
                # ACTUALIZADO: Usar OpenStackServiceDriver en lugar del driver directo
                driver = OpenStackServiceDriver(token=token)
                logger.info(f"✓ OpenStack Service driver initialized")
                
            else:
                supported_types = ['linux', 'openstack']
                raise ValueError(
                    f"Unsupported infrastructure type: '{infrastructure}'. "
                    f"Supported types: {supported_types}"
                )
        
        except Exception as e:
            logger.error(f"Failed to initialize {infrastructure} driver: {e}")
            raise RuntimeError(f"Could not initialize {infrastructure} driver: {e}")
        
        self._driver_cache[cache_key] = driver
        return driver
    
    def get_available_infrastructures(self) -> list:
        """Retorna una lista de infraestructuras disponibles"""
        available = []
        
        # Verificar Linux driver
        try:
            LinuxClusterDriver()
            available.append('linux')
            logger.debug("Linux driver available")
        except Exception as e:
            logger.warning(f"Linux driver not available: {e}")
        
        # Verificar OpenStack Service
        try:
            openstack_service_url = os.getenv('OPENSTACK_SERVICE_URL', 'http://localhost:5006')
            response = requests.get(f"{openstack_service_url}/health", timeout=5)
            if response.status_code == 200:
                available.append('openstack')
                logger.debug("OpenStack Service available")
            else:
                logger.warning(f"OpenStack Service not healthy: {response.status_code}")
        except Exception as e:
            logger.warning(f"OpenStack Service not available: {e}")
        
        return available