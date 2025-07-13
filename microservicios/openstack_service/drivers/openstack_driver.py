#!/usr/bin/env python3
"""
PUCP Cloud Orchestrator - OpenStack Driver (Completo)
Driver para gestionar recursos en OpenStack con soporte completo para slices
"""

import logging
import time
import uuid
from typing import Dict, List, Optional, Any
from datetime import datetime

# OpenStack client imports
from keystoneauth1.identity import v3
from keystoneauth1 import session
from novaclient import client as nova_client
from neutronclient.v2_0 import client as neutron_client
from glanceclient import client as glance_client
from cinderclient import client as cinder_client

logger = logging.getLogger(__name__)

class OpenStackDriver:
    """Driver completo para gestionar recursos OpenStack"""
    
    def __init__(self, config=None):
        self.config = config or {
            'auth_url': 'http://10.60.2.21:5000/v3',
            'username': 'admin',
            'password': 'openstack123',
            'project_name': 'admin',
            'user_domain_name': 'Default',
            'project_domain_name': 'Default',
            'region_name': 'RegionOne'
        }
        
        self.auth = None
        self.session = None
        self.nova = None
        self.neutron = None
        self.glance = None
        self.cinder = None
        
        self._initialize_clients()
    
    def _initialize_clients(self):
        """Inicializa clientes OpenStack"""
        try:
            # Crear autenticación
            self.auth = v3.Password(
                auth_url=self.config['auth_url'],
                username=self.config['username'],
                password=self.config['password'],
                project_name=self.config['project_name'],
                user_domain_name=self.config['user_domain_name'],
                project_domain_name=self.config['project_domain_name']
            )
            
            # Crear sesión
            self.session = session.Session(auth=self.auth)
            
            # Inicializar clientes
            self.nova = nova_client.Client(
                '2.1', 
                session=self.session,
                region_name=self.config['region_name']
            )
            
            self.neutron = neutron_client.Client(
                session=self.session,
                region_name=self.config['region_name']
            )
            
            self.glance = glance_client.Client(
                '2',
                session=self.session,
                region_name=self.config['region_name']
            )
            
            self.cinder = cinder_client.Client(
                '3',
                session=self.session,
                region_name=self.config['region_name']
            )
            
            logger.info("OpenStack clients initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize OpenStack clients: {e}")
            raise
    
    def create_project(self, name: str, description: str = "", domain_id: str = "default") -> Dict:
        """Crear proyecto en OpenStack"""
        try:
            # Para simplificar, asumimos que el proyecto ya existe o se crea manualmente
            # En un entorno real, usarías el cliente de Keystone
            
            project_id = f"project-{str(uuid.uuid4())[:8]}"
            
            return {
                'success': True,
                'project': {
                    'id': project_id,
                    'name': name,
                    'description': description,
                    'domain_id': domain_id
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to create project: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def create_instance(self, instance_config: Dict) -> Dict:
        """Crear instancia en OpenStack"""
        try:
            # Obtener imagen
            try:
                image = self.glance.images.get(instance_config['image'])
            except:
                # Si no encuentra la imagen por ID, buscar por nombre
                images = list(self.glance.images.list(
                    filters={'name': instance_config['image']}
                ))
                if not images:
                    raise Exception(f"Image not found: {instance_config['image']}")
                image = images[0]
            
            # Obtener flavor
            try:
                flavor = self.nova.flavors.get(instance_config['flavor'])
            except:
                # Si no encuentra el flavor por ID, buscar por nombre
                flavors = self.nova.flavors.list()
                flavor = next((f for f in flavors if f.name == instance_config['flavor']), None)
                if not flavor:
                    raise Exception(f"Flavor not found: {instance_config['flavor']}")
            
            # Preparar redes
            networks = []
            if instance_config.get('networks'):
                for net_id in instance_config['networks']:
                    networks.append({'net-id': net_id})
            
            # Preparar grupos de seguridad
            security_groups = instance_config.get('security_groups', ['default'])
            
            # Crear instancia
            server = self.nova.servers.create(
                name=instance_config['name'],
                image=image.id,
                flavor=flavor.id,
                nics=networks,
                security_groups=security_groups,
                key_name=instance_config.get('key_name'),
                availability_zone=instance_config.get('availability_zone'),
                meta=instance_config.get('metadata', {})
            )
            
            logger.info(f"Instance creation initiated: {server.id}")
            
            return {
                'success': True,
                'instance': {
                    'id': server.id,
                    'name': server.name,
                    'status': server.status,
                    'flavor_id': server.flavor['id'],
                    'image_id': server.image['id'],
                    'created': server.created
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to create instance: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def delete_instance(self, instance_id: str, project_id: str = None) -> Dict:
        """Eliminar instancia de OpenStack"""
        try:
            server = self.nova.servers.get(instance_id)
            server.delete()
            
            logger.info(f"Instance deletion initiated: {instance_id}")
            
            return {
                'success': True,
                'message': f'Instance {instance_id} deletion initiated'
            }
            
        except Exception as e:
            logger.error(f"Failed to delete instance: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def create_network(self, network_config: Dict) -> Dict:
        """Crear red en OpenStack"""
        try:
            # Crear red
            network_body = {
                'network': {
                    'name': network_config['name'],
                    'admin_state_up': True
                }
            }
            
            if network_config.get('external'):
                network_body['network']['router:external'] = True
            
            network = self.neutron.create_network(network_body)
            network_id = network['network']['id']
            
            # Crear subnet
            subnet_body = {
                'subnet': {
                    'name': f"{network_config['name']}-subnet",
                    'network_id': network_id,
                    'cidr': network_config['cidr'],
                    'ip_version': 4,
                    'enable_dhcp': network_config.get('enable_dhcp', True)
                }
            }
            
            if network_config.get('gateway_ip'):
                subnet_body['subnet']['gateway_ip'] = network_config['gateway_ip']
            
            if network_config.get('dns_nameservers'):
                subnet_body['subnet']['dns_nameservers'] = network_config['dns_nameservers']
            
            subnet = self.neutron.create_subnet(subnet_body)
            
            logger.info(f"Network created: {network_id}")
            
            return {
                'success': True,
                'network': network['network'],
                'subnet': subnet['subnet']
            }
            
        except Exception as e:
            logger.error(f"Failed to create network: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def delete_network(self, network_id: str) -> Dict:
        """Eliminar red de OpenStack"""
        try:
            # Obtener subnets de la red
            subnets = self.neutron.list_subnets(network_id=network_id)
            
            # Eliminar subnets primero
            for subnet in subnets['subnets']:
                self.neutron.delete_subnet(subnet['id'])
            
            # Eliminar red
            self.neutron.delete_network(network_id)
            
            logger.info(f"Network deleted: {network_id}")
            
            return {
                'success': True,
                'message': f'Network {network_id} deleted'
            }
            
        except Exception as e:
            logger.error(f"Failed to delete network: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def list_images(self) -> Dict:
        """Listar imágenes disponibles"""
        try:
            images = list(self.glance.images.list())
            
            image_list = []
            for image in images:
                image_list.append({
                    'id': image.id,
                    'name': image.name,
                    'status': image.status,
                    'visibility': image.visibility,
                    'size': getattr(image, 'size', 0),
                    'disk_format': getattr(image, 'disk_format', 'unknown'),
                    'container_format': getattr(image, 'container_format', 'unknown'),
                    'created_at': getattr(image, 'created_at', None),
                    'updated_at': getattr(image, 'updated_at', None)
                })
            
            return {
                'success': True,
                'images': image_list
            }
            
        except Exception as e:
            logger.error(f"Failed to list images: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def list_flavors(self) -> Dict:
        """Listar flavors disponibles"""
        try:
            flavors = self.nova.flavors.list()
            
            flavor_list = []
            for flavor in flavors:
                flavor_list.append({
                    'id': flavor.id,
                    'name': flavor.name,
                    'vcpus': flavor.vcpus,
                    'ram': flavor.ram,
                    'disk': flavor.disk,
                    'ephemeral': getattr(flavor, 'ephemeral', 0),
                    'swap': getattr(flavor, 'swap', 0) or 0,
                    'rxtx_factor': getattr(flavor, 'rxtx_factor', 1.0),
                    'is_public': getattr(flavor, 'is_public', True)
                })
            
            return {
                'success': True,
                'flavors': flavor_list
            }
            
        except Exception as e:
            logger.error(f"Failed to list flavors: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_project_quotas(self, project_id: str) -> Dict:
        """Obtener quotas de un proyecto"""
        try:
            # Obtener quotas de Nova (compute)
            nova_quotas = self.nova.quotas.get(project_id)
            
            # Obtener quotas de Neutron (network)
            neutron_quotas = self.neutron.show_quota(project_id)
            
            # Obtener quotas de Cinder (volume) si está disponible
            cinder_quotas = None
            try:
                cinder_quotas = self.cinder.quotas.get(project_id)
            except:
                pass
            
            quotas = {
                'compute': {
                    'instances': nova_quotas.instances,
                    'cores': nova_quotas.cores,
                    'ram': nova_quotas.ram,
                    'floating_ips': getattr(nova_quotas, 'floating_ips', -1),
                    'security_groups': getattr(nova_quotas, 'security_groups', -1),
                    'security_group_rules': getattr(nova_quotas, 'security_group_rules', -1)
                },
                'network': {
                    'network': neutron_quotas['quota']['network'],
                    'subnet': neutron_quotas['quota']['subnet'],
                    'port': neutron_quotas['quota']['port'],
                    'router': neutron_quotas['quota']['router'],
                    'floatingip': neutron_quotas['quota']['floatingip'],
                    'security_group': neutron_quotas['quota']['security_group'],
                    'security_group_rule': neutron_quotas['quota']['security_group_rule']
                }
            }
            
            if cinder_quotas:
                quotas['volume'] = {
                    'volumes': cinder_quotas.volumes,
                    'snapshots': cinder_quotas.snapshots,
                    'gigabytes': cinder_quotas.gigabytes
                }
            
            return {
                'success': True,
                'quotas': quotas
            }
            
        except Exception as e:
            logger.error(f"Failed to get project quotas: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def deploy_slice(self, slice_config: Dict, placement: Dict) -> Dict:
        """Desplegar slice completo en OpenStack"""
        deployed_vms = []
        created_networks = []
        errors = []
        
        slice_id = slice_config.get('id', str(uuid.uuid4()))
        
        try:
            logger.info(f"Deploying slice {slice_id} in OpenStack")
            
            # 1. Crear redes primero
            for network_config in slice_config.get('networks', []):
                try:
                    network_name = f"{slice_id}-{network_config['name']}"
                    
                    net_config = {
                        'name': network_name,
                        'cidr': network_config['cidr'],
                        'gateway_ip': network_config.get('gateway'),
                        'enable_dhcp': True,
                        'dns_nameservers': network_config.get('dns_servers', ['8.8.8.8', '8.8.4.4']),
                        'external': network_config.get('network_type') == 'external'
                    }
                    
                    network_result = self.create_network(net_config)
                    
                    if network_result['success']:
                        created_networks.append({
                            'name': network_config['name'],
                            'network_id': network_result['network']['id'],
                            'subnet_id': network_result['subnet']['id'],
                            'cidr': network_config['cidr']
                        })
                        logger.info(f"✓ Network created: {network_name}")
                    else:
                        errors.append(f"Failed to create network {network_name}: {network_result['error']}")
                        
                except Exception as e:
                    error_msg = f"Error creating network {network_config['name']}: {e}"
                    logger.error(error_msg)
                    errors.append(error_msg)
            
            # 2. Crear instancias
            for vm_config in slice_config.get('nodes', []):
                vm_name = vm_config['name']
                
                if vm_name not in placement:
                    error_msg = f"No placement found for VM {vm_name}"
                    logger.error(error_msg)
                    errors.append(error_msg)
                    continue
                
                try:
                    # Preparar configuración de la instancia
                    instance_name = f"{slice_id}-{vm_name}"
                    
                    # Mapear redes creadas
                    vm_networks = []
                    for network in created_networks:
                        vm_networks.append(network['network_id'])
                    
                    instance_config = {
                        'name': instance_name,
                        'image': vm_config.get('image', 'ubuntu-20.04'),
                        'flavor': vm_config.get('flavor', 'small'),
                        'networks': vm_networks,
                        'security_groups': ['default'],
                        'availability_zone': placement[vm_name].get('availability_zone'),
                        'metadata': {
                            'slice_id': slice_id,
                            'vm_name': vm_name,
                            'created_by': 'pucp-orchestrator'
                        }
                    }
                    
                    instance_result = self.create_instance(instance_config)
                    
                    if instance_result['success']:
                        vm_info = instance_result['instance'].copy()
                        vm_info['name'] = vm_name
                        vm_info['original_name'] = instance_name
                        vm_info['placement'] = placement[vm_name]
                        
                        deployed_vms.append(vm_info)
                        logger.info(f"✓ VM created: {instance_name}")
                    else:
                        error_msg = f"Failed to create VM {vm_name}: {instance_result['error']}"
                        logger.error(error_msg)
                        errors.append(error_msg)
                        
                except Exception as e:
                    error_msg = f"Error creating VM {vm_name}: {e}"
                    logger.error(error_msg)
                    errors.append(error_msg)
            
            # 3. Esperar a que las instancias estén activas
            if deployed_vms:
                logger.info("Waiting for instances to become active...")
                self._wait_for_instances_active(deployed_vms)
            
            return {
                'slice_id': slice_id,
                'success': len(errors) == 0,
                'status': 'deployed' if len(errors) == 0 else 'partial',
                'deployed_vms': deployed_vms,
                'created_networks': created_networks,
                'errors': errors
            }
            
        except Exception as e:
            logger.error(f"Critical error deploying slice {slice_id}: {e}")
            
            # Cleanup en caso de error crítico
            self._cleanup_slice_deployment(deployed_vms, created_networks)
            
            return {
                'slice_id': slice_id,
                'success': False,
                'status': 'failed',
                'error': str(e),
                'deployed_vms': deployed_vms,
                'created_networks': created_networks
            }
    
    def destroy_slice(self, slice_id: str, vm_list: List[Dict]) -> Dict:
        """Destruir slice completo en OpenStack"""
        deleted_vms = []
        errors = []
        
        try:
            logger.info(f"Destroying slice {slice_id} in OpenStack")
            
            # 1. Eliminar instancias
            for vm_info in vm_list:
                try:
                    instance_id = vm_info.get('instance_id') or vm_info.get('id')
                    vm_name = vm_info.get('name', 'unknown')
                    
                    if not instance_id:
                        logger.warning(f"No instance ID for VM {vm_name}")
                        continue
                    
                    delete_result = self.delete_instance(instance_id)
                    
                    if delete_result['success']:
                        deleted_vms.append(vm_name)
                        logger.info(f"✓ VM {vm_name} deletion initiated")
                    else:
                        errors.append(f"Failed to delete VM {vm_name}: {delete_result['error']}")
                        
                except Exception as e:
                    error_msg = f"Error deleting VM {vm_info.get('name', 'unknown')}: {e}"
                    logger.error(error_msg)
                    errors.append(error_msg)
            
            # 2. Cleanup de redes (se hace después de que las instancias se eliminen)
            # Se podría agregar aquí la lógica para eliminar redes creadas para el slice
            
            return {
                'slice_id': slice_id,
                'success': len(errors) == 0,
                'status': 'destroyed' if len(errors) == 0 else 'partial',
                'deleted_vms': deleted_vms,
                'errors': errors
            }
            
        except Exception as e:
            logger.error(f"Critical error destroying slice {slice_id}: {e}")
            return {
                'slice_id': slice_id,
                'success': False,
                'status': 'failed',
                'error': str(e),
                'deleted_vms': deleted_vms
            }
    
    def _wait_for_instances_active(self, deployed_vms: List[Dict], timeout: int = 300):
        """Esperar a que las instancias estén activas"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            all_active = True
            
            for vm_info in deployed_vms:
                try:
                    server = self.nova.servers.get(vm_info['id'])
                    vm_info['status'] = server.status
                    
                    if server.status == 'ACTIVE':
                        # Obtener IPs
                        addresses = server.addresses
                        for network_name, network_addresses in addresses.items():
                            for addr in network_addresses:
                                if addr['OS-EXT-IPS:type'] == 'fixed':
                                    vm_info['private_ip'] = addr['addr']
                                elif addr['OS-EXT-IPS:type'] == 'floating':
                                    vm_info['public_ip'] = addr['addr']
                    elif server.status == 'ERROR':
                        vm_info['error'] = 'Instance entered ERROR state'
                        all_active = False
                    else:
                        all_active = False
                        
                except Exception as e:
                    logger.warning(f"Error checking instance status: {e}")
                    all_active = False
            
            if all_active:
                logger.info("All instances are active")
                break
                
            time.sleep(10)
        
        if time.time() - start_time >= timeout:
            logger.warning("Timeout waiting for instances to become active")
    
    def _cleanup_slice_deployment(self, deployed_vms: List[Dict], created_networks: List[Dict]):
        """Limpiar deployment fallido"""
        logger.info("Cleaning up failed deployment...")
        
        # Eliminar instancias
        for vm_info in deployed_vms:
            try:
                self.delete_instance(vm_info['id'])
                logger.info(f"Cleaned up VM: {vm_info.get('name', vm_info['id'])}")
            except Exception as e:
                logger.warning(f"Failed to cleanup VM {vm_info.get('name', vm_info['id'])}: {e}")
        
        # Eliminar redes
        for network_info in created_networks:
            try:
                self.delete_network(network_info['network_id'])
                logger.info(f"Cleaned up network: {network_info['name']}")
            except Exception as e:
                logger.warning(f"Failed to cleanup network {network_info['name']}: {e}")