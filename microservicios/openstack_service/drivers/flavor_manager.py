#!/usr/bin/env python3
"""
Flavor Manager para OpenStack
Gestiona los flavors (tipos de VM) disponibles en OpenStack
"""

import logging
import requests
from typing import Dict, List, Optional
from microservicios.openstack_config_ssh import OPENSTACK_CONFIG, VM_FLAVORS_OPENSTACK

logger = logging.getLogger(__name__)

class FlavorManager:
    def __init__(self, auth_token: str = None, keystone_endpoint: str = None):
        self.auth_token = auth_token
        self.compute_endpoint = keystone_endpoint.replace(':5000', ':8774') if keystone_endpoint else 'http://localhost:15001'
        self.predefined_flavors = VM_FLAVORS_OPENSTACK
        
    def get_available_flavors(self, sync_from_openstack: bool = True) -> Dict[str, Dict]:
        """
        Obtiene flavors disponibles, combinando predefinidos con los de OpenStack
        """
        flavors = {}
        
        # Agregar flavors predefinidos
        flavors.update(self.predefined_flavors)
        
        # Sincronizar con OpenStack si es posible
        if sync_from_openstack and self.auth_token:
            try:
                openstack_flavors = self._fetch_openstack_flavors()
                flavors.update(openstack_flavors)
                logger.info(f"Sincronizados {len(openstack_flavors)} flavors desde OpenStack")
            except Exception as e:
                logger.warning(f"No se pudieron obtener flavors de OpenStack: {e}")
                logger.info("Usando flavors predefinidos únicamente")
        
        return flavors
    
    def _fetch_openstack_flavors(self) -> Dict[str, Dict]:
        """
        Obtiene flavors directamente desde OpenStack API
        """
        headers = {
            'X-Auth-Token': self.auth_token,
            'Content-Type': 'application/json'
        }
        
        try:
            # Obtener lista de flavors
            response = requests.get(
                f"{self.compute_endpoint}/v2.1/flavors/detail",
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            
            flavors_data = response.json()
            flavors = {}
            
            for flavor in flavors_data.get('flavors', []):
                flavor_id = flavor['id']
                flavor_name = flavor['name']
                
                # Convertir formato OpenStack a nuestro formato
                flavors[flavor_id] = {
                    'name': flavor_name,
                    'vcpus': flavor['vcpus'],
                    'ram': flavor['ram'],  # MB
                    'disk': flavor['disk'],  # GB
                    'description': f"OpenStack flavor: {flavor_name} ({flavor['vcpus']} vCPU, {flavor['ram']}MB RAM, {flavor['disk']}GB disk)",
                    'openstack_id': flavor_id,
                    'is_public': flavor.get('os-flavor-access:is_public', True),
                    'ephemeral': flavor.get('OS-FLV-EXT-DATA:ephemeral', 0),
                    'swap': flavor.get('swap', 0),
                    'rxtx_factor': flavor.get('rxtx_factor', 1.0),
                    'extra_specs': flavor.get('extra_specs', {})
                }
                
            return flavors
            
        except requests.RequestException as e:
            logger.error(f"Error fetching flavors from OpenStack: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error fetching flavors: {e}")
            raise
    
    def get_flavor_by_id(self, flavor_id: str) -> Optional[Dict]:
        """
        Obtiene un flavor específico por ID
        """
        flavors = self.get_available_flavors()
        return flavors.get(flavor_id)
    
    def validate_flavor(self, flavor_id: str) -> bool:
        """
        Valida que un flavor existe y está disponible
        """
        return flavor_id in self.get_available_flavors()
    
    def get_recommended_flavor(self, requirements: Dict) -> Optional[str]:
        """
        Recomienda un flavor basado en requisitos mínimos
        """
        min_vcpus = requirements.get('vcpus', 1)
        min_ram = requirements.get('ram', 512)  # MB
        min_disk = requirements.get('disk', 1)   # GB
        
        flavors = self.get_available_flavors()
        suitable_flavors = []
        
        for flavor_id, flavor_info in flavors.items():
            if (flavor_info['vcpus'] >= min_vcpus and 
                flavor_info['ram'] >= min_ram and 
                flavor_info['disk'] >= min_disk):
                suitable_flavors.append((flavor_id, flavor_info))
        
        if not suitable_flavors:
            return None
        
        # Ordenar por eficiencia (menor desperdicio de recursos)
        suitable_flavors.sort(key=lambda x: (
            x[1]['vcpus'] * 1000 + x[1]['ram'] + x[1]['disk'] * 100
        ))
        
        return suitable_flavors[0][0]  # Retornar el más eficiente
    
    def create_custom_flavor(self, flavor_config: Dict) -> Dict:
        """
        Crea un flavor personalizado en OpenStack (requiere permisos admin)
        """
        if not self.auth_token:
            raise ValueError("Se requiere token de autenticación para crear flavors")
        
        headers = {
            'X-Auth-Token': self.auth_token,
            'Content-Type': 'application/json'
        }
        
        flavor_data = {
            "flavor": {
                "name": flavor_config['name'],
                "vcpus": flavor_config['vcpus'],
                "ram": flavor_config['ram'],
                "disk": flavor_config.get('disk', 0),
                "id": flavor_config.get('id', 'auto'),
                "os-flavor-access:is_public": flavor_config.get('is_public', True)
            }
        }
        
        try:
            response = requests.post(
                f"{self.compute_endpoint}/v2.1/flavors",
                headers=headers,
                json=flavor_data,
                timeout=10
            )
            response.raise_for_status()
            
            created_flavor = response.json()['flavor']
            logger.info(f"Flavor creado: {created_flavor['name']} (ID: {created_flavor['id']})")
            
            return created_flavor
            
        except requests.RequestException as e:
            logger.error(f"Error creando flavor: {e}")
            raise
    
    def get_flavor_usage_stats(self) -> Dict:
        """
        Obtiene estadísticas de uso de flavors
        """
        # Esta función requeriría acceso a la base de datos de slices
        # para contar cuántas veces se usa cada flavor
        return {
            'most_used': 'small',
            'least_used': 'large',
            'total_instances_by_flavor': {
                'nano': 5,
                'micro': 12,
                'small': 25,
                'medium': 8,
                'large': 3
            }
        }
    
    def suggest_flavor_optimization(self, slice_requirements: Dict) -> Dict:
        """
        Sugiere optimización de flavors para un slice
        """
        topology = slice_requirements.get('topology', 'linear')
        node_count = slice_requirements.get('node_count', 3)
        workload_type = slice_requirements.get('workload_type', 'general')
        
        suggestions = {
            'recommendations': [],
            'cost_optimization': {},
            'performance_optimization': {}
        }
        
        # Recomendaciones basadas en topología
        if topology == 'mesh' and node_count > 5:
            suggestions['recommendations'].append(
                "Para topología mesh con muchos nodos, considere usar flavors 'micro' para reducir costos"
            )
        elif topology == 'tree' and workload_type == 'compute':
            suggestions['recommendations'].append(
                "Para topología árbol con carga computacional, use 'medium' para el nodo raíz y 'small' para hojas"
            )
        
        # Optimización de costos
        total_cost = self._calculate_slice_cost(slice_requirements)
        suggestions['cost_optimization'] = {
            'estimated_cost_per_hour': total_cost,
            'suggestions': [
                "Usar flavors más pequeños para nodos de prueba",
                "Considerar auto-scaling para cargas variables"
            ]
        }
        
        return suggestions
    
    def _calculate_slice_cost(self, requirements: Dict) -> float:
        """
        Calcula costo estimado de un slice (precio ficticio para demo)
        """
        base_cost_per_vcpu_hour = 0.02  # $0.02 por vCPU por hora
        base_cost_per_gb_ram_hour = 0.01  # $0.01 por GB RAM por hora
        
        total_cost = 0
        flavors = self.get_available_flavors()
        
        for node in requirements.get('nodes', []):
            flavor_id = node.get('flavor', 'small')
            flavor = flavors.get(flavor_id, flavors['small'])
            
            node_cost = (
                flavor['vcpus'] * base_cost_per_vcpu_hour +
                (flavor['ram'] / 1024) * base_cost_per_gb_ram_hour
            )
            total_cost += node_cost
        
        return round(total_cost, 4)