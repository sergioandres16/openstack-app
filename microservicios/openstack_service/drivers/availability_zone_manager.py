#!/usr/bin/env python3
"""
Availability Zone Manager para OpenStack
Gestiona las zonas de disponibilidad para distribución de VMs
"""

import logging
import requests
from typing import Dict, List, Optional
from microservicios.edits.openstack_config_ssh import OPENSTACK_CONFIG

logger = logging.getLogger(__name__)

class AvailabilityZoneManager:
    def __init__(self, auth_token: str = None, compute_endpoint: str = None):
        self.auth_token = auth_token
        self.compute_endpoint = compute_endpoint or 'http://localhost:15001'
        
        # Zonas predefinidas (fallback)
        self.default_zones = {
            'nova': {
                'name': 'nova',
                'state': 'available',
                'hosts': ['compute-01', 'compute-02'],
                'description': 'Default availability zone'
            },
            'zone-1': {
                'name': 'zone-1',
                'state': 'available',
                'hosts': ['compute-01'],
                'description': 'Primary compute zone'
            },
            'zone-2': {
                'name': 'zone-2',
                'state': 'available',
                'hosts': ['compute-02'],
                'description': 'Secondary compute zone'
            }
        }
    
    def get_availability_zones(self, detailed: bool = True) -> Dict[str, Dict]:
        """
        Obtiene las zonas de disponibilidad disponibles
        """
        if self.auth_token:
            try:
                return self._fetch_openstack_zones(detailed)
            except Exception as e:
                logger.warning(f"No se pudieron obtener zonas de OpenStack: {e}")
                logger.info("Usando zonas predefinidas")
        
        return self.default_zones
    
    def _fetch_openstack_zones(self, detailed: bool = True) -> Dict[str, Dict]:
        """
        Obtiene zonas de disponibilidad desde OpenStack API
        """
        headers = {
            'X-Auth-Token': self.auth_token,
            'Content-Type': 'application/json'
        }
        
        endpoint = f"{self.compute_endpoint}/v2.1/os-availability-zone"
        if detailed:
            endpoint += "/detail"
        
        try:
            response = requests.get(endpoint, headers=headers, timeout=10)
            response.raise_for_status()
            
            zones_data = response.json()
            zones = {}
            
            for zone in zones_data.get('availabilityZoneInfo', []):
                zone_name = zone['zoneName']
                zones[zone_name] = {
                    'name': zone_name,
                    'state': zone['zoneState']['available'],
                    'hosts': list(zone.get('hosts', {}).keys()) if detailed else [],
                    'description': f"OpenStack availability zone: {zone_name}",
                    'host_info': zone.get('hosts', {}) if detailed else {}
                }
            
            return zones
            
        except requests.RequestException as e:
            logger.error(f"Error fetching availability zones: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error fetching zones: {e}")
            raise
    
    def get_zone_capacity(self, zone_name: str) -> Dict:
        """
        Obtiene información de capacidad de una zona específica
        """
        zones = self.get_availability_zones(detailed=True)
        zone = zones.get(zone_name)
        
        if not zone:
            raise ValueError(f"Zona de disponibilidad '{zone_name}' no encontrada")
        
        capacity = {
            'zone_name': zone_name,
            'total_hosts': len(zone['hosts']),
            'available_hosts': [],
            'host_details': {}
        }
        
        # Información detallada por host (si está disponible)
        for host_name in zone['hosts']:
            host_info = zone.get('host_info', {}).get(host_name, {})
            
            capacity['host_details'][host_name] = {
                'services': list(host_info.keys()) if host_info else ['nova-compute'],
                'status': 'active',  # Simplificado
                'estimated_capacity': {
                    'vcpus': 32,  # Valores estimados
                    'ram_mb': 65536,
                    'disk_gb': 1000
                }
            }
            
            capacity['available_hosts'].append(host_name)
        
        return capacity
    
    def suggest_zone_distribution(self, slice_config: Dict) -> Dict:
        """
        Sugiere distribución de VMs entre zonas de disponibilidad
        """
        nodes = slice_config.get('nodes', [])
        topology = slice_config.get('topology', 'linear')
        high_availability = slice_config.get('high_availability', False)
        
        zones = self.get_availability_zones()
        available_zones = [z for z in zones.keys() if zones[z]['state']]
        
        if not available_zones:
            raise ValueError("No hay zonas de disponibilidad activas")
        
        distribution = {
            'strategy': 'balanced',
            'zone_assignments': {},
            'recommendations': []
        }
        
        # Estrategias de distribución según topología
        if topology == 'mesh' and high_availability:
            # Para mesh con HA, distribuir uniformemente
            distribution['strategy'] = 'high_availability'
            distribution = self._distribute_for_ha(nodes, available_zones)
            
        elif topology == 'tree':
            # Para árbol, poner root en zona principal
            distribution['strategy'] = 'hierarchical'
            distribution = self._distribute_for_tree(nodes, available_zones)
            
        elif topology == 'linear':
            # Para lineal, distribución secuencial
            distribution['strategy'] = 'sequential'
            distribution = self._distribute_sequential(nodes, available_zones)
            
        else:
            # Distribución balanceada por defecto
            distribution = self._distribute_balanced(nodes, available_zones)
        
        return distribution
    
    def _distribute_for_ha(self, nodes: List, zones: List) -> Dict:
        """
        Distribución para alta disponibilidad
        """
        distribution = {
            'strategy': 'high_availability',
            'zone_assignments': {},
            'recommendations': [
                'VMs distribuidas entre múltiples zonas para alta disponibilidad',
                'Se evita concentrar nodos críticos en una sola zona'
            ]
        }
        
        zone_count = len(zones)
        for i, node in enumerate(nodes):
            zone = zones[i % zone_count]
            node_name = node.get('name', f'node-{i}')
            distribution['zone_assignments'][node_name] = {
                'zone': zone,
                'reason': 'Alta disponibilidad - distribución uniforme'
            }
        
        return distribution
    
    def _distribute_for_tree(self, nodes: List, zones: List) -> Dict:
        """
        Distribución jerárquica para topología árbol
        """
        distribution = {
            'strategy': 'hierarchical',
            'zone_assignments': {},
            'recommendations': [
                'Nodo raíz en zona principal para mejor rendimiento',
                'Nodos hoja distribuidos en zonas secundarias'
            ]
        }
        
        primary_zone = zones[0]
        secondary_zones = zones[1:] if len(zones) > 1 else [zones[0]]
        
        for i, node in enumerate(nodes):
            node_name = node.get('name', f'node-{i}')
            node_role = node.get('role', 'leaf')
            
            if node_role == 'root' or i == 0:
                # Nodo raíz en zona principal
                distribution['zone_assignments'][node_name] = {
                    'zone': primary_zone,
                    'reason': 'Nodo raíz en zona principal'
                }
            else:
                # Nodos hoja en zonas secundarias
                zone = secondary_zones[(i-1) % len(secondary_zones)]
                distribution['zone_assignments'][node_name] = {
                    'zone': zone,
                    'reason': 'Nodo hoja distribuido'
                }
        
        return distribution
    
    def _distribute_sequential(self, nodes: List, zones: List) -> Dict:
        """
        Distribución secuencial para topología lineal
        """
        distribution = {
            'strategy': 'sequential',
            'zone_assignments': {},
            'recommendations': [
                'Distribución secuencial respetando orden lineal',
                'Minimiza latencia entre nodos adyacentes'
            ]
        }
        
        # Para lineal, preferir mantener nodos adyacentes en la misma zona
        # o zonas cercanas
        nodes_per_zone = max(1, len(nodes) // len(zones))
        
        for i, node in enumerate(nodes):
            zone_index = i // nodes_per_zone
            if zone_index >= len(zones):
                zone_index = len(zones) - 1
                
            zone = zones[zone_index]
            node_name = node.get('name', f'node-{i}')
            
            distribution['zone_assignments'][node_name] = {
                'zone': zone,
                'reason': f'Secuencial - zona {zone_index + 1}'
            }
        
        return distribution
    
    def _distribute_balanced(self, nodes: List, zones: List) -> Dict:
        """
        Distribución balanceada por defecto
        """
        distribution = {
            'strategy': 'balanced',
            'zone_assignments': {},
            'recommendations': [
                'Distribución balanceada entre todas las zonas disponibles',
                'Optimiza utilización de recursos'
            ]
        }
        
        for i, node in enumerate(nodes):
            zone = zones[i % len(zones)]
            node_name = node.get('name', f'node-{i}')
            
            distribution['zone_assignments'][node_name] = {
                'zone': zone,
                'reason': 'Distribución balanceada'
            }
        
        return distribution
    
    def validate_zone_assignment(self, assignments: Dict) -> Dict:
        """
        Valida asignaciones de zona y reporta problemas
        """
        zones = self.get_availability_zones()
        validation = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'suggestions': []
        }
        
        for node_name, assignment in assignments.items():
            zone_name = assignment.get('zone')
            
            # Verificar que la zona existe
            if zone_name not in zones:
                validation['valid'] = False
                validation['errors'].append(
                    f"Zona '{zone_name}' no existe para nodo '{node_name}'"
                )
                continue
            
            # Verificar que la zona está disponible
            if not zones[zone_name]['state']:
                validation['valid'] = False
                validation['errors'].append(
                    f"Zona '{zone_name}' no está disponible para nodo '{node_name}'"
                )
            
            # Verificar capacidad (simplificado)
            zone_capacity = self.get_zone_capacity(zone_name)
            if zone_capacity['total_hosts'] == 0:
                validation['warnings'].append(
                    f"Zona '{zone_name}' no tiene hosts disponibles"
                )
        
        # Sugerencias de optimización
        zone_counts = {}
        for assignment in assignments.values():
            zone = assignment.get('zone')
            zone_counts[zone] = zone_counts.get(zone, 0) + 1
        
        max_nodes_per_zone = max(zone_counts.values())
        if max_nodes_per_zone > len(assignments) * 0.7:  # Más del 70% en una zona
            validation['suggestions'].append(
                "Considere distribuir mejor las VMs entre zonas para mayor disponibilidad"
            )
        
        return validation
    
    def get_zone_network_topology(self) -> Dict:
        """
        Obtiene información de topología de red entre zonas
        """
        zones = self.get_availability_zones()
        
        # Información simulada de conectividad entre zonas
        network_topology = {
            'zones': list(zones.keys()),
            'connectivity_matrix': {},
            'latency_estimates': {},
            'bandwidth_estimates': {}
        }
        
        zone_list = list(zones.keys())
        for zone1 in zone_list:
            for zone2 in zone_list:
                if zone1 == zone2:
                    latency = 0.1  # ms
                    bandwidth = 10000  # Mbps (interno)
                else:
                    latency = 2.0  # ms (entre zonas)
                    bandwidth = 1000   # Mbps (inter-zona)
                
                network_topology['connectivity_matrix'][f"{zone1}-{zone2}"] = True
                network_topology['latency_estimates'][f"{zone1}-{zone2}"] = latency
                network_topology['bandwidth_estimates'][f"{zone1}-{zone2}"] = bandwidth
        
        return network_topology