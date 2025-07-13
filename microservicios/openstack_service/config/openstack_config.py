#!/usr/bin/env python3
"""
Configuración para OpenStack Service
"""

import os

# Configuración principal de OpenStack
OPENSTACK_CONFIG = {
    'auth_url': os.getenv('OPENSTACK_AUTH_URL', 'http://10.60.2.21:5000/v3'),
    'username': os.getenv('OPENSTACK_USERNAME', 'admin'),
    'password': os.getenv('OPENSTACK_PASSWORD', 'openstack123'),
    'project_name': os.getenv('OPENSTACK_PROJECT_NAME', 'admin'),
    'user_domain_name': os.getenv('OPENSTACK_USER_DOMAIN_NAME', 'Default'),
    'project_domain_name': os.getenv('OPENSTACK_PROJECT_DOMAIN_NAME', 'Default'),
    'region_name': os.getenv('OPENSTACK_REGION_NAME', 'RegionOne'),
    'interface': os.getenv('OPENSTACK_INTERFACE', 'public'),
    'identity_api_version': 3
}

# Configuración de red por defecto
NETWORK_CONFIG = {
    'provider_network': 'provider',
    'external_network': 'external',
    'management_network': 'management',
    'dns_nameservers': ['8.8.8.8', '8.8.4.4'],
    'vlan_range': {
        'start': 200,
        'end': 299
    }
}

# Flavors por defecto que mapean a los del proyecto principal
FLAVOR_MAPPING = {
    'nano': 'm1.nano',      # 1 vCPU, 512 MB RAM, 1 GB disk
    'micro': 'm1.micro',    # 1 vCPU, 1 GB RAM, 5 GB disk
    'small': 'm1.small',    # 1 vCPU, 1.5 GB RAM, 10 GB disk
    'medium': 'm1.medium',  # 2 vCPU, 2.5 GB RAM, 20 GB disk
    'large': 'm1.large'     # 4 vCPU, 6 GB RAM, 40 GB disk
}

# Imágenes por defecto disponibles
DEFAULT_IMAGES = {
    'ubuntu-20.04': 'ubuntu-20.04-server-cloudimg',
    'ubuntu-22.04': 'ubuntu-22.04-server-cloudimg',
    'centos-8': 'centos-8-stream-cloudimg',
    'alpine-linux': 'alpine-linux-cloudimg'
}

# Configuración de quotas por defecto para nuevos proyectos
DEFAULT_QUOTAS = {
    'instances': 20,
    'cores': 40,
    'ram': 51200,  # MB
    'volumes': 10,
    'gigabytes': 100,
    'snapshots': 10,
    'networks': 10,
    'subnets': 20,
    'ports': 50,
    'routers': 10,
    'floating_ips': 10,
    'security_groups': 10,
    'security_group_rules': 100
}

# Configuración de zonas de disponibilidad
AVAILABILITY_ZONES = {
    'nova': ['nova'],
    'cinder': ['nova']
}

# Configuración de grupos de seguridad por defecto
DEFAULT_SECURITY_GROUPS = [
    {
        'name': 'pucp-default',
        'description': 'Default security group for PUCP Cloud Orchestrator',
        'rules': [
            {
                'direction': 'ingress',
                'protocol': 'tcp',
                'port_range_min': 22,
                'port_range_max': 22,
                'remote_ip_prefix': '0.0.0.0/0'
            },
            {
                'direction': 'ingress',
                'protocol': 'icmp',
                'remote_ip_prefix': '0.0.0.0/0'
            },
            {
                'direction': 'egress',
                'protocol': None,
                'remote_ip_prefix': '0.0.0.0/0'
            }
        ]
    },
    {
        'name': 'pucp-web',
        'description': 'Web server security group',
        'rules': [
            {
                'direction': 'ingress',
                'protocol': 'tcp',
                'port_range_min': 80,
                'port_range_max': 80,
                'remote_ip_prefix': '0.0.0.0/0'
            },
            {
                'direction': 'ingress',
                'protocol': 'tcp',
                'port_range_min': 443,
                'port_range_max': 443,
                'remote_ip_prefix': '0.0.0.0/0'
            }
        ]
    }
]

# Configuración de metadatos por defecto
DEFAULT_METADATA = {
    'created_by': 'pucp-orchestrator',
    'orchestrator_version': '3.0.0',
    'environment': 'production'
}

# Configuración de timeouts
TIMEOUTS = {
    'instance_creation': 300,  # 5 minutos
    'instance_deletion': 180,  # 3 minutos
    'network_creation': 60,    # 1 minuto
    'volume_creation': 120,    # 2 minutos
    'snapshot_creation': 300   # 5 minutos
}

# Configuración de monitoreo
MONITORING_CONFIG = {
    'enabled': True,
    'metrics_interval': 60,  # segundos
    'log_level': 'INFO',
    'prometheus_endpoint': None  # Se puede configurar para exportar métricas
}

# Configuración específica por entorno
ENVIRONMENT_CONFIGS = {
    'development': {
        'debug': True,
        'log_level': 'DEBUG',
        'auto_cleanup': True,
        'default_project': 'dev-project'
    },
    'staging': {
        'debug': False,
        'log_level': 'INFO',
        'auto_cleanup': False,
        'default_project': 'staging-project'
    },
    'production': {
        'debug': False,
        'log_level': 'WARNING',
        'auto_cleanup': False,
        'default_project': 'admin'
    }
}

def get_environment_config(environment='production'):
    """Obtiene configuración específica del entorno"""
    return ENVIRONMENT_CONFIGS.get(environment, ENVIRONMENT_CONFIGS['production'])

def validate_config():
    """Valida la configuración de OpenStack"""
    required_fields = ['auth_url', 'username', 'password', 'project_name']
    
    missing_fields = []
    for field in required_fields:
        if not OPENSTACK_CONFIG.get(field):
            missing_fields.append(field)
    
    if missing_fields:
        raise ValueError(f"Missing required OpenStack configuration fields: {missing_fields}")
    
    return True