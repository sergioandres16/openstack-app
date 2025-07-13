import os

# Configuración general del orquestador (ACTUALIZADA con OpenStack Service)
ORCHESTRATOR_CONFIG = {
    'name': 'PUCP Cloud Orchestrator',
    'version': '3.0.0',
    'environment': os.getenv('ENVIRONMENT', 'production'),
    'debug': os.getenv('DEBUG', 'False').lower() == 'true',
    
    # Configuración de servicios (ACTUALIZADA)
    'services': {
        'api_gateway': {
            'host': '0.0.0.0',
            'port': 5000
        },
        'auth_service': {
            'host': '0.0.0.0',
            'port': 5001
        },
        'slice_service': {
            'host': '0.0.0.0',
            'port': 5002
        },
        'template_service': {
            'host': '0.0.0.0',
            'port': 5003
        },
        'network_service': {
            'host': '0.0.0.0',
            'port': 5004
        },
        'image_service': {
            'host': '0.0.0.0',
            'port': 5005
        },
        # NUEVO: OpenStack Service
        'openstack_service': {
            'host': '0.0.0.0',
            'port': 5006
        }
    },
    
    # Configuración de seguridad
    'security': {
        'jwt_secret_key': os.getenv('JWT_SECRET_KEY', 'pucp-cloud-secret-2025'),
        'token_expiration_hours': 24,
        'max_login_attempts': 5
    },
    
    # Configuración de infraestructuras (ACTUALIZADA)
    'infrastructures': {
        'linux': {
            'enabled': True,
            'driver': 'LinuxClusterDriver',
            'max_vms_per_slice': 20,
            'default_image': 'ubuntu-20.04-server',
            'direct_driver': True
        },
        'openstack': {
            'enabled': True,
            'driver': 'OpenStackServiceDriver',  # ACTUALIZADO
            'max_vms_per_slice': 50,
            'default_image': 'ubuntu-20.04',
            'direct_driver': False,  # NUEVO: Indica que usa microservicio
            'service_url': os.getenv('OPENSTACK_SERVICE_URL', 'http://localhost:5006')
        }
    },
    
    # Configuración de logging
    'logging': {
        'level': os.getenv('LOG_LEVEL', 'INFO'),
        'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        'file': '/var/log/pucp-orchestrator/orchestrator.log'
    }
}

# Configuración específica del cluster Linux (sin cambios)
LINUX_CLUSTER_CONFIG = {
    'cluster_name': 'PUCP Linux Cluster',
    'management_network': '192.168.201.0/24',
    'data_network_range': '10.60.0.0/16',
    'vlan_range': {
        'start': 100,
        'end': 199
    },
    'servers': {
        'server1': {
            'hostname': 'pucp-server1',
            'ip': '192.168.201.11',
            'max_vcpus': 4,
            'max_ram_gb': 8,
            'max_disk_gb': 100
        },
        'server2': {
            'hostname': 'pucp-server2',
            'ip': '192.168.201.12',
            'max_vcpus': 4,
            'max_ram_gb': 8,
            'max_disk_gb': 100
        },
        'server3': {
            'hostname': 'pucp-server3',
            'ip': '192.168.201.13',
            'max_vcpus': 4,
            'max_ram_gb': 8,
            'max_disk_gb': 100
        },
        'server4': {
            'hostname': 'pucp-server4',
            'ip': '192.168.201.14',
            'max_vcpus': 4,
            'max_ram_gb': 16,
            'max_disk_gb': 100
        }
    }
}

# Configuración específica de OpenStack (ACTUALIZADA para microservicio)
OPENSTACK_CONFIG = {
    # Configuración del microservicio
    'service_url': os.getenv('OPENSTACK_SERVICE_URL', 'http://localhost:5006'),
    'service_timeout': 300,  # 5 minutos para operaciones de deployment
    
    # Configuración de conexión directa (mantenida para referencia)
    'auth_url': os.getenv('OPENSTACK_AUTH_URL', 'http://10.60.2.21:5000/v3'),
    'username': os.getenv('OPENSTACK_USERNAME', 'admin'),
    'password': os.getenv('OPENSTACK_PASSWORD', 'openstack123'),
    'project_name': os.getenv('OPENSTACK_PROJECT_NAME', 'admin'),
    'user_domain_name': os.getenv('OPENSTACK_USER_DOMAIN_NAME', 'Default'),
    'project_domain_name': os.getenv('OPENSTACK_PROJECT_DOMAIN_NAME', 'Default'),
    'region_name': os.getenv('OPENSTACK_REGION_NAME', 'RegionOne'),
    
    # Configuración de red
    'provider_network': 'provider',
    'external_network': 'external',
    'vlan_range': {
        'start': 200,
        'end': 299
    },
    
    # NUEVO: Configuración del microservicio
    'microservice': {
        'enabled': True,
        'auto_project_creation': True,
        'default_project': 'pucp-default-project',
        'project_prefix': 'pucp-slice-',
        'cleanup_on_error': True,
        'monitoring_enabled': True
    }
}

# NUEVA: Configuración de microservicios
MICROSERVICES_CONFIG = {
    'enabled': True,
    'discovery': {
        'method': 'static',  # static, consul, etcd
        'health_check_interval': 30,
        'failure_threshold': 3
    },
    'services': {
        'openstack_service': {
            'url': os.getenv('OPENSTACK_SERVICE_URL', 'http://localhost:5006'),
            'health_endpoint': '/health',
            'timeout': 30,
            'retries': 3,
            'circuit_breaker': {
                'enabled': True,
                'failure_threshold': 5,
                'recovery_timeout': 60
            }
        }
    },
    'auth': {
        'token_forwarding': True,
        'service_to_service_auth': False
    }
}

# NUEVA: Configuración de integración entre servicios
SERVICE_INTEGRATION_CONFIG = {
    'orchestrator': {
        'openstack_service_client': {
            'base_url': os.getenv('OPENSTACK_SERVICE_URL', 'http://localhost:5006'),
            'timeout': 300,
            'retry_attempts': 3,
            'retry_delay': 5
        }
    },
    'api_gateway': {
        'route_mapping': {
            '/api/openstack': 'openstack_service'
        },
        'load_balancing': {
            'enabled': False,
            'algorithm': 'round_robin'
        }
    }
}

def get_service_url(service_name: str) -> str:
    """Obtiene URL de un servicio"""
    service_config = ORCHESTRATOR_CONFIG['services'].get(service_name)
    if service_config:
        host = service_config['host']
        port = service_config['port']
        # Convertir 0.0.0.0 a localhost para conexiones locales
        if host == '0.0.0.0':
            host = 'localhost'
        return f"http://{host}:{port}"
    return None

def is_infrastructure_enabled(infrastructure: str) -> bool:
    """Verifica si una infraestructura está habilitada"""
    infra_config = ORCHESTRATOR_CONFIG['infrastructures'].get(infrastructure, {})
    return infra_config.get('enabled', False)

def get_microservice_config(service_name: str) -> dict:
    """Obtiene configuración de un microservicio"""
    return MICROSERVICES_CONFIG['services'].get(service_name, {})

def validate_openstack_service_config() -> bool:
    """Valida configuración del OpenStack Service"""
    required_env_vars = [
        'OPENSTACK_AUTH_URL',
        'OPENSTACK_USERNAME', 
        'OPENSTACK_PASSWORD'
    ]
    
    missing_vars = []
    for var in required_env_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        print(f"Warning: Missing OpenStack environment variables: {missing_vars}")
        print("OpenStack Service will use default values")
        return False
    
    return True