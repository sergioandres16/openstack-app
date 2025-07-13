#!/usr/bin/env python3
"""
Configuración OpenStack actualizada para acceso via SSH
VM OpenStack: ubuntu@10.20.12.187 -p 5821
"""

import os

# Configuración de conexión SSH a OpenStack via Jumper
SSH_CONFIG = {
    'jumper_host': '10.20.12.187',  # IP del jumper/bastion
    'jumper_port': 5821,  # Puerto SSH del jumper
    'jumper_user': 'ubuntu',  # Usuario para el jumper
    'openstack_headnode': '192.168.202.1',  # IP del headnode OpenStack (red interna)
    'ssh_key_path': os.path.expanduser('~/.ssh/pucp_key'),
    'ssh_tunnel_local_port': 15000,  # Puerto local base para túneles
}

# Configuración de OpenStack (a través del túnel SSH)
OPENSTACK_CONFIG = {
    # URLs a través del túnel SSH
    'auth_url': f"http://localhost:{SSH_CONFIG['ssh_tunnel_local_port']}/identity/v3",
    'compute_url': f"http://localhost:{SSH_CONFIG['ssh_tunnel_local_port']}/compute/v2.1",
    'network_url': f"http://localhost:{SSH_CONFIG['ssh_tunnel_local_port']}/networking",
    'image_url': f"http://localhost:{SSH_CONFIG['ssh_tunnel_local_port']}/image",

    # Credenciales OpenStack
    'username': os.getenv('OPENSTACK_USERNAME', 'admin'),
    'password': os.getenv('OPENSTACK_PASSWORD', 'openstack123'),
    'project_name': os.getenv('OPENSTACK_PROJECT_NAME', 'admin'),
    'user_domain_name': os.getenv('OPENSTACK_USER_DOMAIN_NAME', 'Default'),
    'project_domain_name': os.getenv('OPENSTACK_PROJECT_DOMAIN_NAME', 'Default'),
    'region_name': os.getenv('OPENSTACK_REGION_NAME', 'RegionOne'),
    'interface': 'public',
    'identity_api_version': 3
}

# Configuración de túnel SSH para OpenStack
SSH_TUNNEL_CONFIG = {
    'enabled': True,
    'remote_openstack_auth_url': 'http://192.168.202.1:5000/v3',  # URL real del headnode
    'local_tunnel_port': SSH_CONFIG['ssh_tunnel_local_port'],
    'remote_keystone_host': '192.168.202.1',
    'remote_keystone_port': 5000,
    'auto_establish': True,
    'timeout': 30,
    'headnode_ip': '192.168.202.1'  # IP del headnode OpenStack
}

# Mapeo de puertos para servicios OpenStack via túnel
OPENSTACK_SERVICE_PORTS = {
    'keystone': {'remote': 5000, 'local': 15000},
    'nova': {'remote': 8774, 'local': 15001},
    'neutron': {'remote': 9696, 'local': 15002},
    'glance': {'remote': 9292, 'local': 15003},
    'cinder': {'remote': 8776, 'local': 15004},
    'horizon': {'remote': 80, 'local': 15005}
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

# Flavors disponibles en OpenStack remoto
VM_FLAVORS_OPENSTACK = {
    'nano': {
        'name': 'm1.nano',
        'vcpus': 1,
        'ram': 512,  # MB
        'disk': 1,  # GB
        'description': 'Nano instance (1 vCPU, 512MB RAM, 1GB disk)'
    },
    'micro': {
        'name': 'm1.micro',
        'vcpus': 1,
        'ram': 1024,
        'disk': 5,
        'description': 'Micro instance (1 vCPU, 1GB RAM, 5GB disk)'
    },
    'small': {
        'name': 'm1.small',
        'vcpus': 1,
        'ram': 1536,
        'disk': 10,
        'description': 'Small instance (1 vCPU, 1.5GB RAM, 10GB disk)'
    },
    'medium': {
        'name': 'm1.medium',
        'vcpus': 2,
        'ram': 2560,
        'disk': 20,
        'description': 'Medium instance (2 vCPU, 2.5GB RAM, 20GB disk)'
    },
    'large': {
        'name': 'm1.large',
        'vcpus': 4,
        'ram': 6144,
        'disk': 40,
        'description': 'Large instance (4 vCPU, 6GB RAM, 40GB disk)'
    }
}

# Imágenes disponibles
DEFAULT_IMAGES_OPENSTACK = {
    'ubuntu-20.04': {
        'name': 'ubuntu-20.04-server-cloudimg',
        'os_type': 'linux',
        'os_version': '20.04',
        'description': 'Ubuntu 20.04 LTS Server'
    },
    'ubuntu-22.04': {
        'name': 'ubuntu-22.04-server-cloudimg',
        'os_type': 'linux',
        'os_version': '22.04',
        'description': 'Ubuntu 22.04 LTS Server'
    },
    'centos-8': {
        'name': 'centos-8-stream-cloudimg',
        'os_type': 'linux',
        'os_version': '8',
        'description': 'CentOS 8 Stream'
    },
    'alpine': {
        'name': 'alpine-linux-cloudimg',
        'os_type': 'linux',
        'os_version': '3.18',
        'description': 'Alpine Linux (lightweight)'
    }
}

# Topologías predefinidas
PREDEFINED_TOPOLOGIES = {
    'linear': {
        'name': 'Topología Lineal',
        'description': 'Nodos conectados en serie (A → B → C → D)',
        'icon': '○—○—○—○',
        'min_nodes': 2,
        'max_nodes': 10,
        'template': {
            'nodes': [
                {'name': 'node-{i}', 'image': 'ubuntu-20.04', 'flavor': 'small'}
            ],
            'connections': [
                {'from': 'node-{i}', 'to': 'node-{i+1}', 'network': 'net-{i}'}
            ]
        }
    },
    'mesh': {
        'name': 'Topología Malla',
        'description': 'Todos los nodos conectados entre sí',
        'icon': '○⟷○\n⟨⟩⟨⟩\n○⟷○',
        'min_nodes': 3,
        'max_nodes': 8,
        'template': {
            'nodes': [
                {'name': 'node-{i}', 'image': 'ubuntu-20.04', 'flavor': 'small'}
            ],
            'connections': 'full_mesh'
        }
    },
    'tree': {
        'name': 'Topología Árbol',
        'description': 'Estructura jerárquica en árbol',
        'icon': '    ○\n   ╱ ╲\n  ○   ○\n ╱╲  ╱╲\n○  ○ ○  ○',
        'min_nodes': 3,
        'max_nodes': 15,
        'template': {
            'nodes': [
                {'name': 'root', 'image': 'ubuntu-20.04', 'flavor': 'medium'},
                {'name': 'branch-{i}', 'image': 'ubuntu-20.04', 'flavor': 'small'},
                {'name': 'leaf-{i}', 'image': 'ubuntu-20.04', 'flavor': 'micro'}
            ],
            'connections': 'tree_structure'
        }
    },
    'ring': {
        'name': 'Topología Anillo',
        'description': 'Nodos conectados en círculo',
        'icon': '○—○\n│   │\n○—○',
        'min_nodes': 3,
        'max_nodes': 12,
        'template': {
            'nodes': [
                {'name': 'node-{i}', 'image': 'ubuntu-20.04', 'flavor': 'small'}
            ],
            'connections': 'ring'
        }
    },
    'bus': {
        'name': 'Topología Bus',
        'description': 'Todos los nodos conectados a un bus central',
        'icon': '○\n│\n○═══○═══○\n│\n○',
        'min_nodes': 3,
        'max_nodes': 20,
        'template': {
            'nodes': [
                {'name': 'bus', 'image': 'ubuntu-20.04', 'flavor': 'medium'},
                {'name': 'client-{i}', 'image': 'ubuntu-20.04', 'flavor': 'small'}
            ],
            'connections': 'bus_topology'
        }
    }
}

# Configuración de recursos del sistema
SYSTEM_RESOURCES_CONFIG = {
    'monitoring': {
        'enabled': True,
        'update_interval': 30,  # segundos
        'metrics': ['cpu', 'memory', 'disk', 'network', 'instances']
    },
    'limits': {
        'max_slices_per_user': 10,
        'max_vms_per_slice': 20,
        'max_networks_per_slice': 10,
        'max_vcpus_per_user': 50,
        'max_ram_per_user': 51200,  # MB
        'max_disk_per_user': 500  # GB
    }
}

# Configuración de consolas VMs
VM_CONSOLE_CONFIG = {
    'enabled': True,
    'console_type': 'novnc',  # novnc, spice, rdp
    'token_expiration': 3600,  # 1 hora
    'base_url': f"http://localhost:{SSH_CONFIG['ssh_tunnel_local_port']}/console",
    'auto_generate_credentials': True
}


def get_ssh_command():
    """Genera comando SSH para conectar al jumper"""
    return f"ssh -p {SSH_CONFIG['jumper_port']} {SSH_CONFIG['jumper_user']}@{SSH_CONFIG['jumper_host']}"


def get_ssh_tunnel_command():
    """Genera comando para crear túnel SSH al headnode OpenStack"""
    tunnels = []
    for service, ports in OPENSTACK_SERVICE_PORTS.items():
        # Túnel desde puerto local hacia el headnode a través del jumper
        tunnels.append(f"-L {ports['local']}:{SSH_CONFIG['openstack_headnode']}:{ports['remote']}")

    tunnel_args = " ".join(tunnels)
    return f"ssh -N {tunnel_args} -p {SSH_CONFIG['jumper_port']} {SSH_CONFIG['jumper_user']}@{SSH_CONFIG['jumper_host']}"


def get_simple_tunnel_command(local_port, remote_port):
    """Genera comando para túnel simple como el ejemplo dado"""
    return f"ssh -NL {local_port}:{SSH_CONFIG['openstack_headnode']}:{remote_port} {SSH_CONFIG['jumper_user']}@{SSH_CONFIG['jumper_host']} -p {SSH_CONFIG['jumper_port']}"


def validate_ssh_connection():
    """Valida la conexión SSH al jumper"""
    import subprocess
    try:
        cmd = f"ssh -p {SSH_CONFIG['jumper_port']} -o ConnectTimeout=10 -o BatchMode=yes {SSH_CONFIG['jumper_user']}@{SSH_CONFIG['jumper_host']} 'echo OK'"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        return result.returncode == 0 and 'OK' in result.stdout
    except Exception:
        return False