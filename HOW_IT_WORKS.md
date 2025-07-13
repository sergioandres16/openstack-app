# Cómo Funciona PUCP Cloud Orchestrator

## 🏗️ Arquitectura General

```
┌─────────────────────────────────────────────────────────────────┐
│                    PUCP Cloud Orchestrator                     │
│                        (Tu Servidor)                           │
├─────────────────────────────────────────────────────────────────┤
│  Web Interface (Flask)     │  OpenStack Service (Microservicio) │
│  - Dashboard               │  - Flavor Management               │
│  - Slice Editor            │  - Availability Zones             │
│  - User Management         │  - Instance Lifecycle             │
│  - Resource Monitoring     │  - Network Management             │
└─────────────────────────────────────────────────────────────────┘
                              │
                    SSH Tunnels (Multiplexed)
                              │
               ┌─────────────────────────────┐
               │        Jumper/Bastion       │
               │     10.20.12.187:5821       │
               │       (ubuntu user)         │
               └─────────────────────────────┘
                              │
                      Red Interna (192.168.x.x)
                              │
               ┌─────────────────────────────┐
               │     OpenStack Headnode      │
               │      192.168.202.1          │
               │                             │
               │  ┌─────────────────────────┐│
               │  │   Keystone :5000        ││
               │  │   Nova     :8774        ││
               │  │   Neutron  :9696        ││
               │  │   Glance   :9292        ││
               │  │   Cinder   :8776        ││
               │  └─────────────────────────┘│
               └─────────────────────────────┘
```

## 🚀 Proceso de Despliegue y Ejecución

### 1. Preparación del Entorno

```bash
# 1. Copiar aplicación a tu servidor
scp -r cloud-2022/ usuario@tu-servidor:/opt/pucp-cloud/

# 2. Instalar dependencias
cd /opt/pucp-cloud
pip3 install -r requirements.txt

# 3. Configurar SSH
ssh-keygen -t rsa -b 4096 -f ~/.ssh/pucp_key
ssh-copy-id -i ~/.ssh/pucp_key.pub -p 5821 ubuntu@10.20.12.187
```

### 2. Configuración Automática

La aplicación se configura automáticamente usando:

```python
# microservicios/edits/openstack_config_ssh.py
SSH_CONFIG = {
    'jumper_host': '10.20.12.187',
    'jumper_port': 5821,
    'jumper_user': 'ubuntu',
    'openstack_headnode': '192.168.202.1',  # ← Tu headnode real
    'ssh_key_path': '~/.ssh/pucp_key'
}
```

### 3. Startup Automático

```bash
# Ejecutar startup script
python3 start_pucp_cloud.py
```

**Lo que hace internamente:**

1. **Verificación SSH**: Prueba conexión al jumper
2. **Test Headnode**: Verifica conectividad al headnode OpenStack
3. **Túneles SSH**: Establece túneles automáticamente:
   ```bash
   ssh -NL 15000:192.168.202.1:5000 ubuntu@10.20.12.187 -p 5821  # Keystone
   ssh -NL 15001:192.168.202.1:8774 ubuntu@10.20.12.187 -p 5821  # Nova
   ssh -NL 15002:192.168.202.1:9696 ubuntu@10.20.12.187 -p 5821  # Neutron
   ssh -NL 15003:192.168.202.1:9292 ubuntu@10.20.12.187 -p 5821  # Glance
   ```
4. **Servicios**: Inicia web app (puerto 5000) y OpenStack service (puerto 5006)

## 🔧 Gestión de Flavors

### Cómo Agarra los Flavors

```python
# 1. Flavors Predefinidos (fallback)
VM_FLAVORS_OPENSTACK = {
    'nano': {'vcpus': 1, 'ram': 512, 'disk': 1},
    'micro': {'vcpus': 1, 'ram': 1024, 'disk': 5},
    'small': {'vcpus': 1, 'ram': 1536, 'disk': 10},
    'medium': {'vcpus': 2, 'ram': 2560, 'disk': 20},
    'large': {'vcpus': 4, 'ram': 6144, 'disk': 40}
}

# 2. Sincronización con OpenStack Real
def get_available_flavors():
    # Intenta conectar a OpenStack via túnel SSH
    response = requests.get(
        'http://localhost:15001/v2.1/flavors/detail',  # ← A través del túnel
        headers={'X-Auth-Token': token}
    )
    # Combina flavors reales + predefinidos
```

### API de Flavors Disponible

```bash
# Obtener todos los flavors
curl http://tu-servidor:5006/api/openstack/flavors

# Obtener flavors con estadísticas de uso
curl http://tu-servidor:5006/api/openstack/flavors?stats=true

# Recomendar flavor basado en requisitos
curl -X POST http://tu-servidor:5006/api/openstack/flavors/recommend \
  -H "Content-Type: application/json" \
  -d '{"requirements": {"vcpus": 2, "ram": 2048, "disk": 20}}'
```

## 🏢 Gestión de Zonas de Disponibilidad

### Cómo Maneja las Availability Zones

```python
# 1. Detección Automática
def get_availability_zones():
    # Consulta a OpenStack via túnel
    response = requests.get(
        'http://localhost:15001/v2.1/os-availability-zone/detail',
        headers={'X-Auth-Token': token}
    )
    # Retorna zonas reales de tu OpenStack

# 2. Zonas Predefinidas (fallback)
default_zones = {
    'nova': {'hosts': ['compute-01', 'compute-02']},
    'zone-1': {'hosts': ['compute-01']},
    'zone-2': {'hosts': ['compute-02']}
}
```

### Distribución Inteligente por Topología

```python
# Ejemplo: Topología Mesh con Alta Disponibilidad
slice_config = {
    'topology': 'mesh',
    'nodes': [
        {'name': 'node-1', 'flavor': 'small'},
        {'name': 'node-2', 'flavor': 'small'},
        {'name': 'node-3', 'flavor': 'small'},
        {'name': 'node-4', 'flavor': 'small'}
    ],
    'high_availability': True
}

# El sistema automáticamente distribuye:
distribution = {
    'node-1': {'zone': 'zone-1', 'reason': 'HA - distribución uniforme'},
    'node-2': {'zone': 'zone-2', 'reason': 'HA - distribución uniforme'},
    'node-3': {'zone': 'zone-1', 'reason': 'HA - distribución uniforme'},
    'node-4': {'zone': 'zone-2', 'reason': 'HA - distribución uniforme'}
}
```

### API de Availability Zones

```bash
# Obtener zonas disponibles
curl http://tu-servidor:5006/api/openstack/availability-zones

# Obtener zonas con información de capacidad
curl http://tu-servidor:5006/api/openstack/availability-zones?capacity=true

# Sugerir distribución para un slice
curl -X POST http://tu-servidor:5006/api/openstack/availability-zones/suggest \
  -H "Content-Type: application/json" \
  -d '{
    "slice_config": {
      "topology": "tree",
      "nodes": [...],
      "high_availability": true
    }
  }'
```

## 🔄 Flujo Completo de Creación de Slice

### 1. Usuario Crea Slice

```
Web Interface → JavaScript → Web App (Flask) → OpenStack Service → OpenStack API
```

### 2. Proceso Interno

```python
# 1. Selección de Topología
topology = 'mesh'  # Usuario selecciona

# 2. Optimización Automática de Flavors
flavor_manager.suggest_flavor_optimization(slice_config)
# Resultado: usa 'small' para nodos normales, 'medium' para nodos críticos

# 3. Distribución de Zonas
az_manager.suggest_zone_distribution(slice_config)
# Resultado: distribuye entre zone-1 y zone-2 para HA

# 4. Creación de Recursos
for node in nodes:
    # Crea VM en OpenStack
    nova_client.servers.create(
        name=node['name'],
        image=node['image'],
        flavor=node['flavor'],
        availability_zone=node['zone'],
        networks=[{'uuid': network_id}]
    )

# 5. Configuración de Red
neutron_client.create_network(...)
neutron_client.create_subnet(...)
neutron_client.create_router(...)
```

## 📊 Monitoreo en Tiempo Real

### Cómo Funciona el Monitoreo

```python
# 1. Recolección de Métricas
def get_resource_status():
    # OpenStack
    openstack_metrics = {
        'instances': len(nova_client.servers.list()),
        'vcpu_usage': sum(server.flavor['vcpus'] for server in servers),
        'ram_usage': sum(server.flavor['ram'] for server in servers)
    }
    
    # Linux Cluster (si aplica)
    linux_metrics = {
        'cpu_percent': psutil.cpu_percent(),
        'memory_usage': psutil.virtual_memory(),
        'disk_usage': psutil.disk_usage('/')
    }
    
    return combined_metrics

# 2. Auto-refresh Frontend
setInterval(function() {
    $.get('/api/resources/status', function(data) {
        updateCharts(data);
        updateProgressBars(data);
    });
}, 30000);  // Cada 30 segundos
```

## 🔍 Debugging y Troubleshooting

### Logs y Diagnósticos

```bash
# Ver logs en tiempo real
sudo journalctl -u pucp-cloud -f

# Verificar túneles SSH
ps aux | grep ssh | grep 192.168.202.1

# Probar conectividad manualmente
ssh -i ~/.ssh/pucp_key -p 5821 ubuntu@10.20.12.187 "curl -s http://192.168.202.1:5000"

# Verificar servicios OpenStack en headnode
ssh -i ~/.ssh/pucp_key -p 5821 ubuntu@10.20.12.187 "ssh 192.168.202.1 'systemctl status openstack-keystone'"

# Test API endpoints
curl http://localhost:5006/api/ssh-tunnel/status
curl http://localhost:5006/api/openstack/flavors
curl http://localhost:5006/api/openstack/availability-zones
```

### Problemas Comunes y Soluciones

1. **Túneles SSH no se conectan**
   ```bash
   # Verificar permisos de clave SSH
   chmod 600 ~/.ssh/pucp_key
   
   # Probar conexión manual
   ssh -vvv -i ~/.ssh/pucp_key -p 5821 ubuntu@10.20.12.187
   ```

2. **OpenStack no responde**
   ```bash
   # Verificar servicios en headnode
   ssh -i ~/.ssh/pucp_key -p 5821 ubuntu@10.20.12.187 "ssh 192.168.202.1 'ps aux | grep keystone'"
   ```

3. **Flavors no se cargan**
   ```bash
   # Verificar túnel Nova
   netstat -tlnp | grep 15001
   curl http://localhost:15001/v2.1/flavors
   ```

## 🎯 Ventajas de Esta Arquitectura

### ✅ Beneficios

1. **Transparencia**: La app funciona como si OpenStack fuera local
2. **Seguridad**: Todo tráfico va cifrado por SSH
3. **Flexibilidad**: Funciona con cualquier OpenStack detrás de jumper
4. **Resilencia**: Auto-reconexión de túneles si se caen
5. **Escalabilidad**: Fácil agregar más servicios OpenStack

### 🔧 Mantenimiento

```bash
# Restart servicios
sudo systemctl restart pucp-cloud

# Actualizar aplicación
cd /opt/pucp-cloud
git pull origin main  # Si usas git
sudo systemctl restart pucp-cloud

# Backup base de datos
cp *.db backup/

# Monitoreo de recursos
htop
df -h
netstat -tlnp
```

Esta arquitectura te permite gestionar OpenStack remotamente de forma segura y eficiente, con una interfaz web moderna que abstrae toda la complejidad de la conexión SSH y los túneles.