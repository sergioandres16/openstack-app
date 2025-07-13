# PUCP Cloud Orchestrator

Sistema completo de orquestación de nubes para la PUCP que permite gestionar slices de red con topologías predefinidas en infraestructuras híbridas (OpenStack + Linux Cluster).

## Características Principales

### 🔐 Sistema de Autenticación
- Login por usuario con JWT tokens
- Gestión de sesiones seguras
- Control de acceso por usuario

### 🌐 Topologías Predefinidas
- **Lineal**: Nodos conectados en serie (A → B → C → D)
- **Malla**: Todos los nodos conectados entre sí
- **Árbol**: Estructura jerárquica en árbol
- **Anillo**: Nodos conectados en círculo
- **Bus**: Todos los nodos conectados a un bus central

### 📊 Gestión de Slices
- Editor visual de slices con drag & drop
- Configuración de capacidad de VMs (vCPUs, RAM, disco)
- Despliegue automático en OpenStack o Linux Cluster
- Monitoreo en tiempo real del estado de slices
- Eliminación de slices con limpieza completa

### 💾 Gestión de Imágenes
- Subida de imágenes de VMs (.qcow2, .vmdk, .img, .raw)
- Validación automática de imágenes
- Soporte para imágenes públicas y privadas
- Integración con Glance (OpenStack) y libvirt

### 📈 Monitoreo de Recursos
- Vista en tiempo real del consumo de recursos
- Métricas de CPU, RAM, disco y red
- Gráficos interactivos con Chart.js
- Alertas de utilización

### 🖥️ Acceso a Consolas
- Consolas VNC para VMs OpenStack
- Consolas seriales para debugging
- Tokens temporales de acceso
- Credenciales automáticas

## Arquitectura

### Componentes Principales
- **Web Application** (`web_app.py`): Interfaz web principal con Flask
- **OpenStack Service** (`microservicios/openstack_service/`): Microservicio para OpenStack
- **SSH Tunnel Manager** (`microservicios/ssh_tunnel_manager.py`): Gestión de túneles SSH
- **Frontend**: HTML5, Bootstrap 5, jQuery, Chart.js

### Infraestructura Soportada
- **OpenStack**: Acceso remoto via SSH jumper/bastion
  - Jumper: ubuntu@10.20.12.187:5821 
  - Headnode: 192.168.202.1 (red interna)
  - Arquitectura: App Server → Jumper → Headnode
- **Linux Cluster**: Gestión local con libvirt/KVM
- **Base de Datos**: SQLite para persistencia

## Instalación

### Requisitos Previos
```bash
# Python 3.8+
python3 --version

# SSH client
ssh -V

# Dependencias Python
pip install flask flask-cors PyJWT sqlite3 requests paramiko
```

### Configuración SSH
1. Generar clave SSH si no existe:
```bash
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa
```

2. Copiar clave al jumper/bastion:
```bash
ssh-copy-id -p 5821 ubuntu@10.20.12.187
```

3. Probar conexión al jumper:
```bash
ssh -p 5821 ubuntu@10.20.12.187
```

4. Desde el jumper, verificar acceso al headnode:
```bash
# Dentro del jumper
ping 192.168.202.1
nc -z 192.168.202.1 5000  # Puerto Keystone OpenStack
```

5. Probar túnel SSH completo (ejemplo):
```bash
ssh -NL 8080:192.168.202.1:80 ubuntu@10.20.12.187 -p 5821
# Esto abre túnel del puerto local 8080 al puerto 80 del headnode
```

### Configuración de OpenStack
Editar `microservicios/edits/openstack_config_ssh.py`:
```python
SSH_CONFIG = {
    'jumper_host': '10.20.12.187',         # IP del jumper/bastion
    'jumper_port': 5821,                   # Puerto SSH del jumper
    'jumper_user': 'ubuntu',               # Usuario para el jumper
    'openstack_headnode': '192.168.202.1', # IP del headnode OpenStack
    'ssh_key_path': os.path.expanduser('~/.ssh/id_rsa'),
}

OPENSTACK_CONFIG = {
    'username': 'admin',
    'password': 'tu_password',
    'project_name': 'admin',
    # URLs serán automáticamente redirigidas a través del túnel
    # Ej: http://localhost:15000 -> 192.168.202.1:5000
}
```

## Uso

### Inicio Rápido
```bash
# Clonar o descargar el proyecto
cd cloud-2022

# Iniciar todos los servicios
python3 start_pucp_cloud.py
```

### Inicio Manual
```bash
# Terminal 1: OpenStack Service
python3 microservicios/openstack_service/openstack_service.py

# Terminal 2: Web Application
python3 web_app.py
```

### URLs de Acceso
- **Interfaz Web**: http://localhost:5000
- **API OpenStack**: http://localhost:5006
- **Documentación API**: http://localhost:5006/api/docs

### Primer Uso
1. Acceder a http://localhost:5000
2. Registrarse como nuevo usuario
3. Verificar conectividad SSH en el dashboard
4. Subir primera imagen de VM
5. Crear primer slice con topología predefinida

## Topologías Disponibles

### Topología Lineal
```
○ ─── ○ ─── ○ ─── ○
A     B     C     D
```
- **Uso**: Pruebas de latencia, routing secuencial
- **Nodos**: 2-10
- **Conexiones**: Cada nodo conectado al siguiente

### Topología Malla
```
○ ←→ ○
↕   ↕
○ ←→ ○
```
- **Uso**: Alta disponibilidad, redundancia
- **Nodos**: 3-8
- **Conexiones**: Todos los nodos conectados entre sí

### Topología Árbol
```
      ○
    ╱   ╲
   ○     ○
  ╱ ╲   ╱ ╲
 ○   ○ ○   ○
```
- **Uso**: Jerarquías, distribución de contenido
- **Nodos**: 3-15
- **Conexiones**: Estructura jerárquica

### Topología Anillo
```
○ ─── ○
│     │
○ ─── ○
```
- **Uso**: Redes token ring, redundancia circular
- **Nodos**: 3-12
- **Conexiones**: Cada nodo conectado a dos vecinos

### Topología Bus
```
○
│
○ ═══ ○ ═══ ○
│
○
```
- **Uso**: Redes compartidas, broadcast
- **Nodos**: 3-20
- **Conexiones**: Todos conectados a bus central

## API Endpoints

### Autenticación
- `POST /api/auth/login` - Login de usuario
- `POST /api/auth/register` - Registro de usuario
- `POST /api/auth/logout` - Logout

### Slices
- `GET /api/slices` - Listar slices del usuario
- `POST /api/slices` - Crear nuevo slice
- `GET /api/slices/{id}` - Obtener slice específico
- `PUT /api/slices/{id}` - Actualizar slice
- `DELETE /api/slices/{id}` - Eliminar slice
- `POST /api/slices/{id}/deploy` - Desplegar slice

### Imágenes
- `GET /api/images` - Listar imágenes
- `POST /api/images` - Subir nueva imagen
- `DELETE /api/images/{id}` - Eliminar imagen

### Recursos
- `GET /api/resources/status` - Estado de recursos
- `GET /api/resources/metrics` - Métricas detalladas

### SSH Tunnels
- `GET /api/ssh-tunnel/status` - Estado de túneles
- `POST /api/ssh-tunnel/start` - Iniciar túneles
- `POST /api/ssh-tunnel/stop` - Detener túneles
- `POST /api/ssh-tunnel/test` - Probar conexión SSH

## Resolución de Problemas

### Conexión SSH Falla
```bash
# Verificar conectividad al jumper
ping 10.20.12.187

# Probar SSH al jumper manualmente
ssh -p 5821 -v ubuntu@10.20.12.187

# Verificar clave SSH
ssh-add ~/.ssh/id_rsa

# Probar conectividad al headnode desde el jumper
ssh -p 5821 ubuntu@10.20.12.187 "ping -c 3 192.168.202.1"

# Verificar puertos OpenStack en el headnode
ssh -p 5821 ubuntu@10.20.12.187 "nc -z 192.168.202.1 5000"
```

### Túneles SSH No Se Establecen
1. Verificar que los puertos locales estén libres:
```bash
netstat -tlnp | grep 15000
```

2. Probar túnel manual:
```bash
# Ejemplo: túnel para Keystone
ssh -NL 15000:192.168.202.1:5000 ubuntu@10.20.12.187 -p 5821
```

3. Revisar logs del tunnel manager
4. Verificar configuración en `openstack_config_ssh.py`

### OpenStack No Responde
1. Verificar que el headnode OpenStack esté corriendo:
```bash
ssh -p 5821 ubuntu@10.20.12.187 "systemctl status openstack"
```

2. Comprobar puertos OpenStack en el headnode:
```bash
ssh -p 5821 ubuntu@10.20.12.187 "ss -tlnp | grep :5000"
```

3. Verificar red interna entre jumper y headnode:
```bash
ssh -p 5821 ubuntu@10.20.12.187 "traceroute 192.168.202.1"
```

4. Revisar configuración de red/firewall en ambos servidores

### Errores de Base de Datos
```bash
# Recrear base de datos
rm *.db
python3 web_app.py  # Se creará automáticamente
```

## Logs y Debugging

### Ubicación de Logs
- **Web App**: stdout/stderr
- **OpenStack Service**: logs en consola
- **SSH Tunnels**: logs del sistema

### Modo Debug
```bash
# Activar debug en Flask
export FLASK_DEBUG=1
python3 web_app.py
```

### Verificar Estado de Servicios
```bash
# Procesos activos
ps aux | grep python

# Puertos en uso
netstat -tlnp | grep :500
```

## Arquitectura de Seguridad

### Autenticación
- JWT tokens con expiración
- Hashing seguro de contraseñas
- Validación de sesiones

### Comunicación
- HTTPS recomendado para producción
- Túneles SSH encriptados
- Validación de entrada en APIs

### Aislamiento
- Slices por usuario aislados
- Recursos limitados por usuario
- Validación de permisos en todas las operaciones

## Desarrollo

### Estructura del Proyecto
```
cloud-2022/
├── web_app.py              # Aplicación web principal
├── start_pucp_cloud.py     # Script de inicio
├── templates/              # Templates HTML
├── static/                 # CSS, JS, imágenes
├── microservicios/         # Microservicios
│   ├── openstack_service/  # Servicio OpenStack
│   ├── ssh_tunnel_manager.py
│   └── edits/              # Configuraciones
├── database/               # Esquemas BD
└── conf/                   # Configuraciones
```

### Agregar Nueva Topología
1. Editar `openstack_config_ssh.py`:
```python
PREDEFINED_TOPOLOGIES['nueva'] = {
    'name': 'Nueva Topología',
    'description': 'Descripción...',
    'template': {...}
}
```

2. Actualizar frontend en `slice-create.js`

### Contribuir
1. Fork del repositorio
2. Crear branch para feature
3. Agregar tests
4. Enviar pull request

## Licencia

Proyecto académico - PUCP 2025

## Soporte

Para problemas o preguntas:
- Revisar logs del sistema
- Verificar configuración SSH
- Comprobar conectividad de red
- Contactar al equipo de desarrollo