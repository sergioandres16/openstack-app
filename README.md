# PUCP Cloud Orchestrator

**Sistema web para gestión de slices de red y recursos OpenStack a través de túneles SSH**

## 🎯 Descripción

PUCP Cloud Orchestrator es una aplicación web desarrollada en Flask que permite gestionar recursos de OpenStack de forma remota a través de túneles SSH. El sistema utiliza un servidor jumper/bastion para acceder de forma segura a un cluster OpenStack interno.

## 🏗️ Arquitectura

```
Tu Máquina → Jumper (10.20.12.187:5821) → OpenStack Headnode (192.168.202.1)
     ↓                    ↓                        ↓
[Web App:8080]      [SSH Tunnel]           [OpenStack Services]
```

### Componentes Principales

- **🌐 Aplicación Web** (`web_app.py`): Interfaz principal con autenticación y gestión de slices
- **🔒 Gestor SSH** (`ssh_tunnel_manager.py`): Manejo automático de túneles SSH
- **☁️ Cliente OpenStack**: Integración directa con APIs de OpenStack
- **💾 Base de Datos**: SQLite para usuarios y credenciales

## 🚀 Instalación y Configuración

### Prerrequisitos

```bash
# Python 3.8+
python3 --version

# SSH client
ssh -V

# Git
git --version
```

### 1. Clonar el Repositorio

```bash
git clone <repository-url>
cd openstack-app
```

### 2. Instalar Dependencias

```bash
pip install -r requirements.txt
```

### 3. Configurar SSH

Crear o verificar la clave SSH:

```bash
# Generar clave SSH si no existe
ssh-keygen -t rsa -b 4096 -f ~/.ssh/pucp_key

# Copiar clave al jumper
ssh-copy-id ubuntu@10.20.12.187 -p 5821
```

### 4. Configurar OpenStack (Opcional)

Editar `microservicios/openstack_config_ssh.py` si es necesario:

```python
SSH_CONFIG = {
    'jumper_host': '10.20.12.187',           # IP del jumper
    'jumper_port': 5821,                     # Puerto SSH del jumper
    'jumper_user': 'ubuntu',                 # Usuario SSH
    'openstack_headnode': '192.168.202.1',  # IP del headnode OpenStack
    'ssh_key_path': '~/.ssh/pucp_key',         # Ruta de la clave SSH
}
```

## 🏃‍♂️ Ejecución

### Método Simple (Recomendado)

```bash
python start_pucp_cloud.py
```

### Método Manual

```bash
# Solo la aplicación web (sin túneles automáticos)
python web_app.py
```

## 🌐 Acceso

Una vez iniciado, accede a:

- **Interfaz Web**: http://localhost:8080
- **Usuario por defecto**: `admin` / `admin`

## 📋 Funcionalidades

### 🔐 Autenticación
- Sistema de usuarios con base de datos SQLite
- Gestión de credenciales OpenStack por usuario
- Sesiones seguras con tokens

### ☁️ Gestión OpenStack
- **Imágenes**: Listar imágenes disponibles
- **Recursos**: Monitoreo de quotas y uso
- **Slices**: Gestión de topologías de red (próximamente)

### 🔒 Túneles SSH
- Establecimiento automático de túneles
- Monitoreo y reconexión automática
- Soporte para múltiples servicios OpenStack

### 📊 Topologías Predefinidas
- **Lineal**: Nodos conectados en serie
- **Malla**: Todos los nodos interconectados  
- **Árbol**: Estructura jerárquica
- **Anillo**: Conexión circular
- **Bus**: Nodo central con clientes

## 🔧 Configuración Avanzada

### Variables de Entorno

```bash
# Puerto de la aplicación web
export WEB_PORT=8080

# Credenciales OpenStack (opcional)
export OPENSTACK_USERNAME=admin
export OPENSTACK_PASSWORD=openstack123
export OPENSTACK_PROJECT_NAME=admin
```

### Túneles SSH Manuales

Si necesitas crear túneles manualmente:

```bash
# Túnel para Keystone (Identity)
ssh -NL 15000:192.168.202.1:5000 ubuntu@10.20.12.187 -p 5821

# Túnel para Nova (Compute)
ssh -NL 15001:192.168.202.1:8774 ubuntu@10.20.12.187 -p 5821

# Túnel para Glance (Images)  
ssh -NL 15003:192.168.202.1:9292 ubuntu@10.20.12.187 -p 5821
```

### Configuración de Credenciales OpenStack

1. Accede a **Configuración** en la interfaz web
2. Completa los campos:
   - **Auth URL**: `http://localhost:15000/identity/v3` (para túneles)
   - **Usuario**: Tu usuario OpenStack
   - **Contraseña**: Tu contraseña OpenStack
   - **Proyecto**: Nombre del proyecto
   - **Dominios**: Normalmente "Default"

## 🛠️ Desarrollo

### Estructura del Proyecto

```
openstack-app/
├── web_app.py                    # 🌐 Aplicación Flask principal
├── start_pucp_cloud.py           # 🚀 Orquestador de inicio
├── requirements.txt              # 📦 Dependencias Python
├── pucp_cloud.db                 # 💾 Base de datos SQLite
├── templates/                    # 🎨 Plantillas HTML
├── static/                       # 📁 CSS, JS, imágenes
├── microservicios/
│   ├── openstack_config_ssh.py   # ⚙️ Configuración SSH/OpenStack
│   ├── ssh_tunnel_manager.py     # 🔒 Gestión de túneles SSH
│   └── openstack_service/        # ☁️ Microservicio OpenStack
└── documentation/                # 📚 Documentación adicional
```

### Logs y Depuración

Los logs se muestran en consola. Para más detalles:

```bash
# Ejecutar con debug activado
python web_app.py
# La aplicación estará en modo debug automáticamente
```

### Testing

```bash
# Verificar conectividad SSH
ssh ubuntu@10.20.12.187 -p 5821 'echo "SSH OK"'

# Verificar túnel manual
ssh -NL 15000:192.168.202.1:5000 ubuntu@10.20.12.187 -p 5821 &
curl http://localhost:15000/v3
```

## 🔍 Troubleshooting

### Problemas Comunes

**1. Error de conexión SSH**
```bash
# Verificar conectividad
ping 10.20.12.187

# Verificar puerto SSH
nc -zv 10.20.12.187 5821

# Verificar permisos de la clave
chmod 600 ~/.ssh/id_rsa
```

**2. Túneles no se establecen**
```bash
# Verificar procesos SSH
ps aux | grep ssh

# Matar túneles existentes
pkill -f "ssh.*15000"

# Crear túnel manual
ssh -NL 15000:192.168.202.1:5000 ubuntu@10.20.12.187 -p 5821
```

**3. Error de credenciales OpenStack**
- Verificar que las credenciales sean correctas
- Asegurarse de usar la URL con túnel: `http://localhost:15000/identity/v3`
- Verificar que el túnel SSH esté activo

**4. Base de datos corrupta**
```bash
# Eliminar y recrear la base de datos
rm pucp_cloud.db
python web_app.py  # Se creará automáticamente
```

## 📖 Comandos Útiles

```bash
# Verificar túneles activos
netstat -tlnp | grep 15000

# Ver logs de SSH en tiempo real
journalctl -f | grep ssh

# Monitorear conexiones
watch 'ss -tulpn | grep 15000'

# Reiniciar aplicación
pkill -f python.*web_app.py
python start_pucp_cloud.py
```

## 🤝 Contribución

Para contribuir al proyecto:

1. Fork del repositorio
2. Crear rama feature: `git checkout -b feature/nueva-funcionalidad`
3. Commit: `git commit -am 'Agregar nueva funcionalidad'`
4. Push: `git push origin feature/nueva-funcionalidad`
5. Crear Pull Request

## 📄 Licencia

[Especificar licencia aquí]

## 📞 Soporte

Para soporte técnico o preguntas:

- **Email**: [tu-email@pucp.edu.pe]
- **Issues**: Usar el sistema de issues de GitHub
- **Wiki**: [Link a documentación adicional]

---

**Desarrollado para PUCP** 🎓

*Última actualización: Julio 2025*