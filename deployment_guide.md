# Guía de Despliegue - PUCP Cloud Orchestrator

## 📋 Preparación del Servidor

### 1. Requisitos del Sistema
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip git openssh-client netcat-openbsd

# CentOS/RHEL
sudo yum install python3 python3-pip git openssh-clients nc
```

### 2. Crear Usuario de Aplicación
```bash
sudo useradd -m -s /bin/bash pucp-cloud
sudo usermod -aG sudo pucp-cloud
su - pucp-cloud
```

### 3. Configurar SSH para OpenStack
```bash
# Generar clave SSH
ssh-keygen -t rsa -b 4096 -f ~/.ssh/pucp_openstack_key

# Copiar clave al jumper
ssh-copy-id -i ~/.ssh/pucp_openstack_key.pub -p 5821 ubuntu@10.20.12.187

# Probar conexión
ssh -i ~/.ssh/pucp_openstack_key -p 5821 ubuntu@10.20.12.187
```

## 📁 Instalación de la Aplicación

### 1. Clonar/Copiar Código
```bash
# Opción A: Si tienes git
git clone <tu-repo> /home/pucp-cloud/pucp-orchestrator

# Opción B: Copiar carpeta completa
scp -r cloud-2022/ pucp-cloud@tu-servidor:/home/pucp-cloud/pucp-orchestrator
```

### 2. Instalar Dependencias
```bash
cd /home/pucp-cloud/pucp-orchestrator
pip3 install --user -r requirements.txt

# O instalar manualmente
pip3 install --user flask flask-cors PyJWT requests paramiko sqlite3
```

### 3. Configurar Variables de Entorno
```bash
# Crear archivo de configuración
cat > ~/.env << 'EOF'
# OpenStack Credentials
OPENSTACK_USERNAME=admin
OPENSTACK_PASSWORD=tu_password_openstack
OPENSTACK_PROJECT_NAME=admin
OPENSTACK_USER_DOMAIN_NAME=Default
OPENSTACK_PROJECT_DOMAIN_NAME=Default
OPENSTACK_REGION_NAME=RegionOne

# SSH Configuration
SSH_KEY_PATH=/home/pucp-cloud/.ssh/pucp_openstack_key
JUMPER_HOST=10.20.12.187
JUMPER_PORT=5821
JUMPER_USER=ubuntu
HEADNODE_IP=192.168.202.1

# App Configuration
FLASK_SECRET_KEY=tu-clave-secreta-muy-larga-y-segura
FLASK_PORT=5000
DEBUG_MODE=False
EOF

# Cargar variables
source ~/.env
```

### 4. Configurar Aplicación
```bash
# Editar configuración principal
nano microservicios/edits/openstack_config_ssh.py
```

```python
# Actualizar con tus datos reales:
SSH_CONFIG = {
    'jumper_host': os.getenv('JUMPER_HOST', '10.20.12.187'),
    'jumper_port': int(os.getenv('JUMPER_PORT', 5821)),
    'jumper_user': os.getenv('JUMPER_USER', 'ubuntu'),
    'openstack_headnode': os.getenv('HEADNODE_IP', '192.168.202.1'),
    'ssh_key_path': os.getenv('SSH_KEY_PATH', '~/.ssh/pucp_openstack_key'),
}

OPENSTACK_CONFIG = {
    'username': os.getenv('OPENSTACK_USERNAME', 'admin'),
    'password': os.getenv('OPENSTACK_PASSWORD'),
    'project_name': os.getenv('OPENSTACK_PROJECT_NAME', 'admin'),
    'user_domain_name': os.getenv('OPENSTACK_USER_DOMAIN_NAME', 'Default'),
    'project_domain_name': os.getenv('OPENSTACK_PROJECT_DOMAIN_NAME', 'Default'),
    'region_name': os.getenv('OPENSTACK_REGION_NAME', 'RegionOne'),
}
```

## 🚀 Ejecución y Pruebas

### 1. Verificar Conectividad
```bash
# Probar SSH al jumper
ssh -i ~/.ssh/pucp_openstack_key -p 5821 ubuntu@10.20.12.187 "echo 'Jumper OK'"

# Probar conectividad al headnode
ssh -i ~/.ssh/pucp_openstack_key -p 5821 ubuntu@10.20.12.187 "ping -c 3 192.168.202.1"

# Probar puertos OpenStack
ssh -i ~/.ssh/pucp_openstack_key -p 5821 ubuntu@10.20.12.187 "nc -z 192.168.202.1 5000"
```

### 2. Iniciar Aplicación
```bash
# Método 1: Startup script completo
python3 start_pucp_cloud.py

# Método 2: Manual (para debugging)
# Terminal 1:
python3 microservicios/openstack_service/openstack_service.py

# Terminal 2:
python3 web_app.py
```

### 3. Verificar Servicios
```bash
# Verificar puertos activos
netstat -tlnp | grep :5000
netstat -tlnp | grep :5006
netstat -tlnp | grep :1500

# Verificar túneles SSH
ps aux | grep ssh
```

## 🔧 Configuración como Servicio Systemd

### 1. Crear Archivo de Servicio
```bash
sudo nano /etc/systemd/system/pucp-cloud.service
```

```ini
[Unit]
Description=PUCP Cloud Orchestrator
After=network.target

[Service]
Type=simple
User=pucp-cloud
Group=pucp-cloud
WorkingDirectory=/home/pucp-cloud/pucp-orchestrator
Environment=PATH=/home/pucp-cloud/.local/bin:/usr/bin:/bin
EnvironmentFile=/home/pucp-cloud/.env
ExecStart=/usr/bin/python3 start_pucp_cloud.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### 2. Activar Servicio
```bash
sudo systemctl daemon-reload
sudo systemctl enable pucp-cloud
sudo systemctl start pucp-cloud
sudo systemctl status pucp-cloud
```

## 📊 Monitoreo y Logs

### Ver Logs en Tiempo Real
```bash
# Logs del servicio
sudo journalctl -u pucp-cloud -f

# Logs de la aplicación
tail -f /home/pucp-cloud/pucp-orchestrator/app.log
```

### Verificar Estado
```bash
# Estado de servicios
sudo systemctl status pucp-cloud

# Procesos activos
ps aux | grep python | grep pucp

# Puertos en uso
sudo netstat -tlnp | grep python
```

## 🌐 Acceso Web

Una vez iniciado, acceder a:
- **Interfaz Principal**: http://tu-servidor:5000
- **API OpenStack**: http://tu-servidor:5006
- **Health Check**: http://tu-servidor:5000/health

## 🔒 Configuración de Firewall

```bash
# UFW (Ubuntu)
sudo ufw allow 5000/tcp
sudo ufw allow 5006/tcp
sudo ufw allow 22/tcp

# Firewalld (CentOS)
sudo firewall-cmd --permanent --add-port=5000/tcp
sudo firewall-cmd --permanent --add-port=5006/tcp
sudo firewall-cmd --reload
```

## 🔍 Troubleshooting Común

### Problema: Túneles SSH no se conectan
```bash
# Verificar clave SSH
ssh-add ~/.ssh/pucp_openstack_key

# Probar conexión manual
ssh -vvv -i ~/.ssh/pucp_openstack_key -p 5821 ubuntu@10.20.12.187

# Verificar permisos de clave
chmod 600 ~/.ssh/pucp_openstack_key
```

### Problema: OpenStack no responde
```bash
# Verificar desde el jumper
ssh -i ~/.ssh/pucp_openstack_key -p 5821 ubuntu@10.20.12.187 "curl -s http://192.168.202.1:5000"

# Verificar servicios en headnode
ssh -i ~/.ssh/pucp_openstack_key -p 5821 ubuntu@10.20.12.187 "ssh 192.168.202.1 'systemctl status openstack-keystone'"
```

### Problema: Base de datos corrupta
```bash
cd /home/pucp-cloud/pucp-orchestrator
rm -f *.db
python3 web_app.py  # Se recreará automáticamente
```