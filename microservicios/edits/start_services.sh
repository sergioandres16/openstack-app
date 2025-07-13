#!/bin/bash
"""
PUCP Cloud Orchestrator - Service Startup Script (UPDATED)
Script para iniciar todos los servicios incluyendo OpenStack Service
"""

set -e

echo "🚀 Starting PUCP Cloud Orchestrator Services..."

# Configuración
BASE_DIR="/opt/pucp-orchestrator"
LOG_DIR="/var/log/pucp-orchestrator"
PID_DIR="/var/run/pucp-orchestrator"

# Crear directorios si no existen
sudo mkdir -p $LOG_DIR $PID_DIR
sudo chown ubuntu:ubuntu $LOG_DIR $PID_DIR

# Función para verificar si un puerto está en uso
check_port() {
    local port=$1
    if netstat -tuln | grep -q ":$port "; then
        echo "⚠️  Port $port is already in use"
        return 1
    fi
    return 0
}

# Función para iniciar un servicio
start_service() {
    local service_name=$1
    local service_path=$2
    local port=$3
    local log_file="$LOG_DIR/${service_name}.log"
    local pid_file="$PID_DIR/${service_name}.pid"
    
    echo "Starting $service_name on port $port..."
    
    if ! check_port $port; then
        echo "❌ Cannot start $service_name: port $port is in use"
        return 1
    fi
    
    cd $service_path
    nohup python3 ${service_name}.py > $log_file 2>&1 &
    echo $! > $pid_file
    
    # Verificar que el servicio arrancó
    sleep 2
    if kill -0 $! 2>/dev/null; then
        echo "✅ $service_name started successfully (PID: $!)"
    else
        echo "❌ Failed to start $service_name"
        return 1
    fi
}

echo "📋 Checking environment..."

# Verificar Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed"
    exit 1
fi

# Verificar dependencias críticas
python3 -c "import flask, jwt, requests" 2>/dev/null || {
    echo "❌ Missing critical Python dependencies"
    echo "Please run: pip3 install -r requirements.txt"
    exit 1
}

# Variables de entorno por defecto
export JWT_SECRET_KEY="${JWT_SECRET_KEY:-pucp-cloud-secret-2025}"
export ENVIRONMENT="${ENVIRONMENT:-production}"

# NUEVO: Variables de entorno para OpenStack Service
export OPENSTACK_SERVICE_URL="${OPENSTACK_SERVICE_URL:-http://localhost:5006}"
export OPENSTACK_AUTH_URL="${OPENSTACK_AUTH_URL:-http://10.60.2.21:5000/v3}"
export OPENSTACK_USERNAME="${OPENSTACK_USERNAME:-admin}"
export OPENSTACK_PASSWORD="${OPENSTACK_PASSWORD:-openstack123}"
export OPENSTACK_PROJECT_NAME="${OPENSTACK_PROJECT_NAME:-admin}"

echo "🏗️  Starting core services..."

# 1. Auth Service (puerto 5001)
start_service "auth_service" "$BASE_DIR/auth_service" 5001

# 2. Template Service (puerto 5003)
start_service "template_service" "$BASE_DIR/template_service" 5003

# 3. Image Service (puerto 5005)
start_service "image_service" "$BASE_DIR/image_service" 5005

# 4. Network Service (puerto 5004)
start_service "network_service" "$BASE_DIR/network_service" 5004

echo "🌟 Starting infrastructure services..."

# 5. NUEVO: OpenStack Service (puerto 5006)
echo "Starting OpenStack Service..."
if [ -d "$BASE_DIR/microservicios/openstack_service" ]; then
    start_service "openstack_service" "$BASE_DIR/microservicios/openstack_service" 5006
else
    echo "⚠️  OpenStack Service directory not found at $BASE_DIR/microservicios/openstack_service"
    echo "Creating symbolic link..."
    sudo ln -sf "$(pwd)/microservicios/openstack_service" "$BASE_DIR/microservicios/"
    start_service "openstack_service" "$BASE_DIR/microservicios/openstack_service" 5006
fi

# 6. Slice Service (puerto 5002)
start_service "slice_service" "$BASE_DIR/slice_service" 5002

echo "🌐 Starting API Gateway..."

# 7. API Gateway (puerto 5000)
start_service "api_gateway" "$BASE_DIR" 5000

echo ""
echo "🎉 All services started successfully!"
echo ""
echo "📊 Service Status:"
echo "  ✅ Auth Service      - http://localhost:5001"
echo "  ✅ Slice Service     - http://localhost:5002"
echo "  ✅ Template Service  - http://localhost:5003"
echo "  ✅ Network Service   - http://localhost:5004"
echo "  ✅ Image Service     - http://localhost:5005"
echo "  ✅ OpenStack Service - http://localhost:5006"
echo "  ✅ API Gateway       - http://localhost:5000"
echo ""
echo "🔗 API Gateway (main endpoint): http://localhost:5000"
echo ""
echo "📋 Health checks:"
echo "  curl http://localhost:5000/health"
echo "  curl http://localhost:5000/health/openstack"
echo ""
echo "📝 Logs are available in: $LOG_DIR/"
echo "🔄 PIDs are stored in: $PID_DIR/"
echo ""
echo "To stop all services: $BASE_DIR/scripts/stop_services.sh"