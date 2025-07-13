# PUCP Cloud Orchestrator - Microservicios

## OpenStack Service

Este directorio contiene el microservicio dedicado para la gestión de recursos OpenStack, diseñado para integrarse perfectamente con el PUCP Cloud Orchestrator existente.

### Estructura del Proyecto

```
microservicios/
├── openstack_service/
│   ├── openstack_service.py          # Servicio principal Flask
│   ├── requirements.txt              # Dependencias específicas
│   ├── Dockerfile                    # Imagen Docker
│   ├── config/
│   │   ├── __init__.py
│   │   └── openstack_config.py       # Configuración OpenStack
│   ├── drivers/
│   │   ├── __init__.py
│   │   └── openstack_driver.py       # Driver OpenStack completo
│   ├── api/
│   │   ├── __init__.py
│   │   └── openstack_api.py          # Cliente API OpenStack
│   └── tests/
│       └── test_openstack_service.py
└── edits/
    ├── api_gateway_updated.py         # API Gateway integrado
    ├── slice_service_updated.py       # Slice Service integrado
    ├── config_updated.py              # Configuración actualizada
    └── requirements_updated.txt       # Requirements actualizados
```

### Características del OpenStack Service

#### 🎯 Funcionalidades Principales

- **Gestión de Proyectos**: Crear y administrar proyectos OpenStack
- **Instancias**: Crear, listar, y eliminar instancias/VMs
- **Redes**: Gestión completa de redes y subredes
- **Volúmenes**: Administración de almacenamiento
- **Imágenes y Flavors**: Listado de recursos disponibles
- **Quotas**: Consulta de límites de recursos
- **Deployment de Slices**: Despliegue completo de topologías

#### 🔌 Endpoints API

```
GET  /health                          # Health check
GET  /api/openstack/projects          # Listar proyectos
POST /api/openstack/projects          # Crear proyecto
GET  /api/openstack/instances         # Listar instancias
POST /api/openstack/instances         # Crear instancia
DELETE /api/openstack/instances/{id}  # Eliminar instancia
GET  /api/openstack/networks          # Listar redes
POST /api/openstack/networks          # Crear red
GET  /api/openstack/images            # Listar imágenes
GET  /api/openstack/flavors           # Listar flavors
GET  /api/openstack/quotas/{id}       # Obtener quotas
POST /api/openstack/deploy-slice      # Desplegar slice completo
```

#### 🔐 Autenticación y Seguridad

- Integración completa con el sistema JWT del proyecto principal
- Validación de tokens en cada endpoint protegido
- Headers de autorización forwarded desde API Gateway
- Contexto de usuario preservado en todas las operaciones

### Integración con el Proyecto Principal

#### 1. API Gateway
- Nueva ruta `/api/openstack` que redirecciona al OpenStack Service
- Health check específico en `/health/openstack`
- Forwarding automático de tokens de autenticación

#### 2. Slice Service
- Orchestrator actualizado para usar OpenStack Service
- Nuevo `OpenStackServiceDriver` que interactúa vía HTTP/REST
- Soporte para deployment híbrido (Linux + OpenStack)

#### 3. Configuración
- Variables de entorno para OpenStack añadidas
- Configuración de microservicios habilitada
- Service discovery estático implementado

### Instalación y Deployment

#### Opción 1: Instalación Manual

```bash
# 1. Instalar dependencias del OpenStack Service
cd microservicios/openstack_service
pip install -r requirements.txt

# 2. Configurar variables de entorno
export OPENSTACK_AUTH_URL="http://10.60.2.21:5000/v3"
export OPENSTACK_USERNAME="admin"
export OPENSTACK_PASSWORD="openstack123"
export OPENSTACK_PROJECT_NAME="admin"

# 3. Iniciar OpenStack Service
python3 openstack_service.py

# 4. Aplicar archivos editados al proyecto principal
cp ../edits/api_gateway_updated.py ../../api_gateway.py
cp ../edits/config_updated.py ../../config.py
# ... (aplicar otros archivos según sea necesario)

# 5. Reiniciar servicios principales
./scripts/restart_services.sh
```

#### Opción 2: Docker Compose

```bash
# Usar docker-compose actualizado
cp microservicios/edits/docker-compose.yml ./
docker-compose up -d
```

### Configuración de Variables de Entorno

```bash
# OpenStack Connection
export OPENSTACK_AUTH_URL="http://10.60.2.21:5000/v3"
export OPENSTACK_USERNAME="admin"
export OPENSTACK_PASSWORD="openstack123"
export OPENSTACK_PROJECT_NAME="admin"
export OPENSTACK_USER_DOMAIN_NAME="Default"
export OPENSTACK_PROJECT_DOMAIN_NAME="Default"
export OPENSTACK_REGION_NAME="RegionOne"

# Service Configuration
export OPENSTACK_SERVICE_URL="http://localhost:5006"
export JWT_SECRET_KEY="pucp-cloud-secret-2025"
```

### Testing

#### Test Básico de Conectividad

```bash
# Health check
curl http://localhost:5006/health

# Test con autenticación (obtener token primero)
TOKEN=$(curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "testpass123"}' \
  | jq -r '.token')

# Listar proyectos
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:5000/api/openstack/projects

# Listar imágenes disponibles
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:5000/api/openstack/images
```

#### Test de Deployment de Slice

```bash
# Crear slice con infraestructura OpenStack
curl -X POST http://localhost:5000/api/slices \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test-openstack-slice",
    "description": "Test slice for OpenStack",
    "infrastructure": "openstack",
    "nodes": [
      {
        "name": "vm1",
        "image": "ubuntu-20.04",
        "flavor": "small"
      }
    ],
    "networks": [
      {
        "name": "test-net",
        "cidr": "192.168.100.0/24",
        "network_type": "private"
      }
    ]
  }'
```

### Monitoreo y Logging

#### Logs
- Service logs: `/var/log/pucp-orchestrator/openstack-service.log`
- Container logs: `docker logs <container_name>`

#### Health Checks
```bash
# Service health
curl http://localhost:5006/health

# API Gateway health (incluye OpenStack Service)
curl http://localhost:5000/health/openstack
```

### Troubleshooting

#### Problemas Comunes

1. **Error de autenticación OpenStack**
   - Verificar variables de entorno
   - Comprobar conectividad con Keystone
   - Validar credenciales

2. **Service no responde**
   - Verificar que el puerto 5006 esté libre
   - Comprobar logs del servicio
   - Validar dependencias instaladas

3. **Error en API Gateway**
   - Verificar configuración de rutas
   - Comprobar URL del OpenStack Service
   - Validar forwarding de tokens

#### Debug Commands

```bash
# Verificar conectividad directa
python3 -c "
from microservicios.openstack_service.drivers.openstack_driver import OpenStackDriver
driver = OpenStackDriver()
print('OpenStack connection:', 'OK' if driver.nova else 'FAILED')
"

# Test de endpoints
curl -v http://localhost:5006/health
curl -v http://localhost:5000/api/openstack/projects
```

### Arquitectura del Microservicio

#### Componentes

1. **OpenStack Service** (`openstack_service.py`)
   - Servidor Flask principal
   - Endpoints REST para operaciones OpenStack
   - Integración con base de datos local

2. **OpenStack Driver** (`drivers/openstack_driver.py`)
   - Cliente directo para APIs OpenStack
   - Gestión de recursos (instancias, redes, volúmenes)
   - Operaciones de slice completas

3. **API Client** (`api/openstack_api.py`)
   - Cliente HTTP para OpenStack APIs
   - Manejo de autenticación y tokens
   - Abstracción de endpoints

4. **Configuración** (`config/openstack_config.py`)
   - Settings de conexión OpenStack
   - Mapeo de flavors y imágenes
   - Configuración de quotas

#### Flujo de Datos

```
Usuario → API Gateway → OpenStack Service → OpenStack APIs
                    ↓
              Base de Datos Local
```

### Ventajas de esta Arquitectura

1. **Separación de Responsabilidades**: OpenStack aislado en su propio microservicio
2. **Escalabilidad**: Servicio independiente que puede escalarse por separado
3. **Mantenibilidad**: Código específico de OpenStack centralizado
4. **Flexibilidad**: Fácil intercambio con otros drivers de cloud
5. **Integración Transparente**: No requiere cambios mayores en el código existente

### Próximos Pasos

1. Implementar circuit breaker para manejo de fallos
2. Agregar métricas y monitoring con Prometheus
3. Implementar cache para mejorar performance
4. Añadir tests unitarios y de integración completos
5. Documentación detallada de APIs con OpenAPI/Swagger