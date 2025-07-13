# PUCP Cloud Orchestrator - OpenStack Service Dockerfile
FROM python:3.9-slim

LABEL maintainer="PUCP Cloud Orchestrator Team"
LABEL service="openstack-service"
LABEL version="3.0.0"

# Variables de entorno
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV FLASK_APP=openstack_service.py
ENV FLASK_ENV=production

# Crear usuario no-root
RUN groupadd -r pucp && useradd -r -g pucp pucp

# Instalar dependencias del sistema
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    libffi-dev \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Establecer directorio de trabajo
WORKDIR /app

# Copiar requirements y instalar dependencias Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código fuente
COPY . .

# Crear directorios necesarios
RUN mkdir -p /data /var/log/pucp-orchestrator && \
    chown -R pucp:pucp /app /data /var/log/pucp-orchestrator

# Cambiar a usuario no-root
USER pucp

# Exponer puerto
EXPOSE 5006

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:5006/health || exit 1

# Comando por defecto
CMD ["python3", "openstack_service.py"]