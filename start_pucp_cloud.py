#!/usr/bin/env python3
"""
PUCP Cloud Orchestrator - Startup Script
Inicia todos los servicios necesarios para el Cloud Orchestrator
"""

import subprocess
import sys
import os
import time
import logging
import signal
from multiprocessing import Process
from microservicios.ssh_tunnel_manager import tunnel_manager, start_openstack_tunnels
from microservicios.edits.openstack_config_ssh import SSH_CONFIG, SSH_TUNNEL_CONFIG

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class PUCPCloudOrchestrator:
    def __init__(self):
        self.processes = {}
        self.shutdown_requested = False
        
        # Configurar manejo de señales
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        """Manejador de señales para shutdown graceful"""
        logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        self.shutdown_requested = True
        self.shutdown_all_services()
        sys.exit(0)
    
    def start_web_application(self):
        """Inicia la aplicación web principal"""
        try:
            logger.info("Starting main web application...")
            
            # Verificar que el archivo existe
            web_app_path = os.path.join(os.path.dirname(__file__), 'web_app.py')
            if not os.path.exists(web_app_path):
                logger.error("web_app.py not found!")
                return None
            
            process = subprocess.Popen(
                [sys.executable, web_app_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            time.sleep(3)  # Esperar a que arranque
            
            if process.poll() is None:
                logger.info(f"Web application started successfully (PID: {process.pid})")
                return process
            else:
                stdout, stderr = process.communicate()
                logger.error(f"Failed to start web application: {stderr.decode()}")
                return None
                
        except Exception as e:
            logger.error(f"Error starting web application: {e}")
            return None
    
    def start_openstack_service(self):
        """Inicia el microservicio de OpenStack"""
        try:
            logger.info("Starting OpenStack microservice...")
            
            service_path = os.path.join(
                os.path.dirname(__file__), 
                'microservicios/openstack_service/openstack_service.py'
            )
            
            if not os.path.exists(service_path):
                logger.error("OpenStack service not found!")
                return None
            
            process = subprocess.Popen(
                [sys.executable, service_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            time.sleep(3)  # Esperar a que arranque
            
            if process.poll() is None:
                logger.info(f"OpenStack service started successfully (PID: {process.pid})")
                return process
            else:
                stdout, stderr = process.communicate()
                logger.error(f"Failed to start OpenStack service: {stderr.decode()}")
                return None
                
        except Exception as e:
            logger.error(f"Error starting OpenStack service: {e}")
            return None
    
    def start_linux_cluster_service(self):
        """Inicia el microservicio de Linux Cluster"""
        try:
            logger.info("Starting Linux Cluster microservice...")
            
            # Para este ejemplo, asumimos que existe un servicio similar
            # En la implementación real, aquí iría el microservicio del cluster Linux
            logger.info("Linux Cluster service would start here (not implemented in this demo)")
            return None
                
        except Exception as e:
            logger.error(f"Error starting Linux Cluster service: {e}")
            return None
    
    def setup_ssh_tunnels(self):
        """Configura y establece túneles SSH a OpenStack"""
        try:
            logger.info("Setting up SSH tunnels to OpenStack headnode...")
            logger.info(f"Architecture: App Server -> Jumper ({SSH_CONFIG['jumper_host']}:{SSH_CONFIG['jumper_port']}) -> Headnode ({SSH_CONFIG['openstack_headnode']})")
            
            # Verificar conexión SSH básica al jumper
            if not tunnel_manager.test_ssh_connection():
                logger.error(f"Cannot establish SSH connection to jumper {SSH_CONFIG['jumper_host']}:{SSH_CONFIG['jumper_port']}")
                logger.error("Please check:")
                logger.error(f"1. SSH access to {SSH_CONFIG['jumper_user']}@{SSH_CONFIG['jumper_host']}")
                logger.error(f"2. SSH key at {SSH_CONFIG['ssh_key_path']}")
                logger.error("3. Network connectivity to jumper")
                return False
            
            logger.info("SSH connection to jumper successful")
            
            # Verificar conectividad al headnode
            if not tunnel_manager.test_headnode_connection():
                logger.warning(f"Cannot reach OpenStack headnode {SSH_CONFIG['openstack_headnode']} through jumper")
                logger.warning("This may be normal if headnode is not running or network is not configured")
                logger.warning("SSH tunnels will still be established, but OpenStack may not be accessible")
            else:
                logger.info("Headnode connectivity verified")
            
            # Iniciar túneles si está configurado para auto-establecimiento
            if SSH_TUNNEL_CONFIG.get('auto_establish', False):
                success = start_openstack_tunnels()
                if success:
                    logger.info("SSH tunnels established successfully")
                    
                    # Mostrar información de túneles
                    tunnel_info = tunnel_manager.get_tunnel_info()
                    for service, info in tunnel_info.items():
                        if info['status'] == 'active':
                            logger.info(f"  {service}: {info['tunnel_path']}")
                            logger.info(f"    Local endpoint: {info['endpoint']}")
                    
                    return True
                else:
                    logger.error("Failed to establish SSH tunnels")
                    return False
            else:
                logger.info("SSH tunnels not configured for auto-establishment")
                return True
                
        except Exception as e:
            logger.error(f"Error setting up SSH tunnels: {e}")
            return False
    
    def check_dependencies(self):
        """Verifica dependencias necesarias"""
        logger.info("Checking dependencies...")
        
        # Verificar Python packages
        required_packages = [
            'flask', 'flask-cors', 'jwt', 'sqlite3',
            'subprocess', 'threading', 'logging'
        ]
        
        missing_packages = []
        for package in required_packages:
            try:
                __import__(package.replace('-', '_'))
            except ImportError:
                missing_packages.append(package)
        
        if missing_packages:
            logger.error(f"Missing required packages: {', '.join(missing_packages)}")
            logger.error("Please install missing packages with: pip install <package>")
            return False
        
        # Verificar SSH
        ssh_available = subprocess.run(['which', 'ssh'], capture_output=True).returncode == 0
        if not ssh_available:
            logger.error("SSH client not found. Please install OpenSSH client.")
            return False
        
        logger.info("All dependencies satisfied")
        return True
    
    def start_all_services(self):
        """Inicia todos los servicios del Cloud Orchestrator"""
        logger.info("🚀 Starting PUCP Cloud Orchestrator...")
        
        # Verificar dependencias
        if not self.check_dependencies():
            logger.error("Dependency check failed. Exiting.")
            return False
        
        # Configurar túneles SSH
        if not self.setup_ssh_tunnels():
            logger.warning("SSH tunnels setup failed, but continuing...")
        
        # Iniciar microservicio OpenStack
        openstack_process = self.start_openstack_service()
        if openstack_process:
            self.processes['openstack'] = openstack_process
        
        # Iniciar aplicación web principal
        web_process = self.start_web_application()
        if web_process:
            self.processes['web'] = web_process
        
        if self.processes:
            logger.info("✅ PUCP Cloud Orchestrator started successfully!")
            logger.info("📊 Services running:")
            
            for service, process in self.processes.items():
                logger.info(f"  - {service.title()}: PID {process.pid}")
            
            if tunnel_manager.get_tunnel_status():
                logger.info("🔒 SSH Tunnels:")
                for service, active in tunnel_manager.get_tunnel_status().items():
                    status = "✅ Active" if active else "❌ Inactive"
                    logger.info(f"  - {service}: {status}")
            
            logger.info("🌐 Access URLs:")
            logger.info("  - Web Interface: http://localhost:5000")
            logger.info("  - OpenStack API: http://localhost:5006")
            
            return True
        else:
            logger.error("❌ Failed to start any services")
            return False
    
    def shutdown_all_services(self):
        """Detiene todos los servicios"""
        logger.info("Shutting down PUCP Cloud Orchestrator...")
        
        # Detener túneles SSH
        try:
            tunnel_manager.stop_ssh_tunnel()
            logger.info("SSH tunnels stopped")
        except Exception as e:
            logger.error(f"Error stopping SSH tunnels: {e}")
        
        # Detener procesos
        for service_name, process in self.processes.items():
            try:
                logger.info(f"Stopping {service_name} service...")
                process.terminate()
                
                # Esperar terminación graceful
                try:
                    process.wait(timeout=10)
                    logger.info(f"{service_name} service stopped")
                except subprocess.TimeoutExpired:
                    # Forzar terminación si no responde
                    logger.warning(f"Force killing {service_name} service...")
                    process.kill()
                    process.wait()
                    
            except Exception as e:
                logger.error(f"Error stopping {service_name}: {e}")
        
        self.processes.clear()
        logger.info("✅ All services stopped")
    
    def monitor_services(self):
        """Monitorea los servicios y los reinicia si es necesario"""
        logger.info("Starting service monitoring...")
        
        while not self.shutdown_requested:
            try:
                # Verificar procesos
                for service_name, process in list(self.processes.items()):
                    if process.poll() is not None:
                        logger.warning(f"{service_name} service died, attempting restart...")
                        
                        # Remover proceso muerto
                        del self.processes[service_name]
                        
                        # Reintentar arranque
                        if service_name == 'web':
                            new_process = self.start_web_application()
                        elif service_name == 'openstack':
                            new_process = self.start_openstack_service()
                        else:
                            new_process = None
                        
                        if new_process:
                            self.processes[service_name] = new_process
                            logger.info(f"{service_name} service restarted successfully")
                        else:
                            logger.error(f"Failed to restart {service_name} service")
                
                # Verificar túneles SSH cada minuto
                if not any(tunnel_manager.get_tunnel_status().values()):
                    logger.warning("All SSH tunnels are down, attempting restart...")
                    start_openstack_tunnels()
                
                time.sleep(30)  # Verificar cada 30 segundos
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Error in service monitoring: {e}")
                time.sleep(10)
    
    def run(self):
        """Ejecuta el orquestador completo"""
        try:
            # Iniciar servicios
            if not self.start_all_services():
                logger.error("Failed to start services. Exiting.")
                return 1
            
            logger.info("🎯 PUCP Cloud Orchestrator is running!")
            logger.info("Press Ctrl+C to stop all services")
            
            # Monitorear servicios
            self.monitor_services()
            
        except KeyboardInterrupt:
            logger.info("Interrupt received, shutting down...")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return 1
        finally:
            self.shutdown_all_services()
        
        return 0

def main():
    """Función principal"""
    orchestrator = PUCPCloudOrchestrator()
    return orchestrator.run()

if __name__ == '__main__':
    sys.exit(main())