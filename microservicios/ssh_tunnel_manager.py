#!/usr/bin/env python3
"""
SSH Tunnel Manager para PUCP Cloud Orchestrator
Gestiona los túneles SSH para conectar a OpenStack remoto
"""

import subprocess
import threading
import time
import logging
import os
import signal
from typing import Dict, Optional, List
from microservicios.openstack_config_ssh import SSH_CONFIG, OPENSTACK_SERVICE_PORTS, SSH_TUNNEL_CONFIG

logger = logging.getLogger(__name__)

class SSHTunnelManager:
    def __init__(self):
        self.active_tunnels: Dict[str, subprocess.Popen] = {}
        self.tunnel_status: Dict[str, bool] = {}
        self.monitoring_thread: Optional[threading.Thread] = None
        self.should_monitor = False
        
    def start_ssh_tunnel(self, service_name: str = None) -> bool:
        """
        Inicia túnel SSH para un servicio específico o todos los servicios
        """
        if service_name:
            return self._start_single_tunnel(service_name)
        else:
            return self._start_all_tunnels()
    
    def _start_single_tunnel(self, service_name: str) -> bool:
        """Inicia túnel para un servicio específico"""
        if service_name not in OPENSTACK_SERVICE_PORTS:
            logger.error(f"Servicio desconocido: {service_name}")
            return False
            
        if service_name in self.active_tunnels:
            logger.warning(f"Túnel para {service_name} ya está activo")
            return True
            
        ports = OPENSTACK_SERVICE_PORTS[service_name]
        local_port = ports['local']
        remote_port = ports['remote']
        
        # Verificar si el puerto local está disponible
        if not self._is_port_available(local_port):
            logger.error(f"Puerto local {local_port} no está disponible")
            return False
        
        # Construir comando SSH para túnel a través del jumper hacia el headnode
        ssh_cmd = [
            'ssh',
            '-N',  # No ejecutar comando remoto
            '-L', f"{local_port}:{SSH_CONFIG['openstack_headnode']}:{remote_port}",  # Port forwarding al headnode
            '-p', str(SSH_CONFIG['jumper_port']),
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'LogLevel=ERROR',
            '-o', f"ConnectTimeout={SSH_TUNNEL_CONFIG.get('timeout', 30)}",
            f"{SSH_CONFIG['jumper_user']}@{SSH_CONFIG['jumper_host']}"
        ]
        
        # Agregar clave SSH si existe
        if os.path.exists(SSH_CONFIG['ssh_key_path']):
            ssh_cmd.extend(['-i', SSH_CONFIG['ssh_key_path']])
        
        try:
            logger.info(f"Iniciando túnel SSH para {service_name} en puerto {local_port}")
            process = subprocess.Popen(
                ssh_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid  # Crear nuevo grupo de proceso
            )
            
            # Esperar un momento para verificar que el proceso inició correctamente
            time.sleep(2)
            
            if process.poll() is None:  # Proceso sigue corriendo
                self.active_tunnels[service_name] = process
                self.tunnel_status[service_name] = True
                logger.info(f"Túnel SSH para {service_name} iniciado exitosamente (PID: {process.pid})")
                return True
            else:
                # El proceso terminó, obtener error
                _, stderr = process.communicate()
                logger.error(f"Falló al iniciar túnel para {service_name}: {stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"Error iniciando túnel para {service_name}: {e}")
            return False
    
    def _start_all_tunnels(self) -> bool:
        """Inicia túneles para todos los servicios"""
        success_count = 0
        total_services = len(OPENSTACK_SERVICE_PORTS)
        
        for service_name in OPENSTACK_SERVICE_PORTS.keys():
            if self._start_single_tunnel(service_name):
                success_count += 1
            else:
                logger.warning(f"No se pudo iniciar túnel para {service_name}")
        
        logger.info(f"Iniciados {success_count}/{total_services} túneles SSH")
        
        # Iniciar monitoreo de túneles
        if success_count > 0:
            self.start_monitoring()
        
        return success_count == total_services
    
    def stop_ssh_tunnel(self, service_name: str = None) -> bool:
        """
        Detiene túnel SSH para un servicio específico o todos
        """
        if service_name:
            return self._stop_single_tunnel(service_name)
        else:
            return self._stop_all_tunnels()
    
    def _stop_single_tunnel(self, service_name: str) -> bool:
        """Detiene túnel para un servicio específico"""
        if service_name not in self.active_tunnels:
            logger.warning(f"No hay túnel activo para {service_name}")
            return True
        
        try:
            process = self.active_tunnels[service_name]
            
            # Intentar terminar el proceso gracefully
            process.terminate()
            
            # Esperar un momento para que termine
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # Si no termina, forzar terminación
                process.kill()
                process.wait()
            
            # Limpiar referencias
            del self.active_tunnels[service_name]
            self.tunnel_status[service_name] = False
            
            logger.info(f"Túnel SSH para {service_name} detenido")
            return True
            
        except Exception as e:
            logger.error(f"Error deteniendo túnel para {service_name}: {e}")
            return False
    
    def _stop_all_tunnels(self) -> bool:
        """Detiene todos los túneles activos"""
        self.should_monitor = False
        
        success = True
        for service_name in list(self.active_tunnels.keys()):
            if not self._stop_single_tunnel(service_name):
                success = False
        
        return success
    
    def get_tunnel_status(self) -> Dict[str, bool]:
        """Obtiene el estado de todos los túneles"""
        return self.tunnel_status.copy()
    
    def is_tunnel_active(self, service_name: str) -> bool:
        """Verifica si un túnel específico está activo"""
        return self.tunnel_status.get(service_name, False)
    
    def start_monitoring(self):
        """Inicia monitoreo de túneles en hilo separado"""
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            return
        
        self.should_monitor = True
        self.monitoring_thread = threading.Thread(target=self._monitor_tunnels, daemon=True)
        self.monitoring_thread.start()
        logger.info("Monitoreo de túneles SSH iniciado")
    
    def _monitor_tunnels(self):
        """Monitorea el estado de los túneles y los reinicia si es necesario"""
        while self.should_monitor:
            for service_name, process in list(self.active_tunnels.items()):
                if process.poll() is not None:  # Proceso terminó
                    logger.warning(f"Túnel SSH para {service_name} se desconectó, reintentando...")
                    
                    # Limpiar proceso terminado
                    del self.active_tunnels[service_name]
                    self.tunnel_status[service_name] = False
                    
                    # Reintentar conexión
                    time.sleep(5)  # Esperar antes de reintentar
                    self._start_single_tunnel(service_name)
            
            time.sleep(10)  # Verificar cada 10 segundos
    
    def _is_port_available(self, port: int) -> bool:
        """Verifica si un puerto local está disponible"""
        import socket
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('localhost', port))
                return True
            except OSError:
                return False
    
    def test_ssh_connection(self) -> bool:
        """Prueba la conexión SSH básica al jumper"""
        try:
            cmd = [
                'ssh',
                '-p', str(SSH_CONFIG['jumper_port']),
                '-o', 'ConnectTimeout=10',
                '-o', 'BatchMode=yes',
                '-o', 'StrictHostKeyChecking=no',
                f"{SSH_CONFIG['jumper_user']}@{SSH_CONFIG['jumper_host']}",
                'echo OK'
            ]
            
            if os.path.exists(SSH_CONFIG['ssh_key_path']):
                cmd.insert(-2, '-i')
                cmd.insert(-2, SSH_CONFIG['ssh_key_path'])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            return result.returncode == 0 and 'OK' in result.stdout
            
        except Exception as e:
            logger.error(f"Error probando conexión SSH al jumper: {e}")
            return False
    
    def test_headnode_connection(self) -> bool:
        """Prueba la conexión al headnode OpenStack a través del jumper"""
        try:
            # Comando para probar conectividad al headnode desde el jumper
            cmd = [
                'ssh',
                '-p', str(SSH_CONFIG['jumper_port']),
                '-o', 'ConnectTimeout=10',
                '-o', 'BatchMode=yes',
                '-o', 'StrictHostKeyChecking=no',
                f"{SSH_CONFIG['jumper_user']}@{SSH_CONFIG['jumper_host']}",
                f"nc -z -w5 {SSH_CONFIG['openstack_headnode']} 5000 && echo HEADNODE_OK"
            ]
            
            if os.path.exists(SSH_CONFIG['ssh_key_path']):
                cmd.insert(-2, '-i')
                cmd.insert(-2, SSH_CONFIG['ssh_key_path'])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            return result.returncode == 0 and 'HEADNODE_OK' in result.stdout
            
        except Exception as e:
            logger.error(f"Error probando conexión al headnode: {e}")
            return False
    
    def get_tunnel_info(self) -> Dict[str, Dict]:
        """Obtiene información detallada de todos los túneles"""
        info = {}
        
        for service_name, ports in OPENSTACK_SERVICE_PORTS.items():
            status = self.is_tunnel_active(service_name)
            pid = None
            
            if service_name in self.active_tunnels:
                pid = self.active_tunnels[service_name].pid
            
            info[service_name] = {
                'local_port': ports['local'],
                'remote_port': ports['remote'],
                'status': 'active' if status else 'inactive',
                'pid': pid,
                'endpoint': f"http://localhost:{ports['local']}",
                'jumper_host': SSH_CONFIG['jumper_host'],
                'headnode_host': SSH_CONFIG['openstack_headnode'],
                'tunnel_path': f"App Server -> {SSH_CONFIG['jumper_host']}:{SSH_CONFIG['jumper_port']} -> {SSH_CONFIG['openstack_headnode']}:{ports['remote']}"
            }
        
        return info
    
    def __del__(self):
        """Limpieza al destruir el objeto"""
        self._stop_all_tunnels()

# Instancia global del manager
tunnel_manager = SSHTunnelManager()

def start_openstack_tunnels() -> bool:
    """Función de conveniencia para iniciar todos los túneles"""
    return tunnel_manager.start_ssh_tunnel()

def stop_openstack_tunnels() -> bool:
    """Función de conveniencia para detener todos los túneles"""
    return tunnel_manager.stop_ssh_tunnel()

def get_tunnel_status() -> Dict[str, bool]:
    """Función de conveniencia para obtener estado de túneles"""
    return tunnel_manager.get_tunnel_status()

def is_openstack_accessible() -> bool:
    """Verifica si OpenStack es accesible a través de los túneles"""
    return tunnel_manager.is_tunnel_active('keystone')