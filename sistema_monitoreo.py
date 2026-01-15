#!/usr/bin/env python3
"""
SISTEMA DE MONITOREO Y SEGURIDAD PARA CENTROS DE DATOS REDES Y TELECOMUNICACIONES
DGTIC-UNAM - PROGRAMA PARA BECARIOS
Versión FINAL COMPLETA - Panel Becario simplificado
"""

from flask import Flask, request, jsonify, render_template_string, make_response, redirect
import os
import sys
import socket
import secrets
import subprocess
import platform
import time
import json
import hashlib
import csv
from datetime import datetime, timezone, timedelta
from functools import wraps
import threading
import queue
import re

# =============================
# CARGADOR DE VARIABLES .env
# =============================
class CargadorENV:
    """Cargador simple de variables de entorno desde archivo .env"""
    
    @staticmethod
    def cargar(archivo_env=".env", mostrar_info=True):
        """Cargar variables desde archivo .env"""
        archivo_completo = os.path.join(os.path.dirname(os.path.abspath(__file__)), archivo_env)
        
        if not os.path.exists(archivo_completo):
            if mostrar_info:
                print(f"[ℹ️] Archivo .env no encontrado: {archivo_completo}")
                print(f"[ℹ️] Se usarán valores por defecto")
            return False
        
        try:
            variables_cargadas = 0
            with open(archivo_completo, 'r', encoding='utf-8') as f:
                for linea in f:
                    linea = linea.strip()
                    
                    if not linea or linea.startswith('#'):
                        continue
                    
                    if '=' in linea:
                        clave, valor = linea.split('=', 1)
                        clave = clave.strip()
                        valor = valor.strip()
                        
                        if (valor.startswith('"') and valor.endswith('"')) or \
                           (valor.startswith("'") and valor.endswith("'")):
                            valor = valor[1:-1]
                        
                        os.environ[clave] = valor
                        variables_cargadas += 1
            
            if mostrar_info:
                print(f"[✓] Cargadas {variables_cargadas} variables desde .env")
            return True
            
        except Exception as e:
            print(f"[✗] Error al cargar .env: {e}")
            return False

# =============================
# CONFIGURACIÓN DEL SISTEMA
# =============================
class Config:
    """Configuración centralizada del sistema"""
    
    # Cargar variables de entorno
    CargadorENV.cargar()
    
    # Información del sistema
    APP_NAME = os.environ.get('APP_NAME', "DGTIC-UNAM - Sistema de Monitoreo")
    VERSION = os.environ.get('VERSION', "3.0.0")
    INSTITUCION = os.environ.get('INSTITUCION', "DGTIC-UNAM")
    DEPARTAMENTO = os.environ.get('DEPARTAMENTO', "Programa de Becarios - Centro de Datos")
    
    # Configuración de red
    PORT = int(os.environ.get('SERVIDOR_PUERTO', 5000))
    HOST = os.environ.get('SERVIDOR_HOST', '0.0.0.0')
    DEBUG = os.environ.get('DEBUG_MODE', 'False').lower() == 'true'
    
    # Credenciales del sistema
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'DGTIC-Admin-2024!')
    BECARIO_PASSWORD = os.environ.get('BECARIO_PASSWORD', 'DGTIC-Becario-2024!')
    
    # Seguridad
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    SESSION_TIMEOUT = int(os.environ.get('SESSION_TIMEOUT', 3600))
    
    # Directorios
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DATA_DIR = os.path.join(BASE_DIR, "datos_monitoreo")
    LOGS_DIR = os.path.join(DATA_DIR, "logs")
    ENV_FILE = os.path.join(BASE_DIR, ".env")

# =============================
# INICIALIZACIÓN DEL SISTEMA
# =============================
class Sistema:
    """Clase principal del sistema"""
    
    @staticmethod
    def inicializar():
        """Inicializar todo el sistema"""
        print("\n" + "="*70)
        print(f"{Config.APP_NAME} - Versión {Config.VERSION}")
        print("="*70)
        
        # Verificar archivo .env
        if os.path.exists(Config.ENV_FILE):
            print(f"[✓] Archivo .env encontrado y cargado")
        else:
            print(f"[⚠️] Archivo .env no encontrado en: {Config.ENV_FILE}")
            print(f"[ℹ️] Crea un archivo .env con las variables de configuración")
        
        # Crear directorios necesarios
        os.makedirs(Config.DATA_DIR, exist_ok=True)
        os.makedirs(Config.LOGS_DIR, exist_ok=True)
        
        print(f"[✓] Sistema inicializado correctamente")
        print(f"[🌐] URL: http://localhost:{Config.PORT}")
        print("="*70 + "\n")
    
    @staticmethod
    def registrar_log(usuario, ip, accion, exito=True):
        """Registrar log de acceso en archivo CSV"""
        log_file = os.path.join(Config.LOGS_DIR, "accesos.csv")
        file_exists = os.path.isfile(log_file)
        
        try:
            with open(log_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow(['timestamp', 'usuario', 'ip', 'accion', 'exito'])
                
                writer.writerow([
                    datetime.now(timezone.utc).isoformat(),
                    usuario,
                    ip,
                    accion,
                    exito
                ])
        except Exception as e:
            print(f"[⚠️] Error al registrar log: {e}")

# =============================
# HERRAMIENTAS DE MONITOREO - COMPLETAS
# =============================
class HerramientasMonitoreo:
    """Clase con herramientas de monitoreo REALES"""
    
    @staticmethod
    def ejecutar_comando(comando):
        """Ejecutar comando de sistema REAL"""
        try:
            result = subprocess.run(
                comando, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            return {
                'exito': result.returncode == 0,
                'salida': result.stdout,
                'error': result.stderr,
                'codigo': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {'exito': False, 'error': 'Timeout del comando'}
        except Exception as e:
            return {'exito': False, 'error': str(e)}
    
    @staticmethod
    def obtener_estadisticas_sistema():
        """Obtener estadísticas REALES del sistema"""
        stats = {
            'cpu': {'porcentaje': '0%'},
            'memoria': {'porcentaje': '0%', 'usado': '0 MB', 'total': '0 MB'},
            'disco': {'porcentaje': '0%', 'usado': '0 GB', 'total': '0 GB', 'libre': '0 GB'},
            'procesos': {'total': 0}
        }
        
        try:
            # 1. CPU - usando top o ps
            try:
                result = subprocess.run(
                    "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1",
                    shell=True, capture_output=True, text=True, timeout=3
                )
                if result.returncode == 0 and result.stdout.strip():
                    cpu_usage = float(result.stdout.strip())
                    stats['cpu']['porcentaje'] = f"{cpu_usage:.1f}%"
                else:
                    # Alternativa usando /proc/stat
                    with open('/proc/stat', 'r') as f:
                        lines = f.readlines()
                        for line in lines:
                            if line.startswith('cpu '):
                                parts = line.split()
                                total = sum(int(x) for x in parts[1:])
                                idle = int(parts[4])
                                usage = 100 * (total - idle) / total if total > 0 else 0
                                stats['cpu']['porcentaje'] = f"{usage:.1f}%"
                                break
            except:
                stats['cpu']['porcentaje'] = "N/A"
            
            # 2. MEMORIA - usando free
            try:
                result = subprocess.run(
                    "free -m | grep Mem: | awk '{print $2, $3, $7}'",
                    shell=True, capture_output=True, text=True, timeout=3
                )
                if result.returncode == 0:
                    parts = result.stdout.strip().split()
                    if len(parts) >= 3:
                        total = int(parts[0])
                        used = int(parts[1])
                        free_mem = int(parts[2])
                        usage_percent = (used / total) * 100 if total > 0 else 0
                        
                        stats['memoria']['total'] = f"{total} MB"
                        stats['memoria']['usado'] = f"{used} MB"
                        stats['memoria']['libre'] = f"{free_mem} MB"
                        stats['memoria']['porcentaje'] = f"{usage_percent:.1f}%"
            except:
                pass
            
            # 3. DISCO - usando df
            try:
                result = subprocess.run(
                    "df -h / | tail -1 | awk '{print $2, $3, $4, $5}'",
                    shell=True, capture_output=True, text=True, timeout=3
                )
                if result.returncode == 0:
                    parts = result.stdout.strip().split()
                    if len(parts) >= 4:
                        stats['disco']['total'] = parts[0]
                        stats['disco']['usado'] = parts[1]
                        stats['disco']['libre'] = parts[2]
                        stats['disco']['porcentaje'] = parts[3]
            except:
                pass
            
            # 4. PROCESOS - usando ps
            try:
                result = subprocess.run(
                    "ps aux | wc -l",
                    shell=True, capture_output=True, text=True, timeout=3
                )
                if result.returncode == 0:
                    total_procesos = int(result.stdout.strip()) - 1
                    stats['procesos']['total'] = total_procesos
            except:
                pass
            
        except Exception as e:
            print(f"[⚠️] Error al obtener estadísticas: {e}")
        
        return stats
    
    @staticmethod
    def escanear_puertos_con_ss():
        """Escáner de puertos usando SS (método principal) - FUNCIONAL"""
        try:
            comando = 'ss -tuln'
            resultado = HerramientasMonitoreo.ejecutar_comando(comando)
            
            puertos = []
            if resultado['exito']:
                lines = resultado['salida'].strip().split('\n')
                for line in lines[1:]:  # Saltar encabezado
                    if 'LISTEN' in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            # Extraer dirección:puerto
                            addr_part = parts[4]
                            if ':' in addr_part:
                                port_str = addr_part.split(':')[-1]
                                try:
                                    port = int(port_str)
                                    servicio = HerramientasMonitoreo.obtener_servicio(port)
                                    puertos.append({
                                        'puerto': port,
                                        'estado': 'ABIERTO',
                                        'servicio': servicio,
                                        'protocolo': 'TCP' if 'tcp' in line.lower() else 'UDP'
                                    })
                                except:
                                    continue
            
            return puertos
        except Exception as e:
            print(f"[⚠️] Error al escanear puertos con ss: {e}")
            return []
    
    @staticmethod
    def obtener_servicio(puerto):
        """Obtener nombre del servicio basado en puerto común"""
        servicios = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            465: 'SMTPS',
            587: 'SMTP',
            993: 'IMAPS',
            995: 'POP3S',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            6379: 'Redis',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
            8888: 'HTTP-Alt2',
            9000: 'PHP-FPM',
            9200: 'Elasticsearch',
            27017: 'MongoDB',
            5000: 'Flask/Development'
        }
        return servicios.get(puerto, 'Desconocido')
    
    @staticmethod
    def test_conectividad(destino='8.8.8.8'):
        """Test de conectividad REAL usando ping"""
        if destino == 'localhost':
            destino = '127.0.0.1'
        
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            comando = f'ping {param} 2 {destino}'
            resultado = HerramientasMonitoreo.ejecutar_comando(comando)
            
            if resultado['exito']:
                lines = resultado['salida'].split('\n')
                detalles = ""
                for line in lines:
                    if 'time=' in line.lower() or 'ttl=' in line.lower():
                        detalles = line.strip()
                        break
                if not detalles:
                    detalles = f'Ping exitoso a {destino}'
                
                return {'conectado': True, 'detalles': detalles}
            else:
                return {'conectado': False, 'detalles': resultado.get('error', 'Error desconocido')}
        except Exception as e:
            return {'conectado': False, 'detalles': str(e)}
    
    @staticmethod
    def analizar_logs(busqueda=None, limite=50):
        """Analizar logs REALES del sistema"""
        logs = []
        log_file = os.path.join(Config.LOGS_DIR, "accesos.csv")
        
        if not os.path.exists(log_file):
            return logs
        
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if busqueda:
                        if (busqueda.lower() in row.get('usuario', '').lower() or 
                            busqueda.lower() in row.get('accion', '').lower() or
                            busqueda.lower() in row.get('ip', '').lower()):
                            logs.append(row)
                    else:
                        logs.append(row)
        except Exception as e:
            print(f"[⚠️] Error al leer logs: {e}")
        
        return logs[-limite:] if logs else []
    
    @staticmethod
    def monitorear_procesos(limite=10):
        """Obtener lista REAL de procesos"""
        try:
            comando = f'ps aux --sort=-%cpu | head -{limite + 1}'
            resultado = HerramientasMonitoreo.ejecutar_comando(comando)
            
            procesos = []
            if resultado['exito']:
                lines = resultado['salida'].strip().split('\n')
                
                for line in lines[1:]:  # Saltar encabezado
                    parts = line.split(None, 10)  # Dividir en máximo 11 partes
                    if len(parts) >= 11:
                        procesos.append({
                            'usuario': parts[0],
                            'pid': parts[1],
                            'cpu': parts[2],
                            'mem': parts[3],
                            'comando': parts[10][:100]
                        })
                    elif len(parts) >= 5:
                        procesos.append({
                            'usuario': parts[0],
                            'pid': parts[1],
                            'cpu': parts[2],
                            'mem': parts[3],
                            'comando': ' '.join(parts[4:])[:100]
                        })
            
            return procesos
            
        except Exception as e:
            print(f"[⚠️] Error al monitorear procesos: {e}")
            return []
    
    @staticmethod
    def obtener_info_red():
        """Obtener información REAL de red del sistema"""
        try:
            info = {}
            
            # Interfaces de red
            if platform.system() == 'Linux':
                result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True, timeout=3)
                info['interfaces'] = result.stdout if result.returncode == 0 else "Error"
            else:
                result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=3)
                info['interfaces'] = result.stdout if result.returncode == 0 else "Error"
            
            # Rutas
            if platform.system() == 'Linux':
                result = subprocess.run(['ip', 'route', 'show'], capture_output=True, text=True, timeout=3)
                info['rutas'] = result.stdout if result.returncode == 0 else "Error"
            
            # Conexiones activas
            try:
                result = subprocess.run(['ss', '-tun'], capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    info['conexiones'] = result.stdout
                else:
                    result = subprocess.run(['netstat', '-tun'], capture_output=True, text=True, timeout=3)
                    info['conexiones'] = result.stdout if result.returncode == 0 else "Error"
            except:
                info['conexiones'] = "Error"
            
            return info
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def obtener_usuarios_conectados():
        """Obtener usuarios REALES conectados al sistema"""
        try:
            comando = 'who'
            resultado = HerramientasMonitoreo.ejecutar_comando(comando)
            
            usuarios = []
            if resultado['exito']:
                lines = resultado['salida'].strip().split('\n')
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 5:
                        usuarios.append({
                            'usuario': parts[0],
                            'terminal': parts[1],
                            'fecha': f"{parts[2]} {parts[3]}",
                            'ip': parts[4] if len(parts) > 4 else ''
                        })
            
            return usuarios
        except Exception as e:
            print(f"[⚠️] Error al obtener usuarios: {e}")
            return []
    
    @staticmethod
    def ejecutar_comando_telecom(comando):
        """Ejecutar comando de telecomunicaciones (lista blanca)"""
        # Comandos permitidos en telecomunicaciones
        comandos_telecom = [
            'ping', 'traceroute', 'tracepath', 'mtr',
            'dig', 'nslookup', 'host',
            'curl', 'wget',
            'ip', 'ss', 'netstat'
        ]
        
        comando_base = comando.split()[0] if comando.split() else ''
        
        if comando_base not in comandos_telecom:
            return {
                'exito': False,
                'salida': '',
                'error': f'Comando "{comando_base}" no permitido en telecomunicaciones.'
            }
        
        return HerramientasMonitoreo.ejecutar_comando(comando)

# =============================
# APLICACIÓN FLASK
# =============================
app = Flask(__name__)
app.secret_key = Config.SECRET_KEY

# Variable para sesiones en memoria
sesiones_activas = {}
auditoria_log = queue.Queue()

# Hilo para auditoría
def hilo_auditoria():
    """Hilo para procesar logs de auditoría"""
    while True:
        try:
            log_data = auditoria_log.get(timeout=1)
            Sistema.registrar_log(**log_data)
        except queue.Empty:
            continue
        except Exception as e:
            print(f"[⚠️] Error en hilo auditoría: {e}")

threading.Thread(target=hilo_auditoria, daemon=True).start()

# =============================
# DECORADORES Y MIDDLEWARE
# =============================
def requiere_rol(rol_requerido):
    """Decorador para requerir rol específico"""
    def decorador(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            session_id = request.cookies.get('session_id')
            if not session_id or session_id not in sesiones_activas:
                return redirect('/login')
            
            sesion = sesiones_activas[session_id]
            if sesion['rol'] != rol_requerido:
                return '''
                    <div style="padding:50px; text-align:center; background:#0a1929; color:white; min-height:100vh;">
                        <h2>🚫 Acceso Denegado</h2>
                        <p>No tienes permisos para acceder a esta sección</p>
                        <a href="/" style="color:#3498db;">← Volver al Dashboard</a>
                    </div>
                ''', 403
            
            request.sesion = sesion
            return func(*args, **kwargs)
        return wrapper
    return decorador

def requiere_admin_o_becario():
    """Decorador para requerir que sea admin o becario"""
    def decorador(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            session_id = request.cookies.get('session_id')
            if not session_id or session_id not in sesiones_activas:
                return redirect('/login')
            
            sesion = sesiones_activas[session_id]
            if sesion['rol'] not in ['admin', 'becario']:
                return '''
                    <div style="padding:50px; text-align:center; background:#0a1929; color:white; min-height:100vh;">
                        <h2>🚫 Acceso Denegado</h2>
                        <p>No tienes permisos para acceder a esta sección</p>
                        <a href="/" style="color:#3498db;">← Volver al Dashboard</a>
                    </div>
                ''', 403
            
            request.sesion = sesion
            return func(*args, **kwargs)
        return wrapper
    return decorador

@app.before_request
def middleware_seguridad():
    """Middleware de seguridad para todas las peticiones"""
    rutas_publicas = ['login', 'logout', 'static', 'api_status', 'favicon', 'api_metricas', 'api_ping', 'api_puertos']
    
    if request.endpoint in rutas_publicas:
        return
    
    session_id = request.cookies.get('session_id')
    if session_id and session_id in sesiones_activas:
        sesion = sesiones_activas[session_id]
        
        # Verificar timeout de sesión
        if (datetime.now(timezone.utc) - sesion['ultima_actividad']).seconds > Config.SESSION_TIMEOUT:
            del sesiones_activas[session_id]
            return redirect('/login')
        
        # Actualizar última actividad
        sesion['ultima_actividad'] = datetime.now(timezone.utc)
        request.sesion = sesion
        
        # Restricciones especiales para becarios
        if sesion['rol'] == 'becario' and request.endpoint not in ['dashboard', 'logout', 'static', 'favicon']:
            # Becarios solo pueden ver el dashboard y cerrar sesión
            return redirect('/')
        
        return
    
    return redirect('/login')

# =============================
# RUTAS DE AUTENTICACIÓN
# =============================
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Página de login"""
    if request.method == 'POST':
        password = request.form.get('password', '')
        ip = request.remote_addr
        
        if not password:
            return '''
                <div style="padding:20px; text-align:center; background:#0a1929; color:white; min-height:100vh;">
                    <h2>❌ Error: Contraseña requerida</h2>
                    <a href="/login" style="color:#3498db;">← Volver</a>
                </div>
            '''
        
        rol = None
        if password == Config.ADMIN_PASSWORD:
            rol = 'admin'
        elif password == Config.BECARIO_PASSWORD:
            rol = 'becario'
        
        if rol:
            auditoria_log.put({
                'usuario': rol,
                'ip': ip,
                'accion': 'login',
                'exito': True
            })
            
            session_id = secrets.token_urlsafe(32)
            sesiones_activas[session_id] = {
                'rol': rol,
                'ultima_actividad': datetime.now(timezone.utc),
                'ip': ip,
                'login_time': datetime.now(timezone.utc)
            }
            
            response = make_response(redirect('/'))
            response.set_cookie('session_id', session_id, 
                              max_age=Config.SESSION_TIMEOUT,
                              httponly=True,
                              samesite='Strict')
            return response
        
        auditoria_log.put({
            'usuario': 'desconocido',
            'ip': ip,
            'accion': 'login_fallido',
            'exito': False
        })
        
        return '''
            <div style="padding:20px; text-align:center; background:#0a1929; color:white; min-height:100vh;">
                <h2>❌ Error: Contraseña incorrecta</h2>
                <p>Verifica la contraseña e intenta nuevamente</p>
                <a href="/login" style="color:#3498db;">← Volver</a>
            </div>
        '''
    
    return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login - DGTIC-UNAM</title>
            <style>
                body {
                    font-family: 'Segoe UI', Arial, sans-serif;
                    margin: 0;
                    padding: 0;
                    background: linear-gradient(135deg, #0c2461 0%, #1e3799 100%);
                    color: white;
                    min-height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                }
                .login-container {
                    background: rgba(255, 255, 255, 0.1);
                    backdrop-filter: blur(10px);
                    padding: 40px;
                    border-radius: 15px;
                    border: 1px solid rgba(255, 255, 255, 0.2);
                    max-width: 400px;
                    width: 100%;
                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
                }
                h2 {
                    text-align: center;
                    margin-bottom: 30px;
                    color: white;
                }
                .form-group {
                    margin-bottom: 20px;
                }
                input {
                    width: 100%;
                    padding: 14px;
                    border: 2px solid rgba(255, 255, 255, 0.3);
                    border-radius: 8px;
                    background: rgba(255, 255, 255, 0.1);
                    color: white;
                    font-size: 16px;
                    transition: border-color 0.3s;
                }
                input:focus {
                    outline: none;
                    border-color: #3498db;
                }
                button {
                    width: 100%;
                    padding: 14px;
                    background: #2980b9;
                    color: white;
                    border: none;
                    border-radius: 8px;
                    font-size: 16px;
                    cursor: pointer;
                    transition: background 0.3s;
                }
                button:hover {
                    background: #3498db;
                }
                .info-box {
                    margin-top: 20px;
                    padding: 15px;
                    background: rgba(0, 0, 0, 0.3);
                    border-radius: 8px;
                    font-size: 14px;
                    border-left: 4px solid #f1c40f;
                }
                .role-indicator {
                    display: flex;
                    justify-content: space-around;
                    margin-bottom: 20px;
                    padding: 10px;
                    background: rgba(0, 0, 0, 0.2);
                    border-radius: 8px;
                }
                .role {
                    padding: 5px 15px;
                    border-radius: 20px;
                    font-size: 12px;
                    font-weight: bold;
                }
                .admin {
                    background: #e74c3c;
                }
                .becario {
                    background: #2ecc71;
                }
            </style>
        </head>
        <body>
            <div class="login-container">
                <h2>🔐 DGTIC-UNAM - Centro de Datos</h2>
                
                <div class="role-indicator">
                    <span class="role admin">ADMIN</span>
                    <span class="role becario">BECARIO</span>
                </div>
                
                <form method="POST" action="/login">
                    <div class="form-group">
                        <input type="password" name="password" placeholder="Ingresa la contraseña" required>
                    </div>
                    <button type="submit">Acceder al Sistema</button>
                </form>
                
                <div class="info-box">
                    <p><strong>🔒 Sistema de Monitoreo de Producción</strong></p>
                    <p>• DGTIC-UNAM - Programa de Becarios</p>
                    <p>• Centro de Datos y Telecomunicaciones</p>
                    <p>• Acceso restringido por roles</p>
                </div>
            </div>
        </body>
        </html>
    '''

@app.route('/logout')
def logout():
    """Cerrar sesión"""
    session_id = request.cookies.get('session_id')
    if session_id in sesiones_activas:
        rol = sesiones_activas[session_id]['rol']
        auditoria_log.put({
            'usuario': rol,
            'ip': request.remote_addr,
            'accion': 'logout',
            'exito': True
        })
        del sesiones_activas[session_id]
    
    response = make_response(redirect('/login'))
    response.delete_cookie('session_id')
    return response

# =============================
# RUTAS PRINCIPALES
# =============================
@app.route('/')
def dashboard():
    """Dashboard principal - DIFERENCIADO por rol"""
    if not hasattr(request, 'sesion'):
        return redirect('/login')
    
    stats = HerramientasMonitoreo.obtener_estadisticas_sistema()
    
    # CONTENIDO ESPECÍFICO POR ROL
    if request.sesion['rol'] == 'admin':
        # PANEL ADMIN - CON HERRAMIENTAS COMPLETAS
        contenido_personalizado = f'''
            <div class="card">
                <h2>👑 Panel de Administración COMPLETO</h2>
                <p><strong>Acceso completo al sistema con herramientas reales:</strong></p>
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; margin-top: 15px;">
                    <div>
                        <h3>🖥️ Control de Servidores</h3>
                        <ul>
                            <li>• Consola de comandos reales</li>
                            <li>• Monitoreo de procesos en tiempo real</li>
                            <li>• Gestión de usuarios conectados</li>
                            <li>• Información detallada de red</li>
                        </ul>
                        <a href="/admin/server" class="btn">Acceder al Panel</a>
                    </div>
                    <div>
                        <h3>📊 Auditoría y Logs</h3>
                        <ul>
                            <li>• Visualización de logs del sistema</li>
                            <li>• Análisis de accesos y eventos</li>
                            <li>• Búsqueda avanzada en logs</li>
                            <li>• Exportación de registros</li>
                        </ul>
                        <a href="/admin/logs" class="btn">Ver Logs</a>
                    </div>
                </div>
            </div>
        '''
        # NAVEGACIÓN PARA ADMIN
        nav = '''
            <div class="nav">
                <a href="/" class="btn">📊 Dashboard</a>
                <a href="/monitor" class="btn">📈 Monitor en Tiempo Real</a>
                <a href="/red" class="btn">🌐 Herramientas de Red</a>
                <a href="/telecom" class="btn">📡 Telecomunicaciones</a>
                <a href="/configuracion" class="btn">⚙️ Configuración</a>
                <a href="/admin/server" class="btn">👑 Panel Admin</a>
            </div>
        '''
    else:  
        # PANEL BECARIO - SOLO INFORMACIÓN
        contenido_personalizado = f'''
            <div class="card">
                <h2>🎯 Programa de Becarios DGTIC-UNAM</h2>
                <p><strong>Bienvenido al Sistema de Monitoreo y Seguridad</strong></p>
                
                <div style="background: rgba(52, 152, 219, 0.1); padding: 20px; border-radius: 10px; margin: 15px 0;">
                    <h3>🏛️ Acerca del Programa:</h3>
                    <p>El Programa de Becarios de la DGTIC-UNAM tiene como objetivo formar profesionales 
                    especializados en la administración de centros de datos, telecomunicaciones 
                    y seguridad informática mediante un enfoque práctico en entornos controlados.</p>
                </div>
                
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; margin-top: 15px;">
                    <div>
                        <h3>📚 Áreas de Formación:</h3>
                        <ul>
                            <li>• Monitoreo de infraestructura crítica</li>
                            <li>• Gestión de redes y telecomunicaciones</li>
                            <li>• Seguridad perimetral y hardening</li>
                            <li>• Automatización de operaciones</li>
                            <li>• Respuesta a incidentes</li>
                        </ul>
                    </div>
                    <div>
                        <h3>🎓 Competencias a Desarrollar:</h3>
                        <ul>
                            <li>• Administración de sistemas Linux</li>
                            <li>• Diagnóstico de problemas de red</li>
                            <li>• Uso de herramientas de monitoreo</li>
                            <li>• Implementación de políticas de seguridad</li>
                            <li>• Documentación de procedimientos</li>
                        </ul>
                    </div>
                </div>
                
                <div style="margin-top: 20px; padding: 15px; background: rgba(46, 204, 113, 0.1); border-radius: 10px;">
                    <h3>📊 Sistema Actual - Métricas en Tiempo Real:</h3>
                    <p>Este panel muestra métricas REALES del sistema donde se ejecuta la aplicación.</p>
                    <p>Como becario, puedes observar el comportamiento del sistema pero no interactuar con él.</p>
                </div>
                
                <div style="margin-top: 20px; padding: 15px; background: rgba(155, 89, 182, 0.1); border-radius: 10px;">
                    <h3>🔒 Notas de Seguridad:</h3>
                    <ul>
                        <li>• El acceso a herramientas está restringido por roles</li>
                        <li>• Los administradores tienen control completo del sistema</li>
                        <li>• Los becarios tienen acceso de solo lectura para aprendizaje</li>
                        <li>• Todas las acciones quedan registradas en logs</li>
                    </ul>
                </div>
            </div>
        '''
        # NAVEGACIÓN MINIMA PARA BECARIO
        nav = '''
            <div class="nav">
                <a href="/" class="btn">📊 Dashboard Becario</a>
            </div>
        '''
    
    return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard - DGTIC-UNAM</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Arial, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background: #0a1929;
                    color: white;
                }}
                .container {{
                    max-width: 1400px;
                    margin: 0 auto;
                }}
                .header {{
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 30px;
                    padding-bottom: 20px;
                    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
                }}
                .stats {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }}
                .stat-card {{
                    background: linear-gradient(135deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.02) 100%);
                    padding: 20px;
                    border-radius: 10px;
                    border: 1px solid rgba(255, 255, 255, 0.1);
                }}
                .card {{
                    background: linear-gradient(135deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.02) 100%);
                    padding: 25px;
                    border-radius: 10px;
                    border: 1px solid rgba(255, 255, 255, 0.1);
                    margin-bottom: 20px;
                }}
                .btn {{
                    display: inline-block;
                    padding: 10px 20px;
                    background: #2980b9;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    margin: 5px;
                    font-size: 14px;
                    transition: background 0.3s;
                }}
                .btn:hover {{
                    background: #3498db;
                }}
                .btn-danger {{
                    background: #c0392b;
                }}
                .btn-danger:hover {{
                    background: #e74c3c;
                }}
                .nav {{
                    display: flex;
                    gap: 10px;
                    margin-bottom: 20px;
                    flex-wrap: wrap;
                }}
                .role-badge {{
                    display: inline-block;
                    padding: 5px 15px;
                    border-radius: 20px;
                    font-size: 12px;
                    font-weight: bold;
                    margin-left: 10px;
                }}
                .admin-badge {{
                    background: #e74c3c;
                }}
                .becario-badge {{
                    background: #2ecc71;
                }}
                .metric-value {{
                    font-size: 24px;
                    font-weight: bold;
                    margin: 10px 0;
                }}
                .metric-label {{
                    color: #95a5a6;
                    font-size: 14px;
                }}
                ul {{
                    padding-left: 20px;
                }}
                li {{
                    margin-bottom: 5px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📊 DGTIC-UNAM - Centro de Datos 
                        <span class="role-badge {request.sesion['rol']}-badge">{request.sesion['rol'].upper()}</span>
                    </h1>
                    <div>
                        <a href="/logout" class="btn btn-danger">🚪 Cerrar Sesión</a>
                    </div>
                </div>
                
                {nav}
                
                {contenido_personalizado}
                
                <div class="card">
                    <h2>📈 Métricas del Sistema (Tiempo Real)</h2>
                    <div class="stats">
                        <div class="stat-card">
                            <h3>💻 CPU</h3>
                            <div class="metric-value" id="cpuValue">{stats['cpu']['porcentaje']}</div>
                            <div class="metric-label">Uso del procesador</div>
                        </div>
                        
                        <div class="stat-card">
                            <h3>🧠 Memoria</h3>
                            <div class="metric-value" id="memValue">{stats['memoria']['porcentaje']}</div>
                            <div class="metric-label">{stats['memoria']['usado']} usado de {stats['memoria']['total']}</div>
                        </div>
                        
                        <div class="stat-card">
                            <h3>💾 Disco</h3>
                            <div class="metric-value" id="diskValue">{stats['disco']['porcentaje']}</div>
                            <div class="metric-label">{stats['disco']['usado']} usado de {stats['disco']['total']}</div>
                        </div>
                        
                        <div class="stat-card">
                            <h3>🔄 Procesos</h3>
                            <div class="metric-value" id="procValue">{stats['procesos']['total']}</div>
                            <div class="metric-label">Procesos activos</div>
                        </div>
                    </div>
                    
                    <div style="margin-top: 20px; text-align: center;">
                        <button onclick="actualizarMetricas()" class="btn">🔄 Actualizar Métricas</button>
                        <span style="margin-left: 20px; color: #95a5a6;" id="lastUpdate">
                            Última actualización: {datetime.now().strftime("%H:%M:%S")}
                        </span>
                    </div>
                </div>
                
                <div class="card">
                    <h3>📋 Información del Sistema</h3>
                    <p><strong>Aplicación:</strong> {Config.APP_NAME}</p>
                    <p><strong>Versión:</strong> {Config.VERSION}</p>
                    <p><strong>Institución:</strong> {Config.INSTITUCION}</p>
                    <p><strong>Departamento:</strong> {Config.DEPARTAMENTO}</p>
                </div>
            </div>
            
            <script>
            function actualizarMetricas() {{
                fetch('/api/metricas')
                    .then(response => response.json())
                    .then(data => {{
                        document.getElementById('cpuValue').textContent = data.cpu?.porcentaje || 'N/A';
                        document.getElementById('memValue').textContent = data.memoria?.porcentaje || 'N/A';
                        document.getElementById('diskValue').textContent = data.disco?.porcentaje || 'N/A';
                        document.getElementById('procValue').textContent = data.procesos?.total || '0';
                        document.getElementById('lastUpdate').textContent = 
                            'Última actualización: ' + new Date().toLocaleTimeString();
                    }});
            }}
            
            // Actualizar cada 30 segundos
            setInterval(actualizarMetricas, 30000);
            </script>
        </body>
        </html>
    '''

# =============================
# RUTAS PARA ADMIN - COMPLETAS
# =============================
@app.route('/admin/server')
@requiere_rol('admin')
def admin_server():
    """Panel de control de servidores para admin - TODO REAL"""
    # Obtener información REAL
    stats = HerramientasMonitoreo.obtener_estadisticas_sistema()
    procesos = HerramientasMonitoreo.monitorear_procesos(10)
    usuarios = HerramientasMonitoreo.obtener_usuarios_conectados()
    
    # Generar HTML para procesos
    procesos_html = ""
    for proc in procesos:
        procesos_html += f'''
            <tr>
                <td>{proc.get('usuario', 'N/A')}</td>
                <td>{proc.get('pid', 'N/A')}</td>
                <td>{proc.get('cpu', 'N/A')}%</td>
                <td>{proc.get('mem', 'N/A')}%</td>
                <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis;">{proc.get('comando', 'N/A')}</td>
            </tr>
        '''
    
    # Generar HTML para usuarios
    usuarios_html = ""
    for user in usuarios:
        usuarios_html += f'''
            <tr>
                <td>{user.get('usuario', 'N/A')}</td>
                <td>{user.get('terminal', 'N/A')}</td>
                <td>{user.get('fecha', 'N/A')}</td>
                <td>{user.get('ip', 'N/A')}</td>
            </tr>
        '''
    
    return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Control de Servidores - Admin</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Arial, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background: #0a1929;
                    color: white;
                }}
                .container {{
                    max-width: 1400px;
                    margin: 0 auto;
                }}
                .header {{
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 30px;
                }}
                .card {{
                    background: linear-gradient(135deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.02) 100%);
                    padding: 25px;
                    border-radius: 10px;
                    border: 1px solid rgba(255, 255, 255, 0.1);
                    margin-bottom: 20px;
                }}
                .btn {{
                    display: inline-block;
                    padding: 10px 20px;
                    background: #2980b9;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                }}
                .btn-danger {{
                    background: #c0392b;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 15px;
                }}
                th, td {{
                    padding: 12px;
                    text-align: left;
                    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
                }}
                th {{
                    background: rgba(255, 255, 255, 0.05);
                }}
                .command-input {{
                    width: 100%;
                    padding: 10px;
                    background: rgba(255, 255, 255, 0.1);
                    border: 1px solid rgba(255, 255, 255, 0.2);
                    color: white;
                    border-radius: 5px;
                    margin-bottom: 10px;
                }}
                .output-box {{
                    background: black;
                    color: #00ff00;
                    padding: 15px;
                    border-radius: 5px;
                    font-family: monospace;
                    max-height: 300px;
                    overflow-y: auto;
                    margin-top: 10px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🖥️ Control de Servidores - ADMIN</h1>
                    <div>
                        <a href="/" class="btn">← Dashboard</a>
                        <a href="/logout" class="btn btn-danger">Cerrar Sesión</a>
                    </div>
                </div>
                
                <div class="card">
                    <h2>📊 Estado REAL del Sistema</h2>
                    <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px;">
                        <div>
                            <h3>💻 CPU</h3>
                            <p>Uso: {stats['cpu']['porcentaje']}</p>
                        </div>
                        <div>
                            <h3>🧠 Memoria</h3>
                            <p>Usado: {stats['memoria']['usado']} / {stats['memoria']['total']}</p>
                            <p>Porcentaje: {stats['memoria']['porcentaje']}</p>
                        </div>
                        <div>
                            <h3>💾 Disco</h3>
                            <p>Usado: {stats['disco']['usado']} / {stats['disco']['total']}</p>
                            <p>Libre: {stats['disco']['libre']}</p>
                        </div>
                        <div>
                            <h3>🔄 Procesos</h3>
                            <p>Total: {stats['procesos']['total']}</p>
                        </div>
                    </div>
                </div>
                
                <div class="card">
                    <h2>👥 Usuarios Conectados (who)</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Usuario</th>
                                <th>Terminal</th>
                                <th>Fecha/Hora</th>
                                <th>IP/Host</th>
                            </tr>
                        </thead>
                        <tbody>
                            {usuarios_html if usuarios_html else '<tr><td colspan="4">No hay usuarios conectados</td></tr>'}
                        </tbody>
                    </table>
                </div>
                
                <div class="card">
                    <h2>🔄 Top 10 Procesos por CPU (ps aux)</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Usuario</th>
                                <th>PID</th>
                                <th>CPU%</th>
                                <th>Mem%</th>
                                <th>Comando</th>
                            </tr>
                        </thead>
                        <tbody>
                            {procesos_html if procesos_html else '<tr><td colspan="5">No se pudieron obtener procesos</td></tr>'}
                        </tbody>
                    </table>
                </div>
                
                <div class="card">
                    <h2>⚡ Consola de Comandos (Shell - SIN SUDO)</h2>
                    <form method="POST" action="/admin/command" id="commandForm">
                        <input type="text" name="command" class="command-input" placeholder="Ej: ls -la, df -h, whoami, ps aux" required>
                        <button type="submit" class="btn">Ejecutar Comando</button>
                    </form>
                    <div id="commandOutput" class="output-box"></div>
                </div>
                
                <div class="card">
                    <h2>🌐 Información de Red (ip/ss)</h2>
                    <div style="margin-top: 15px;">
                        <button onclick="obtenerInfoRed()" class="btn">🔗 Obtener Info de Red</button>
                    </div>
                    <div id="redOutput" class="output-box" style="display: none; margin-top: 10px;"></div>
                </div>
            </div>
            
            <script>
            document.getElementById('commandForm').addEventListener('submit', async function(e) {{
                e.preventDefault();
                const formData = new FormData(this);
                const outputDiv = document.getElementById('commandOutput');
                outputDiv.innerHTML = 'Ejecutando comando...';
                
                try {{
                    const response = await fetch('/admin/command', {{
                        method: 'POST',
                        body: formData
                    }});
                    const data = await response.json();
                    if (data.error) {{
                        outputDiv.innerHTML = '<span style="color:red">ERROR: ' + data.error + '</span>';
                    }} else {{
                        outputDiv.innerHTML = data.output;
                    }}
                }} catch (error) {{
                    outputDiv.innerHTML = 'Error: ' + error;
                }}
            }});
            
            function obtenerInfoRed() {{
                const outputDiv = document.getElementById('redOutput');
                outputDiv.style.display = 'block';
                outputDiv.innerHTML = 'Obteniendo información de red...';
                
                fetch('/admin/network-info')
                    .then(response => response.json())
                    .then(data => {{
                        let output = "=== Interfaces de Red ===\\n";
                        output += data.interfaces || "No disponible";
                        output += "\\n\\n=== Tabla de Rutas ===\\n";
                        output += data.rutas || "No disponible";
                        output += "\\n\\n=== Conexiones Activas ===\\n";
                        output += data.conexiones || "No disponible";
                        outputDiv.innerHTML = output;
                    }})
                    .catch(error => {{
                        outputDiv.innerHTML = 'Error: ' + error;
                    }});
            }}
            </script>
        </body>
        </html>
    '''

@app.route('/admin/command', methods=['POST'])
@requiere_rol('admin')
def admin_command():
    """Ejecutar comando shell REAL (sin sudo)"""
    comando = request.form.get('command', '')
    
    # Lista de comandos SEGUROS permitidos
    comandos_seguros = [
        'ls', 'pwd', 'whoami', 'date', 'uptime',
        'df', 'ps', 'free', 'uname', 'hostname',
        'ping', 'who', 'w', 'last', 'history',
        'netstat', 'ss', 'ip', 'ifconfig', 'curl',
        'dig', 'nslookup', 'host', 'traceroute'
    ]
    
    comando_base = comando.split()[0] if comando.split() else ''
    
    if comando_base not in comandos_seguros:
        return jsonify({
            'output': '',
            'error': f'Comando "{comando_base}" no permitido. Comandos permitidos: {", ".join(comandos_seguros)}'
        })
    
    resultado = HerramientasMonitoreo.ejecutar_comando(comando)
    
    auditoria_log.put({
        'usuario': request.sesion['rol'],
        'ip': request.remote_addr,
        'accion': f'comando_exec: {comando[:50]}',
        'exito': resultado['exito']
    })
    
    return jsonify({
        'output': resultado.get('salida', '') + (resultado.get('error', '') if resultado.get('error') else ''),
        'error': ''
    })

@app.route('/admin/network-info')
@requiere_rol('admin')
def admin_network_info():
    """Obtener información de red REAL"""
    info = HerramientasMonitoreo.obtener_info_red()
    return jsonify(info)

@app.route('/admin/logs')
@requiere_rol('admin')
def admin_logs():
    """Visualización de logs REALES para admin"""
    busqueda = request.args.get('search', '')
    logs = HerramientasMonitoreo.analizar_logs(busqueda, 100)
    
    logs_html = ""
    for log in logs[-50:]:  # Mostrar últimos 50
        exito = log.get('exito', '')
        color = 'green' if str(exito).lower() == 'true' else 'red'
        logs_html += f'''
            <tr>
                <td>{log.get('timestamp', '')}</td>
                <td><span style="color:{color}">●</span> {log.get('usuario', '')}</td>
                <td>{log.get('ip', '')}</td>
                <td>{log.get('accion', '')}</td>
                <td>{exito}</td>
            </tr>
        '''
    
    return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Logs del Sistema - Admin</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Arial, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background: #0a1929;
                    color: white;
                }}
                .container {{
                    max-width: 1400px;
                    margin: 0 auto;
                }}
                .header {{
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 30px;
                }}
                .card {{
                    background: linear-gradient(135deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.02) 100%);
                    padding: 25px;
                    border-radius: 10px;
                    border: 1px solid rgba(255, 255, 255, 0.1);
                    margin-bottom: 20px;
                }}
                .btn {{
                    display: inline-block;
                    padding: 10px 20px;
                    background: #2980b9;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                }}
                .btn-danger {{
                    background: #c0392b;
                }}
                .search-input {{
                    width: 300px;
                    padding: 10px;
                    background: rgba(255, 255, 255, 0.1);
                    border: 1px solid rgba(255, 255, 255, 0.2);
                    color: white;
                    border-radius: 5px;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 15px;
                }}
                th, td {{
                    padding: 12px;
                    text-align: left;
                    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
                }}
                th {{
                    background: rgba(255, 255, 255, 0.05);
                }}
                tr:hover {{
                    background: rgba(255, 255, 255, 0.05);
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📊 Logs del Sistema - ADMIN</h1>
                    <div>
                        <a href="/" class="btn">← Dashboard</a>
                        <a href="/logout" class="btn btn-danger">Cerrar Sesión</a>
                    </div>
                </div>
                
                <div class="card">
                    <h2>🔍 Auditoría del Sistema (LOGS REALES)</h2>
                    <form method="GET" action="/admin/logs" style="display: flex; gap: 10px; margin-bottom: 20px;">
                        <input type="text" name="search" class="search-input" placeholder="Buscar en logs..." value="{busqueda}">
                        <button type="submit" class="btn">Buscar</button>
                        <a href="/admin/logs" class="btn">Limpiar</a>
                    </form>
                    
                    <table>
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>Usuario</th>
                                <th>IP</th>
                                <th>Acción</th>
                                <th>Éxito</th>
                            </tr>
                        </thead>
                        <tbody>
                            {logs_html if logs_html else '<tr><td colspan="5">No hay logs disponibles</td></tr>'}
                        </tbody>
                    </table>
                    
                    <div style="margin-top: 15px; color: #95a5a6;">
                        Mostrando {len(logs)} registros
                    </div>
                </div>
            </div>
        </body>
        </html>
    '''

# =============================
# RUTAS PARA TODOS LOS USUARIOS (SOLO ADMIN)
# =============================
@app.route('/monitor')
@requiere_rol('admin')
def monitor_tiempo_real():
    """Monitor en tiempo real REAL solo para admin"""
    stats = HerramientasMonitoreo.obtener_estadisticas_sistema()
    procesos = HerramientasMonitoreo.monitorear_procesos(5)
    
    # Generar HTML para procesos
    procesos_html = ""
    for proc in procesos:
        procesos_html += f'''
            <tr>
                <td>{proc.get('usuario', 'N/A')}</td>
                <td>{proc.get('pid', 'N/A')}</td>
                <td>{proc.get('cpu', 'N/A')}%</td>
                <td>{proc.get('mem', 'N/A')}%</td>
                <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis;">{proc.get('comando', 'N/A')}</td>
            </tr>
        '''
    
    return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Monitor en Tiempo Real - DGTIC-UNAM</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Arial, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background: #0a1929;
                    color: white;
                }}
                .container {{
                    max-width: 1400px;
                    margin: 0 auto;
                }}
                .header {{
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 30px;
                }}
                .card {{
                    background: linear-gradient(135deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.02) 100%);
                    padding: 25px;
                    border-radius: 10px;
                    border: 1px solid rgba(255, 255, 255, 0.1);
                    margin-bottom: 20px;
                }}
                .btn {{
                    display: inline-block;
                    padding: 10px 20px;
                    background: #2980b9;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                }}
                .btn-danger {{
                    background: #c0392b;
                }}
                .metric-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }}
                .metric-box {{
                    background: rgba(255, 255, 255, 0.05);
                    padding: 20px;
                    border-radius: 10px;
                    text-align: center;
                }}
                .metric-value {{
                    font-size: 32px;
                    font-weight: bold;
                    margin: 10px 0;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 15px;
                }}
                th, td {{
                    padding: 12px;
                    text-align: left;
                    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
                }}
                th {{
                    background: rgba(255, 255, 255, 0.05);
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📈 Monitor en Tiempo Real - DATOS REALES</h1>
                    <div>
                        <a href="/" class="btn">← Dashboard</a>
                        <a href="/logout" class="btn btn-danger">Cerrar Sesión</a>
                    </div>
                </div>
                
                <div class="card">
                    <h2>📊 Métricas del Sistema (ACTUALES)</h2>
                    
                    <div class="metric-grid">
                        <div class="metric-box">
                            <h3>💻 CPU</h3>
                            <div class="metric-value" id="cpuValue">{stats['cpu']['porcentaje']}</div>
                            <div class="metric-label">Uso actual del procesador</div>
                        </div>
                        
                        <div class="metric-box">
                            <h3>🧠 Memoria</h3>
                            <div class="metric-value" id="memValue">{stats['memoria']['porcentaje']}</div>
                            <div class="metric-label">{stats['memoria']['usado']} usado de {stats['memoria']['total']}</div>
                        </div>
                        
                        <div class="metric-box">
                            <h3>💾 Disco</h3>
                            <div class="metric-value" id="diskValue">{stats['disco']['porcentaje']}</div>
                            <div>{stats['disco']['usado']} usado de {stats['disco']['total']}</div>
                        </div>
                        
                        <div class="metric-box">
                            <h3>🔄 Procesos</h3>
                            <div class="metric-value" id="procValue">{stats['procesos']['total']}</div>
                            <div>Procesos activos en el sistema</div>
                        </div>
                    </div>
                    
                    <div style="margin-top: 20px; text-align: center;">
                        <button onclick="actualizarMetricas()" class="btn">🔄 Actualizar Ahora</button>
                        <span style="margin-left: 20px; color: #95a5a6;" id="lastUpdate">
                            Última actualización: {datetime.now().strftime("%H:%M:%S")}
                        </span>
                    </div>
                </div>
                
                <div class="card">
                    <h2>🔄 Top 5 Procesos por CPU (ps aux)</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Usuario</th>
                                <th>PID</th>
                                <th>CPU%</th>
                                <th>Mem%</th>
                                <th>Comando</th>
                            </tr>
                        </thead>
                        <tbody>
                            {procesos_html if procesos_html else '<tr><td colspan="5">No se pudieron obtener procesos</td></tr>'}
                        </tbody>
                    </table>
                </div>
            </div>
            
            <script>
            function actualizarMetricas() {{
                fetch('/api/metricas')
                    .then(response => response.json())
                    .then(data => {{
                        document.getElementById('cpuValue').textContent = data.cpu?.porcentaje || 'N/A';
                        document.getElementById('memValue').textContent = data.memoria?.porcentaje || 'N/A';
                        document.getElementById('diskValue').textContent = data.disco?.porcentaje || 'N/A';
                        document.getElementById('procValue').textContent = data.procesos?.total || '0';
                        document.getElementById('lastUpdate').textContent = 
                            'Última actualización: ' + new Date().toLocaleTimeString();
                    }});
            }}
            
            // Actualizar cada 30 segundos
            setInterval(actualizarMetricas, 30000);
            </script>
        </body>
        </html>
    '''

@app.route('/red')
@requiere_rol('admin')
def herramientas_red():
    """Herramientas de red con escáner FUNCIONAL - solo admin"""
    # Escanear puertos usando SS (método principal)
    puertos_ss = HerramientasMonitoreo.escanear_puertos_con_ss()
    
    resultados = ""
    if puertos_ss:
        for puerto in puertos_ss:
            color = 'green'
            resultados += f'''
                <tr>
                    <td>{puerto.get('puerto')}</td>
                    <td><span style="color:{color}">●</span> {puerto.get('estado')}</td>
                    <td>{puerto.get('servicio')}</td>
                    <td>{puerto.get('protocolo')}</td>
                </tr>
            '''
    else:
        resultados = '''
            <tr>
                <td colspan="4" style="text-align: center; color: #95a5a6;">
                    ⚠️ No se encontraron puertos abiertos
                    <br><small>Prueba ejecutando manualmente: <code>ss -tuln</code></small>
                </td>
            </tr>
        '''
    
    return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Herramientas de Red - DGTIC-UNAM</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Arial, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background: #0a1929;
                    color: white;
                }}
                .container {{
                    max-width: 1400px;
                    margin: 0 auto;
                }}
                .header {{
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 30px;
                }}
                .card {{
                    background: linear-gradient(135deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.02) 100%);
                    padding: 25px;
                    border-radius: 10px;
                    border: 1px solid rgba(255, 255, 255, 0.1);
                    margin-bottom: 20px;
                }}
                .btn {{
                    display: inline-block;
                    padding: 10px 20px;
                    background: #2980b9;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                }}
                .btn-danger {{
                    background: #c0392b;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 15px;
                }}
                th, td {{
                    padding: 12px;
                    text-align: left;
                    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
                }}
                .info-box {{
                    background: rgba(255, 255, 0, 0.1);
                    padding: 15px;
                    border-radius: 5px;
                    margin: 15px 0;
                    border-left: 4px solid yellow;
                }}
                code {{
                    background: rgba(0,0,0,0.3);
                    padding: 2px 5px;
                    border-radius: 3px;
                    font-family: monospace;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🌐 Herramientas de Red - ESCÁNER FUNCIONAL</h1>
                    <div>
                        <a href="/" class="btn">← Dashboard</a>
                        <a href="/logout" class="btn btn-danger">Cerrar Sesión</a>
                    </div>
                </div>
                
                <div class="card">
                    <h2>🔍 Puertos Abiertos (Método SS)</h2>
                    
                    <div class="info-box">
                        <p><strong>🎯 Método Confirmado:</strong> Usando <code>ss -tuln</code> para detectar puertos sin root.</p>
                        <p>Este comando muestra los puertos que están actualmente escuchando conexiones.</p>
                    </div>
                    
                    <button onclick="actualizarPuertos()" class="btn">🔄 Actualizar Lista de Puertos</button>
                    
                    <h3 style="margin-top: 20px;">📊 Puertos Detectados:</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>Puerto</th>
                                <th>Estado</th>
                                <th>Servicio</th>
                                <th>Protocolo</th>
                            </tr>
                        </thead>
                        <tbody id="puertosBody">
                            {resultados}
                        </tbody>
                    </table>
                </div>
                
                <div class="card">
                    <h2>📡 Test de Conectividad</h2>
                    <form id="pingForm">
                        <div style="display: flex; gap: 10px; margin-bottom: 15px;">
                            <input type="text" id="destino" placeholder="Ej: 8.8.8.8, google.com" style="flex: 1;">
                            <button type="button" onclick="testPing()" class="btn">📡 Probar Conectividad</button>
                        </div>
                    </form>
                    <div id="pingResult" style="margin-top: 15px; padding: 15px; background: rgba(0,0,0,0.3); border-radius: 5px; display: none;">
                    </div>
                </div>
            </div>
            
            <script>
            function actualizarPuertos() {{
                fetch('/api/puertos')
                    .then(response => response.json())
                    .then(data => {{
                        const tbody = document.getElementById('puertosBody');
                        if (data.length > 0) {{
                            let html = '';
                            data.forEach(puerto => {{
                                html += `
                                    <tr>
                                        <td>${{puerto.puerto}}</td>
                                        <td><span style="color:green">●</span> ${{puerto.estado}}</td>
                                        <td>${{puerto.servicio}}</td>
                                        <td>${{puerto.protocolo}}</td>
                                    </tr>
                                `;
                            }});
                            tbody.innerHTML = html;
                        }} else {{
                            tbody.innerHTML = `
                                <tr>
                                    <td colspan="4" style="text-align: center; color: #95a5a6;">
                                        ⚠️ No se encontraron puertos abiertos
                                    </td>
                                </tr>
                            `;
                        }}
                    }});
            }}
            
            function testPing() {{
                const destino = document.getElementById('destino').value;
                if (!destino) {{
                    alert('Por favor ingresa un destino');
                    return;
                }}
                
                const resultDiv = document.getElementById('pingResult');
                resultDiv.style.display = 'block';
                resultDiv.innerHTML = 'Probando conectividad a ' + destino + '...';
                
                fetch('/api/ping?destino=' + encodeURIComponent(destino))
                    .then(response => response.json())
                    .then(data => {{
                        if (data.conectado) {{
                            resultDiv.innerHTML = '✅ Conectado a ' + destino + '<br>' + 
                                                 'Detalles: ' + data.detalles;
                        }} else {{
                            resultDiv.innerHTML = '❌ No se pudo conectar a ' + destino + '<br>' +
                                                 'Error: ' + data.detalles;
                        }}
                    }});
            }}
            </script>
        </body>
        </html>
    '''

@app.route('/telecom')
@requiere_rol('admin')
def telecomunicaciones():
    """Página de herramientas de telecomunicaciones REALES - solo admin"""
    return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Telecomunicaciones - DGTIC-UNAM</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Arial, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background: #0a1929;
                    color: white;
                }}
                .container {{
                    max-width: 1400px;
                    margin: 0 auto;
                }}
                .header {{
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 30px;
                }}
                .card {{
                    background: linear-gradient(135deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.02) 100%);
                    padding: 25px;
                    border-radius: 10px;
                    border: 1px solid rgba(255, 255, 255, 0.1);
                    margin-bottom: 20px;
                }}
                .btn {{
                    display: inline-block;
                    padding: 10px 20px;
                    background: #2980b9;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                }}
                .btn-danger {{
                    background: #c0392b;
                }}
                .output-box {{
                    background: black;
                    color: #00ff00;
                    padding: 15px;
                    border-radius: 5px;
                    font-family: monospace;
                    max-height: 300px;
                    overflow-y: auto;
                }}
                .input-group {{
                    margin-bottom: 15px;
                }}
                input {{
                    width: 100%;
                    padding: 10px;
                    background: rgba(255, 255, 255, 0.1);
                    border: 1px solid rgba(255, 255, 255, 0.2);
                    color: white;
                    border-radius: 5px;
                    margin-bottom: 10px;
                }}
                .info-box {{
                    background: rgba(52, 152, 219, 0.1);
                    padding: 15px;
                    border-radius: 5px;
                    margin: 15px 0;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📡 Telecomunicaciones - HERRAMIENTAS REALES</h1>
                    <div>
                        <a href="/" class="btn">← Dashboard</a>
                        <a href="/logout" class="btn btn-danger">Cerrar Sesión</a>
                    </div>
                </div>
                
                <div class="card">
                    <h2>🌐 Diagnóstico de Red</h2>
                    <div class="info-box">
                        <p><strong>🎯 Herramientas de diagnóstico de red para administradores.</strong></p>
                    </div>
                    
                    <div class="input-group">
                        <label>Comando a ejecutar:</label>
                        <input type="text" id="telecomCommand" placeholder="Ej: ip addr show, ss -tun, ping -c 3 google.com">
                    </div>
                    <button onclick="ejecutarComandoTelecom()" class="btn">🚀 Ejecutar Comando</button>
                    <div id="telecomOutput" class="output-box" style="display: none; margin-top: 15px;"></div>
                </div>
                
                <div class="card">
                    <h2>📊 Comandos Predefinidos Útiles</h2>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 15px;">
                        <button onclick="setCommand('ip addr show')" class="btn">📡 Interfaces de Red</button>
                        <button onclick="setCommand('ss -tun')" class="btn">🔗 Conexiones Activas</button>
                        <button onclick="setCommand('ping -c 3 8.8.8.8')" class="btn">📶 Test Ping</button>
                        <button onclick="setCommand('dig google.com')" class="btn">🔍 DNS Lookup</button>
                        <button onclick="setCommand('curl -I https://google.com')" class="btn">🌐 HTTP Headers</button>
                        <button onclick="setCommand('hostname -I')" class="btn">📍 IP del Sistema</button>
                    </div>
                </div>
            </div>
            
            <script>
            function setCommand(cmd) {{
                document.getElementById('telecomCommand').value = cmd;
            }}
            
            function ejecutarComandoTelecom() {{
                const comando = document.getElementById('telecomCommand').value;
                const outputDiv = document.getElementById('telecomOutput');
                
                if (!comando) {{
                    outputDiv.innerHTML = '⚠️ Por favor ingresa un comando';
                    outputDiv.style.display = 'block';
                    return;
                }}
                
                outputDiv.style.display = 'block';
                outputDiv.innerHTML = 'Ejecutando comando: ' + comando + '...';
                
                fetch('/telecom/command', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/x-www-form-urlencoded',
                    }},
                    body: 'command=' + encodeURIComponent(comando)
                }})
                .then(response => response.json())
                .then(data => {{
                    if (data.error) {{
                        outputDiv.innerHTML = '<span style="color:red">ERROR: ' + data.error + '</span>';
                    }} else {{
                        outputDiv.innerHTML = data.output;
                    }}
                }})
                .catch(error => {{
                    outputDiv.innerHTML = 'Error: ' + error;
                }});
            }}
            </script>
        </body>
        </html>
    '''

@app.route('/telecom/command', methods=['POST'])
@requiere_rol('admin')
def telecom_command():
    """Ejecutar comando de telecomunicaciones - solo admin"""
    comando = request.form.get('command', '')
    resultado = HerramientasMonitoreo.ejecutar_comando_telecom(comando)
    
    return jsonify({
        'output': resultado.get('salida', '') + (resultado.get('error', '') if resultado.get('error') else ''),
        'error': resultado.get('error', '') if not resultado.get('exito') else ''
    })

@app.route('/configuracion')
@requiere_rol('admin')
def configuracion():
    """Página de configuración REAL - solo admin"""
    # Leer contenido del .env (si existe)
    contenido_env = ""
    if os.path.exists(Config.ENV_FILE):
        with open(Config.ENV_FILE, 'r') as f:
            contenido_env = f.read()
    
    return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Configuración - DGTIC-UNAM</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Arial, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background: #0a1929;
                    color: white;
                }}
                .container {{
                    max-width: 1400px;
                    margin: 0 auto;
                }}
                .header {{
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 30px;
                }}
                .card {{
                    background: linear-gradient(135deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.02) 100%);
                    padding: 25px;
                    border-radius: 10px;
                    border: 1px solid rgba(255, 255, 255, 0.1);
                    margin-bottom: 20px;
                }}
                .btn {{
                    display: inline-block;
                    padding: 10px 20px;
                    background: #2980b9;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                }}
                pre {{
                    background: #000;
                    color: #0f0;
                    padding: 15px;
                    border-radius: 5px;
                    overflow: auto;
                    font-family: monospace;
                }}
                .info-box {{
                    background: rgba(255, 255, 0, 0.1);
                    padding: 15px;
                    border-radius: 5px;
                    margin: 15px 0;
                    border-left: 4px solid yellow;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>⚙️ Configuración del Sistema - REAL</h1>
                    <div>
                        <a href="/" class="btn">← Dashboard</a>
                        <a href="/logout" class="btn btn-danger">Cerrar Sesión</a>
                    </div>
                </div>
                
                <div class="card">
                    <h2>📁 Archivo .env REAL</h2>
                    <p><strong>Ubicación:</strong> {Config.ENV_FILE}</p>
                    <p><strong>Estado:</strong> {'✅ Cargado correctamente' if os.path.exists(Config.ENV_FILE) else '❌ No encontrado'}</p>
                    
                    <h3>Contenido REAL del archivo .env:</h3>
                    <pre>
{contenido_env if contenido_env else 'Archivo .env no encontrado'}
                    </pre>
                </div>
                
                <div class="card">
                    <h2>🔧 Configuración Actual REAL</h2>
                    
                    <h3>🔐 Credenciales</h3>
                    <p><strong>Admin:</strong> {Config.ADMIN_PASSWORD}</p>
                    <p><strong>Becario:</strong> {Config.BECARIO_PASSWORD}</p>
                    
                    <h3>🌐 Servidor</h3>
                    <p><strong>Host:</strong> {Config.HOST}</p>
                    <p><strong>Puerto:</strong> {Config.PORT}</p>
                    <p><strong>Debug:</strong> {Config.DEBUG}</p>
                    
                    <h3>📊 Información del Sistema</h3>
                    <p><strong>Aplicación:</strong> {Config.APP_NAME}</p>
                    <p><strong>Versión:</strong> {Config.VERSION}</p>
                    <p><strong>Institución:</strong> {Config.INSTITUCION}</p>
                </div>
            </div>
        </body>
        </html>
    '''

# =============================
# API ENDPOINTS REALES
# =============================
@app.route('/api/status')
def api_status():
    """API: Estado REAL del sistema"""
    return jsonify({
        "estado": "online",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "configuracion": {
            "app_name": Config.APP_NAME,
            "version": Config.VERSION,
            "puerto": Config.PORT,
            "env_cargado": os.path.exists(Config.ENV_FILE),
            "sesiones_activas": len(sesiones_activas)
        }
    })

@app.route('/api/metricas')
def api_metricas():
    """API: Métricas REALES del sistema"""
    stats = HerramientasMonitoreo.obtener_estadisticas_sistema()
    return jsonify(stats)

@app.route('/api/puertos')
def api_puertos():
    """API: Puertos abiertos (método SS)"""
    puertos = HerramientasMonitoreo.escanear_puertos_con_ss()
    return jsonify(puertos)

@app.route('/api/ping')
def api_ping():
    """API: Test de ping REAL"""
    destino = request.args.get('destino', '8.8.8.8')
    resultado = HerramientasMonitoreo.test_conectividad(destino)
    return jsonify(resultado)

@app.route('/favicon.ico')
def favicon():
    """Favicon para evitar errores 404"""
    return '', 204

# =============================
# EJECUCIÓN PRINCIPAL
# =============================
if __name__ == '__main__':
    try:
        # Inicializar sistema
        Sistema.inicializar()
        
        print(f"\n{'='*70}")
        print(f"SISTEMA DGTIC-UNAM - PROGRAMA DE BECARIOS")
        print(f"{'='*70}")
        print(f"• Aplicación: {Config.APP_NAME}")
        print(f"• Versión: {Config.VERSION}")
        print(f"• Puerto: {Config.PORT}")
        print(f"• Rol Admin: {Config.ADMIN_PASSWORD}")
        print(f"• Rol Becario: {Config.BECARIO_PASSWORD}")
        
        try:
            ip = socket.gethostbyname(socket.gethostname())
            print(f"• URL red: http://{ip}:{Config.PORT}")
        except:
            pass
        
        print(f"\n🎯 DIFERENCIACIÓN DE ROLES:")
        print(f"   • ADMIN: Herramientas completas de administración")
        print(f"   • BECARIO: Panel informativo único (solo lectura)")
        
        print(f"\n🔧 HERRAMIENTAS DISPONIBLES PARA ADMIN:")
        print(f"   1. Dashboard completo con estadísticas")
        print(f"   2. Monitor en tiempo real del sistema")
        print(f"   3. Escáner de puertos FUNCIONAL (método SS)")
        print(f"   4. Herramientas de telecomunicaciones")
        print(f"   5. Consola de comandos reales")
        print(f"   6. Visualización de logs del sistema")
        print(f"   7. Configuración del sistema")
        
        print(f"\n📚 PANEL BECARIO (ÚNICA VISTA):")
        print(f"   • Dashboard informativo único")
        print(f"   • Información teórica del programa")
        print(f"   • Métricas del sistema en tiempo real")
        print(f"   • Sin acceso a herramientas operativas")
        
        print(f"\n🔍 ESCÁNER DE PUERTOS MEJORADO:")
        print(f"   • Método principal: ss -tuln (funciona sin root)")
        print(f"   • Muestra puertos TCP/UDP escuchando")
        print(f"   • Identificación automática de servicios")
        
        print(f"{'='*70}\n")
        
        # Prueba del escáner
        print(f"[🔍] Probando escáner de puertos (método SS)...")
        puertos_detectados = HerramientasMonitoreo.escanear_puertos_con_ss()
        if puertos_detectados:
            print(f"[✅] Escáner FUNCIONA. Encontrados {len(puertos_detectados)} puertos:")
            for puerto in puertos_detectados[:5]:  # Mostrar primeros 5
                print(f"     - Puerto {puerto['puerto']} ({puerto['servicio']}) - {puerto['protocolo']}")
            if len(puertos_detectados) > 5:
                print(f"     ... y {len(puertos_detectados) - 5} más")
        else:
            print(f"[⚠️] No se encontraron puertos abiertos")
        
        # Ejecutar aplicación
        app.run(
            host=Config.HOST,
            port=Config.PORT,
            debug=Config.DEBUG,
            use_reloader=False
        )
        
    except KeyboardInterrupt:
        print("\n\n[🛑] Sistema detenido por el usuario")
        sys.exit(0)
    except Exception as e:
        print(f"\n[❌] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
