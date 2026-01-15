# 🏛️ Sistema de Monitoreo y Seguridad DGTIC-UNAM

**Sistema de Monitoreo y Seguridad para Centros de Datos, Redes, Seguridad y Telecomunicaciones**  
*Desarrollado en el Programa de Becarios DGTIC-UNAM*

## 📋 Tabla de Contenidos
- [🏛️ Sobre el Proyecto](#-sobre-el-proyecto)
- [🎯 Características](#-características)
- [👥 Roles](#-roles)
- [🛠️ Instalación](#️-instalación)
- [🚀 Uso Rápido](#-uso-rápido)
- [🔧 Configuración](#-configuración)
- [📊 Estructura](#-estructura)
- [🔒 Seguridad](#-seguridad)
- [📚 Uso Académico](#-uso-académico)
- [🤝 Contribución](#-contribución)
- [📄 Licencia](#-licencia)
- [📞 Contacto](#-contacto)

## 🏛️ Sobre el Proyecto
Herramienta educativa desarrollada en el **Programa de Becarios DGTIC-UNAM** para capacitación en administración de sistemas y seguridad informática.

**⚠️ ADVERTENCIA:** Este sistema es EXCLUSIVAMENTE para uso educativo en entornos controlados. NO usar en producción sin autorización.

## 🎯 Características
### 🔍 Monitoreo en Tiempo Real
- 📊 Métricas de CPU, memoria, disco y procesos
- 📈 Dashboard interactivo con actualización automática
- 👥 Usuarios conectados
- 🔄 Procesos del sistema

### 🌐 Herramientas de Red
- 🔍 Escáner de puertos (método `ss -tuln`)
- 📡 Pruebas de conectividad (ping)
- 🌐 Diagnóstico de red
- 🔗 Interfaces y conexiones

### ⚡ Consola de Administración
- 🖥️ Ejecución segura de comandos
- 📋 Lista blanca de comandos
- 🔐 Restricciones por roles
- 📝 Auditoría completa

## 👥 Roles
### 👑 Administrador
- Acceso completo a todas las herramientas
- Contraseña: `DGTIC-Admin-2024!` (CAMBIAR)

### 🎓 Becario
- Panel informativo de solo lectura
- Contraseña: `DGTIC-Becario-2024!` (CAMBIAR)

## 🛠️ Instalación
```bash
# 1. Clonar repositorio
git clone https://github.com/tu-usuario/becas_dite_unam_dgtic.git
cd becas_dite_unam_dgtic

# 2. Crear entorno virtual
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Configurar
cp .env.example .env
# Editar .env con tus configuraciones

# 5. Crear directorios
mkdir -p datos_monitoreo/logs


