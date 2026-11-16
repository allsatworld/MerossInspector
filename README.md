# Meross Inspector para Windows 10/11

Aplicación de escritorio en español para diagnóstico y control local de enchufes Meross MSS310 compatibles.

## Funciones
- Detecta automáticamente una posible subred local /24 y busca equipos con puerto HTTP 80 abierto.
- Selecciona una IP detectada o introduce la IP del enchufe.
- Diagnostica modelo y estado, mide potencia (W), tensión (V) e intensidad (A) si el firmware lo permite.
- Envía órdenes de encendido y apagado con autenticación Meross mediante clave local.
- No utiliza servicios en la nube. La clave solo permanece en memoria durante la ejecución.

**Importante:** El escáner identifica equipos que responden en el puerto 80, no garantiza que sean Meross. Para identificar el enchufe hace falta la clave local Meross. El control local depende del firmware y la conectividad del MSS310.

## Obtener el EXE portátil desde GitHub Actions
1. Sube `meross_inspector.py` y `.github/workflows/windows-exe.yml` a la raíz de un repositorio GitHub (respeta la ruta de `.github`).
2. Entra en **Actions > Compilar Meross Inspector Windows EXE > Run workflow**.
3. Cuando la ejecución aparezca en verde, abre la ejecución y descarga el artifact **MerossInspector-Windows-EXE**.
4. Descomprime el ZIP y ejecuta `MerossInspector.exe` en Windows 10/11. No necesita Python instalado.

El EXE se construye en un runner Windows de GitHub. No ha sido compilado ni probado en Windows en este entorno Linux.

## Ejecutar desde código fuente
Con Python 3.10 o posterior: `python meross_inspector.py`. Solo usa la biblioteca estándar de Python.

## Seguridad
- Escanea únicamente redes IPv4 privadas de máximo 254 hosts.
- Usa la herramienta solo en redes propias o donde tengas autorización.
- No subas la clave Meross a GitHub; introdúcela en la interfaz de la aplicación.
- El protocolo HTTP local de Meross no cifra el tráfico; usa una red Wi-Fi de confianza.
