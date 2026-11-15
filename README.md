# Meross Inspector 0.1 — Android 15

Proyecto Android Java nativo sin dependencias de terceros. `compileSdk` y `targetSdk` 35, mínimo Android 8.

## Funciones implementadas
- Diagnóstico por IP mediante `Appliance.System.All` y tiempo de respuesta.
- Encendido/apagado mediante `Appliance.Control.Toggle`.
- Potencia, tensión e intensidad mediante `Appliance.Control.Electricity`.
- Firmas locales MD5 según protocolo Meross documentado por la comunidad.

## Limitaciones importantes
- **No hay autodetección todavía**: la IP se introduce manualmente.
- Requiere la **device key local** del enchufe, no la contraseña de Meross. No se incluye extracción de credenciales.
- Compatible solo con dispositivos que acepten la API HTTP local y esos namespaces. ToggleX y otras variantes quedan pendientes.
- El control no se ha probado con un enchufe físico y el APK no se ha compilado en este entorno.
- No se almacenan IP ni claves. HTTP local no cifra el tráfico: utilizar únicamente en una red WiFi confiable.
- No muestra kWh acumulados aún. El modelo debe soportar monitorización eléctrica para mostrar W/V/A.

## Compilar
1. Abrir la carpeta `MerossInspector` en Android Studio.
2. Instalar SDK Android 35 y sincronizar Gradle (AGP 8.7.3, JDK 17).
3. Ejecutar **Build > Build APK(s)**.
4. El APK de depuración estará en `app/build/outputs/apk/debug/app-debug.apk`.

## Próximas mejoras
Autodetección con consentimiento, configuración segura de claves, ToggleX, ConsumptionX, diagnóstico detallado y pruebas con modelos concretos.
