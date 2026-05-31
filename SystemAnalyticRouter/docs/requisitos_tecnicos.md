# Requisitos tecnicos

## Minimos

- Python 3.10 o superior.
- Windows, Linux o macOS.
- Permiso para monitorear la computadora, interfaz o router objetivo.
- Dependencias de `requirements.txt`.

## Para trafico completo del router

El sistema operativo normalmente solo ve el trafico de esta computadora. Para ver todo el router necesitas una fuente autorizada:

- Port mirroring en switch/router.
- Logs del router enviados por syslog.
- SNMP habilitado en el router.
- API administrativa del router.
- Ejecutar el agente en un gateway propio.

## Seguridad

- No guardes credenciales en `configs/api_keys.yml`.
- Usa variables de entorno para tokens.
- Ejecuta captura de paquetes solo en redes propias o con permiso explicito.
- Limita el almacenamiento de datos sensibles y rota la base SQLite si crece demasiado.
- No intentes desencriptar trafico de terceros. Para HTTP/HTTPS usa un proxy autorizado, certificados instalados con consentimiento o logs generados por tus propias aplicaciones.
