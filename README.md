# Servidor - Gestión de Blog

## Requisitos
- Python 3.8+
- Entorno virtual recomendado

## Instalación
1. Crear y activar entorno virtual:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
2. Instalar dependencias:
   ```bash
   pip install -r requirements.txt
   ```

## Ejecución
1. Ejecuta el servidor:
   ```bash
   python3 main.py
   ```
2. El servidor estará disponible en `http://<IP_DEL_SERVIDOR>:8000`

## Notas
- El usuario admin se crea automáticamente al iniciar el servidor.
- Cambia la IP en el cliente para conectarse desde otra máquina.
- el usuario del administrador  inicial es: "admin" y la contraseña: "Admin123!"