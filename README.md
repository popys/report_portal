# Report Portal (Flask)

Un portal sencillo para que tu equipo envíe reportes con usuario/contraseña y adjuntos. Incluye:

- Registro de usuarios (por un administrador)
- Inicio de sesión y cierre de sesión
- Formulario de reporte con título, descripción y archivo adjunto (opcional)
- Panel de administrador para ver todos los reportes y crear usuarios
- Los usuarios pueden ver sólo sus propios reportes
- SQLite como base de datos; subida de archivos a `/uploads`

## Requisitos

- Python 3.10+ recomendado
- (Opcional) Virtualenv

## Instalación

```bash
python -m venv venv
# Windows: venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate
pip install -r requirements.txt
```

## Inicialización de la BD y usuario admin

```bash
python app.py init-db
python app.py create-admin --username admin --password "TuPasswordFuerte123" --full-name "Administrador"
```

> Puedes crear más usuarios desde el panel de admin (arriba a la derecha en el dashboard).

## Ejecutar

```bash
python app.py run
```

La app corre por defecto en http://127.0.0.1:5000

## Configuración

Variables de entorno soportadas (opcionales):

- `SECRET_KEY`: clave de sesión Flask (si no la defines, se genera una temporal).
- `UPLOAD_MAX_MB`: tamaño máximo de archivo en MB (por defecto 25).
- `ALLOWED_EXTS`: extensiones permitidas separadas por comas (por defecto: pdf,doc,docx,xls,xlsx,png,jpg,jpeg,txt,csv).

Ejemplo (Linux/macOS):

```bash
export SECRET_KEY="cambia-esta-clave"
export UPLOAD_MAX_MB=50
export ALLOWED_EXTS="pdf,docx,xlsx,png,jpg"
python app.py run
```

## Notas de seguridad

- Este proyecto es base y didáctico. Para producción, añade:
  - HTTPS detrás de un proxy (Nginx/Traefik/Caddy)
  - CSRF protection (Flask-WTF)
  - Reglas de tamaño y antivirus de archivos
  - Políticas de contraseñas y recuperación de contraseña
  - Copias de seguridad de la BD
