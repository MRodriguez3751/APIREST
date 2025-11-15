# Como levantar la api

## 1. Ejecutar comando dentro de la carpeta donde clonaste el repositorio
```ps
py ./run.py
```
## 2. Acceder a la URL
```http
[localhost](http://127.0.0.1:8000)
```
## 3. Hacer llamado al endpoint /Health para verificar conexion con la base de datos.
```http
[localhost](http://127.0.0.1:8000/health)
```
## 4. Si escribiste bien la URL, tienes dos respuestas posibles.
### Conexión correcta
```json
{
  "status": "healthy",
  "database": "connected"
}
```
### Conexión incorrecta
```json
{
  "status": "unhealthy",
  "database": "disconnected",
  "error": "Error de algo"
}
```
Para este último caso, probablemente sean las variables de entorno mal configuradas.
