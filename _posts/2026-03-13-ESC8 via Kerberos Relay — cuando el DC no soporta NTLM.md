---
title: "ESC8 via Kerberos Relay — cuando el DC no soporta NTLM"
date: 2026-03-13
categories:
  - Hack The Box
  - Active Directory
tags:
  - ESC8
  - ADCS
  - KerberosRelay
  - ActiveDirectory
  - NTLM-Disabled
  - CertificateAbuse
  - CredMarshalTargetInfo
  - PetitPotam
  - DCSync
  - Certipy
  - krbrelayx
  - bloodyAD
  - Windows
  - Privesc
layout: single
author_profile: true
show_date: true
toc: true
toc_sticky: true
toc_label: "Topics"
---

## Contexto

Estaba atacando `cicada.vl`, un dominio Windows donde NTLM estaba completamente deshabilitado en el DC. El objetivo era comprometer el dominio partiendo de credenciales de un usuario sin privilegios especiales: `Rosie.Powell`.

Al enumerar con `certipy-ad`, identifiqué que la Certification Authority del dominio (`cicada-DC-JPQ225-CA`) tenía habilitado **Web Enrollment sobre HTTP** — eso es ESC8.

[![](/assets/images/193.png)](/assets/images/193.png)

El problema: ESC8 normalmente se explota haciendo NTLM relay hacia el endpoint HTTP de ADCS (`/certsrv/certfnsh.asp`). Pero aquí NTLM estaba deshabilitado, así que el relay clásico con `ntlmrelayx` no era una opción. La única salida era hacer **Kerberos relay**.

---

## Qué es ESC8

ESC8 es una misconfiguration de ADCS donde el endpoint de Web Enrollment (`http://<CA>/certsrv/`) no requiere HTTPS ni firma. Esto permite que un atacante que reciba una autenticación de la cuenta de máquina del DC pueda relayarla hacia ese endpoint y obtener un certificado como `DC$`.

Con ese certificado puedo:

1. Autenticarme como `DC$` via PKINIT (Kerberos + certificado)
2. Extraer el hash NT del DC
3. Hacer DCSync y dumpear todos los hashes del dominio

El flujo completo:

```
Coerce DC → autentica hacia mí → relay a /certsrv/ → certificado DC$ → TGT DC$ → DCSync → hash Administrator
```

---

## Por qué no funciona el relay NTLM clásico

En un entorno normal haría esto:

```bash
ntlmrelayx.py -t http://<CA>/certsrv/certfnsh.asp --adcs --template DomainController
petitpotam.py <mi_ip> <dc>
```

Pero aquí el DC tiene NTLM deshabilitado (`NTLM:False` en la salida de nxc). Cuando el DC intenta autenticarse a mi servidor SMB, no negocia NTLM, sino que va directo a **Kerberos**. El relay NTLM nunca llega a ocurrir.

---

## La solución: Kerberos Relay

Kerberos relay se consideraba imposible durante mucho tiempo porque el `AP_REQ` (el mensaje de autenticación Kerberos) va dirigido a un **SPN específico**. Si el DC pide un ticket para `cifs/miservidor`, ese ticket solo vale para ese servicio. No puedo relayarlo a `http://ca/certsrv/` porque el SPN no coincide y el servidor lo rechazará.

El truco para que funcione es forzar al DC a generar un ticket ya dirigido al servicio correcto. Eso se consigue manipulando cómo Windows construye el SPN.

---

## CredMarshalTargetInfo — el corazón del ataque

Cuando Windows se conecta por SMB a un servidor, internamente llama a `SecMakeSPNEx2` para construir el SPN. Esta función llama a `CredMarshalTargetInfo`, que toma información del destino, la **serializa en Base64** y la **añade al final del nombre del host**.

El resultado tiene este aspecto:

```
cifs/DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA
```

Cuando el cliente ve un hostname que termina con esa cadena, llama a `CredUnmarshalTargetInfo`, extrae la estructura serializada del nombre, y usa solo la parte del nombre real (`DC-JPQ225`) como SPN para pedir el ticket Kerberos.

**El resultado**: el DC pide un ticket para `cifs/DC-JPQ225` (la máquina real), pero se conecta físicamente al host `DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA` — que soy yo.

Yo recibo un `AP_REQ` con la identidad de `DC-JPQ225$` correctamente embebida, y lo puedo relaizar a cualquier servicio que acepte Kerberos sin firma, como el endpoint HTTP de ADCS.

---

## De dónde sale el sufijo `1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA`

Esta fue la pregunta clave. El sufijo es la **serialización mínima** de una estructura `CREDENTIAL_TARGET_INFORMATIONW` vacía.

Se puede generar con Frida hookando `CredMarshalTargetInfo` en `lsass.exe` con una estructura vacía:

```javascript
// Frida hook → CredMarshalTargetInfo con CREDENTIAL_TARGET_INFORMATIONW vacía
// Output: 1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA
```

Este valor es **siempre el mismo** porque la estructura está vacía. Es un valor estático que puedo memorizar o copiar directamente.

El formato completo del DNS record es:

```
<nombre_real_del_host>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA
```

Para mi caso:

```
DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA
```

---

## El ataque paso a paso

### Prerequisitos

- Usuario de dominio con permisos para crear DNS records (cualquier usuario autenticado puede hacerlo por defecto en AD)
- ADCS con Web Enrollment habilitado sobre HTTP (ESC8)
- Capacidad de coerce (PetitPotam, DFSCoerce, PrinterBug, etc.)


### Paso 1 — Crear el DNS record malicioso

Registro un DNS record con el nombre especial que hace que el DC genere el ticket con la identidad correcta, apuntando a mi máquina:

[![](/assets/images/194.png)](/assets/images/194.png)

### Paso 2 — Levantar el relay

[![](/assets/images/195.png)](/assets/images/195.png)

Certipy escucha en `0.0.0.0:445` esperando recibir el `AP_REQ` del DC.

### Paso 3 — Coerce

Fuerzo al DC a autenticarse hacia mi DNS record malicioso usando PetitPotam:

[![](/assets/images/196.png)](/assets/images/196.png)

El flujo interno en este momento:

1. El DC recibe la llamada EfsRpcAddUsersToFile
2. Intenta autenticarse al hostname `DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA`
3. Windows llama a `CredUnmarshalTargetInfo`, extrae la estructura, determina que el SPN real es `cifs/DC-JPQ225`
4. El DC pide un TGS para `cifs/DC-JPQ225` al KDC
5. Envía el `AP_REQ` a mi IP (10.10.15.15) porque el DNS record apunta ahí
6. Certipy recibe el `AP_REQ` con la identidad `DC-JPQ225$` y lo relaiza al endpoint HTTP de ADCS

### Paso 4 — Obtener el certificado

Certipy recibe la conexión, relaiza el `AP_REQ` a `/certsrv/certfnsh.asp`, y solicita un certificado usando la template `DomainController` en nombre de `DC-JPQ225$`:

[![](/assets/images/197.png)](/assets/images/197.png)

### Paso 5 — Autenticar con el certificado (PKINIT)

[![](/assets/images/198.png)](/assets/images/198.png)

### Paso 6 — DCSync


[![](/assets/images/199.png)](/assets/images/199.png)

---

## Diagrama del ataque

```
Atacante                    DC (cicada.vl)              ADCS (certsrv)
   |                             |                           |
   |--[1] Crear DNS record------>|                           |
   |    DC-JPQ225<sufijo> → mi IP|                           |
   |                             |                           |
   |--[2] Levantar relay en :445 |                           |
   |                             |                           |
   |--[3] PetitPotam coerce----->|                           |
   |                             |                           |
   |         [4] DC pide TGS para cifs/DC-JPQ225             |
   |         [5] DC envía AP_REQ a mi IP (DNS record)        |
   |<--[5] AP_REQ (DC-JPQ225$)---|                           |
   |                             |                           |
   |--[6] Relay AP_REQ-------------------------------------->|
   |                             |      [7] Certificado DC$  |
   |<-----------------------------------------------[7]------|
   |                             |                           |
   |--[8] PKINIT con dc-jpq225.pfx→ TGT DC$                  |
   |--[9] DCSync → hashes del dominio                        |
```

---

## Notas importantes

**Por qué falla certipy v5 a veces con este ataque:** Certipy v5 tiene un bug donde si el `AP_REQ` llega sin el nombre de usuario correctamente parseado (username vacío), falla con `Attribute's length must be >= 1 and <= 64, but it was 0`. Esto ocurre cuando el DNS record NO tiene el sufijo `CredMarshalTargetInfo` correcto — el ticket llega sin la identidad de `DC-JPQ225$` embebida.

**Nombre del DNS record sin el sufijo especial:** Si registro simplemente `DC-JPQ225ATTACKER`, el DC genera un ticket para `cifs/DC-JPQ225ATTACKER` (el nombre tal cual), no para `cifs/DC-JPQ225`. Certipy recibe el `AP_REQ` pero el campo de identidad llega vacío porque no hay una cuenta de máquina llamada `DC-JPQ225ATTACKER` en el dominio.

**Sincronización de tiempo:** Kerberos requiere que el reloj del atacante esté sincronizado con el DC (máximo 5 minutos de diferencia). Si hay problemas de autenticación, ejecutar `sudo ntpdate <DC_IP>` suele solucionarlo.

**El DNS record persiste tras el reset de la máquina:** Si la máquina HTB se resetea, el DNS record se pierde junto con toda la configuración. Hay que volver a crearlo con bloodyAD o dnstool.py antes de repetir el ataque.

---

## Referencias

- [Synacktiv — Relaying Kerberos over SMB using krbrelayx](https://www.synacktiv.com/publications/relaying-kerberos-over-smb-using-krbrelayx)
- [James Forshaw — Using Kerberos for Authentication Relay Attacks (Project Zero)](https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html)
- [Dirk-jan Mollema — Relaying Kerberos over DNS with krbrelayx and mitm6](https://dirkjanm.io/relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/)
- [KrbRelay-SMBServer by @decoder_it](https://github.com/decoder-it/KrbRelay-SMBServer)
