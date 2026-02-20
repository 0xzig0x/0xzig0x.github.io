---
title: "(RBCD)delegación restringida basada en recursos"
date: 2026-02-19
categories:
  - Hack The Box
  - Active Directory
tags:
  - RBCD
  - Resource-Based Constrained Delegation
  - Active Directory
  - Kerberos
  - S4U2Self
  - S4U2Proxy
  - DCSync
  - BloodHound
  - Impacket
  - Privilege Escalation
  - Domain Controller
  - HTB
  - Rebound
  - Red Team
  - Windows
layout: single
author_profile: true
show_date: true
toc: true
toc_sticky: true
toc_label: "Topics"
---


**¿Qué es?** Una funcion de AD que permite delegar permisos de forma controlada — en vez de darle acceso total a una cuenta, le decís específicamente a qué recursos puede acceder actuando en nombre de otros usuarios.

**¿Por qué importa para el ataque?** AD tiene un atributo llamado `msDS-AllowedToActOnBehalfOfOtherIdentity` en los objetos de equipo/servicio. Este atributo define **quién puede actuar en nombre de otros usuarios** hacia ese recurso.

**El punto clave:** Si un atacante tiene permisos para **escribir ese atributo** en un objeto (cosa que las cuentas máquina suelen tener sobre sí mismas u otros objetos), puede modificarlo para que **una cuenta que él controle** quede autorizada a impersonar a cualquier usuario del dominio hacia ese servicio — incluyendo administradores.

### RBCD – Flujo del Ataque

**1. Compromiso inicial** Primero necesito una cuenta con permisos de escritura sobre atributos de un objeto en AD. Puede ser una cuenta máquina, o cualquier cuenta con `GenericWrite`, `WriteDACL` o `AllExtendedRights` sobre el objeto objetivo. Sin esto no arranca nada — es el punto de entrada obligatorio.

**2. Modifico el atributo** Con esa cuenta escribo en `msDS-AllowedToActOnBehalfOfOtherIdentity` del objeto objetivo y meto mi cuenta controlada. Lo que hago acá es decirle a AD de forma legítima: _"esta cuenta mía tiene permiso para actuar en nombre de cualquier usuario hacia este objeto"_. Kerberos lo ve como configuración válida, no como ataque.

**3. Obtengo un TGT** Con mi cuenta controlada le pido un TGT al KDC. Este ticket es mi identidad dentro de Kerberos — sin él no puedo hacer los pasos siguientes. Es la base de toda la cadena.

**4. S4U2Self → me hago pasar por el usuario objetivo** Uso la extensión S4U2Self para pedirle al KDC un TGS como si yo fuera Administrator. El KDC me lo da porque mi cuenta está autorizada en el atributo que modifiqué. Todavía no accedo a nada — solo tengo un ticket que dice que soy Admin.

**5. S4U2Proxy → ticket válido hacia el servicio** Con ese ticket uso S4U2Proxy para convertirlo en un TGS válido hacia el servicio o recurso objetivo — CIFS, HTTP, LDAP, lo que sea. El KDC lo valida porque todo el flujo está dentro de la delegación que yo mismo configuré en el paso 2.

**6. Accedo como DA** Presento ese TGS y entro al recurso impersonando a Administrator. Para el sistema todo fue legítimo — Kerberos hizo su trabajo normal. Yo solo abusé de a quién le di permiso de delegar.


---

Voy a usar la máquina  Rebound de Hack The Box para demostrar el ataque en acción ya que en esta maquina se debe efectuar este ataque para la escalada de privilegios

### El punto de partida

Ya tengo credenciales de dos cuentas que necesito para esto. Arranco con `DELEGATOR$`, una cuenta máquina. Tenía el AD mapeado en BloodHound de recolecciones previas, así que fui directo a ver qué vectores me daba esta cuenta — y lo que encuentro es que tiene `AllowedToDelegate` hacia `DC01`. Traducido: esta cuenta tiene permiso para presentarse ante el DC como si fuera otro usuario, eso es exactamente lo que necesito para el ataque.

[![](/assets/images/web1.png)](/assets/images/web1.png)

### Primer intento — el error que me reorienta

Con esa info en mano intento impersonar a Administrator. Uso el SPN `HTTP/DC01.rebound.htb` y pongo `cifs` como alternativa por si el primero no jalaba, tiro el hash de `DELEGATOR$` y lanzo el ataque. Todo arranca — obtiene el TGT, declara que va a impersonar a Administrator, hace el proceso completo — y en el último paso truena con `KDC_ERR_BADOPTION`.

[![](/assets/images/web2.png)](/assets/images/web2.png)

El error me da dos posibles causas: o ese SPN no tiene permitido delegar desde `DELEGATOR$`, o el TGT que obtuve no es reenvíable. Esto segundo es lo crítico — para que el ataque cierre, Kerberos necesita que el TGT sea reenvíable porque es lo que le permite tomar ese ticket y convertirlo en uno válido hacia el servicio que quiero atacar. Si el TGT no tiene esa propiedad, Kerberos corta ahí y no hay nada que hacer con ese camino. Toca buscar otro ángulo.

### Configurando la Delegación — El Ataque Arranca

Acá es donde el RBCD empieza de verdad. Como mencioné, cuento con credenciales de dos cuentas: `DELEGATOR$` la cuenta máquina, y `ldap_monitor`.

Uso `impacket-rbcd` para configurar la delegación. Le paso el hash de `DELEGATOR$`, especifico que todo vaya por Kerberos con `-k`, le digo desde dónde quiero delegar con `-delegate-from ldap_monitor`, hacia dónde con `-delegate-to delegator$`, la acción es `write`, le paso la IP del DC y especifico que use LDAP.

[![](/assets/images/web3.png)](/assets/images/web3.png)

Con eso el ataque escribe el atributo `msDS-AllowedToActOnBehalfOfOtherIdentity` directamente en el objeto `DELEGATOR$`, apuntando a `ldap_monitor`. Traducido: le estoy diciendo al Active Directory  que `ldap_monitor` tiene permitido impersonar a cualquier usuario hacia `DELEGATOR$` mediante S4U2Proxy. Primer paso completado.


### Obteniendo los Tickets — La Cadena Final

**TGT para ldap_monitor**

Primero obtengo un TGT para `ldap_monitor` — este es mi punto de partida y es lo que me permite operar como esa cuenta dentro de Kerberos. Sin él no puedo arrancar nada de lo que sigue.

```bash
impacket-getTGT 'rebound.htb/ldap_monitor:1GR8t@$$4u'
[*] Saving ticket in ldap_monitor.ccache
```

**Primer ST — impersonando a DC01** 

Con el TGT de `ldap_monitor` solicito un ST usando el SPN `browser/dc01.rebound.htb` — ese SPN pertenece a `DELEGATOR$` y es exactamente donde configuré la delegación antes. La idea acá es abusar de esa delegación para que Kerberos me emita un ticket como si fuera `DC01$`. Uso el TGT de `ldap_monitor` por Kerberos sin password porque ya tengo el ticket cargado.

[![](/assets/images/web4.png)](/assets/images/web4.png)

```bash
KRB5CCNAME=ldap_monitor.ccache impacket-getST -spn "browser/dc01.rebound.htb" -impersonate "dc01\$" "rebound.htb/ldap_monitor" -k -no-pass
[*] Saving ticket in dc01\$@browser\_dc01.rebound.htb@REBOUND.HTB.ccache
```

Lo obtengo — pero este ticket todavía no me sirve para el DCSync. Está limitado al SPN de `DELEGATOR$`, y para poder volcar credenciales del DC necesito un ticket válido bajo el SPN del propio DC01. Este primer ST es el trampolín para llegar ahí.

**Segundo ST — el que cierra el juego**

Uso ese primer ST como ticket adicional con `-additional-ticket` y solicito un nuevo ST, esta vez bajo el SPN `http/dc01.rebound.htb`, impersonando a `DC01$` y autenticándome con las credenciales de `DELEGATOR$` por Kerberos. Lo que hago acá es encadenar los dos tickets — el primero me acredita como `DC01$`, el segundo convierte eso en acceso real al DC. Este es el ticket final.

[![](/assets/images/web5.png)](/assets/images/web5.png)

Con ese ST ejecuto un DCSync con `secretsdump` apuntando directo al hash del Administrator — y lo obtengo limpio. El DCSync funciona porque estoy operando como `DC01$`, una cuenta máquina del dominio que tiene permisos de replicación por defecto — exactamente lo que necesita el ataque para volcar credenciales sin tocar el DC directamente.

**Validación y acceso total** 

Compruebo el hash con `netexec` por SMB y este es válido. 

[![](/assets/images/web6.png)](/assets/images/web6.png)

Y así, abusando de la lógica legítima de Kerberos y sin explotar ninguna vulnerabilidad clásica, logré comprometer completamente este entorno de Active Directory.
