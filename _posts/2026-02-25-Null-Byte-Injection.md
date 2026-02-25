---
title: "Null Byte Injection"
date: 2026-02-25
categories:
  - Hack The Box
  - Windows
tags:
  - Web Exploitation
  - Null Byte Injection
  - File Upload Bypass
  - PHP
  - Reverse Shell
  - Zip
layout: single
author_profile: true
show_date: true
toc: true
---

El Null Byte Injection es una vulnerabilidad compleja y bastante peligrosa cuando un sitio es vulnerable. Ocurre cuando un atacante inserta o modifica un byte nulo — `%00` en URL, `\0` en código — dentro de la entrada del cliente para manipular cómo el backend procesa esa data.

El problema de fondo es una inconsistencia entre capas. Lenguajes de bajo nivel como C interpretan el `\0` como el fin de un string, literalmente dejan de leer ahí. Entonces cuando una aplicación moderna en PHP o Python pasa esos datos hacia una función de bajo nivel, cada capa ve un string distinto con los mismos datos. El validador sigue leyendo normal, la función de abajo corta en el null byte — y en esa brecha el atacante opera.

No está rompiendo nada, está abusando de esa inconsistencia para que el sistema haga dos cosas al mismo tiempo sin darse cuenta. El validador aprueba, el ejecutor hace algo completamente distinto.

Si el sitio no sanitiza bien esos bytes nulos, el atacante puede bypassear controles de seguridad, manipular rutas de archivos, explotar funciones internas o colar archivos maliciosos que el backend termina ejecutando sin que ningún filtro lo haya detectado.

## Explotación — Certificate HTB

Para demostrar esto en la práctica, usé la máquina Certificate de HackTheBox.

El sitio tiene un panel de subida de archivos que solo acepta documentos comprimidos en zip — pdf, docx, pptx, xlsx. Además está corriendo en PHP, lo que significa que si logro colar un archivo `.php` y apuntar a él, el servidor lo va a interpretar y ejecutar.

[![](/assets/images/web7.png)](/assets/images/web7.png)

Ahí es donde entra el Null Byte Injection.

## Creando el archivo malicioso

Creo mi archivo en PHP, un archivo malicioso que al ser interpretado por el servidor le dice que se conecte de vuelta a mi máquina en el puerto 443 — eso es una reverse shell, la conexión sale del servidor hacia mí, lo que me permite evadir firewalls que bloquean conexiones entrantes.

Pero acá viene el problema — si subo el archivo como `evil.php` dentro del zip, el validador lo va a rechazar de inmediato porque no es un formato permitido. Entonces lo que hago es nombrar mi archivo `evil.php..pdf`. Le coloco dos puntos antes de `pdf` y no uno solo, y eso es intencional por una razón muy específica.

[![](/assets/images/web8.png)](/assets/images/web8.png)

Necesito que al momento de inyectar el null byte, el nombre del archivo quede limpio del lado del sistema. Si solo pusiera `evil.php.pdf` y reemplazara ese único punto por `\0`, quedaría `evil.php\0pdf` — sin punto antes de la extensión, un nombre roto que el sistema no va a manejar bien. En cambio con `evil.php..pdf`, cuando reemplazo el primer punto por `\0` queda `evil.php\0.pdf` — uno de los puntos lo sacrifico como null byte y el otro se queda cumpliendo su función natural, ser el punto de la extensión `.pdf`. El validador lee el string completo y ve `.pdf` , todo tranquilo.

## Modificando el ZIP en hexadecimal

Ahora abro ese zip con hexedit, que me permite ver y editar la data cruda del archivo en hexadecimal. Dentro del zip el nombre del archivo está almacenado en dos lugares — en el header local y en el central directory, que es básicamente el índice interno del zip que le dice al sistema qué archivos contiene y dónde están. En ambos lugares busco el nombre `evil.php..pdf` y localizo los dos puntos representados en hex como `2E 2E`. Reemplazo el primer `2E` por `00` en las dos ocurrencias. Si no lo hago en ambas, el zip queda inconsistente y puede fallar al extraerse.

[![](/assets/images/web9.png)](/assets/images/web9.png)


[![](/assets/images/web10.png)](/assets/images/web10.png)


[![](/assets/images/web11.png)](/assets/images/web11.png)


[![](/assets/images/web12.png)](/assets/images/web12.png)

## Subiendo el archivo y obteniendo la shell

Ahora el zip contiene `evil.php\0.pdf`. Subo el zip, el validador ve `.pdf` y lo aprueba sin levantar ninguna alerta. 

[![](/assets/images/web13.png)](/assets/images/web13.png)

Pero cuando el backend extrae el archivo y lo pasa al sistema de archivos — que por debajo usa funciones escritas en C — ese `\0` es interpretado como fin de cadena y el archivo queda guardado físicamente como `evil.php`. Esa es exactamente la inconsistencia que explotamos — el validador y el sistema de archivos leyeron los mismos bytes y llegaron a conclusiones completamente distintas.

Voy a la URL donde quedó almacenado el archivo, apunto directo a `evil.php`, le hago un curl y el servidor lo encuentra, lo interpreta como PHP y ejecuta el código malicioso. En mi listener con netcat recibo la conexión — shell dentro del servidor, corriendo como el usuario de XAMPP.

[![](/assets/images/web14.png)](/assets/images/web14.png)


[![](/assets/images/web15.png)](/assets/images/web15.png)

## Conclusión

Y así, mediante una mala configuración del backend que no sanitiza correctamente los bytes nulos en los nombres de archivo, logré vulnerar el sitio — pasando de simplemente subir un documento a tener ejecución remota de código en el servidor.

