# Sec-Ops

CONTINUA EN DESARROLLO .....

![image](https://github.com/ferhs343/Sec-Ops/assets/114626248/ef2724de-86c8-4f4c-8a63-362a4a18ea20)

# ¿Qué es?

Sec-Ops, una herramienta diseñada para especialistas en seguridad defensiva, ofreciendo múltiples funcionalidades como la detección de ataques fundamentales, detección de reconocimiento a redes, así como la funcionalidad de inteligencia de amenazas para investigar IP/Dominios sospechosos, automatizando en gran parte el proceso de análisis de un incidente de seguridad.

# Un vistazo a la herramienta

Al ejecutar Sec-Ops, la herramienta primero que nada detectará si en tu sistema se encuentran instaladas las herramientas necesarias para que pueda funcionar, siendo estas Tshark, wget, curl y jq.

Al no contar con alguna(s) herramientas instaladas, Sec-Ops en automático comenzara la instalación de las mismas.

![image](https://github.com/ferhs343/Sec-Ops/assets/114626248/68e500fb-c684-4b73-8143-d12897cd3930)

En este ejemplo, se muestra que el usuario no tiene instaladas las herramientas curl y jq, por lo que Sec-Ops detectará esto y comenzara la instalación de las mismas.

![image](https://github.com/ferhs343/Sec-Ops/assets/114626248/d6399046-5400-4711-8da1-33a7842963ab)

Una vez completada la instalación, Sec-Ops se volverá a ejecutar, detectando que las herramientas instaladas anteriormente efectivamente se encuentran en tu sistema operativo, por lo que Sec-Ops ya puede ejecutarse correctamente.

![image](https://github.com/ferhs343/Sec-Ops/assets/114626248/904a053c-aa8b-4d82-b4fd-371542dcc459)

## Navegación por la herramienta

Como ya a sido mencionado anteriormente, Sec-Ops fué desarrollado para tener un uso amigable con el usuario. Observando la herramienta, se cuenta con un menú con diferentes opciones, tendrás que seleccionar una opción válida de acuerdo a la acción que deseas ejecutar.

![image](https://github.com/ferhs343/Sec-Ops/assets/114626248/db12746f-6852-49fb-ad85-b802700aebf8)

En el siguiente ejemplo, se muestra como se a seleccionado la opcion 1, correspondiente a la funcionalidad de "Attack detection", para esta opción, están disponibles mas subopciones, por lo que se deberá seleccionar una. 

![image](https://github.com/ferhs343/Sec-Ops/assets/114626248/c488b688-e003-46d0-bfbf-cf2e89d6b92a)

![image](https://github.com/ferhs343/Sec-Ops/assets/114626248/62b52094-031c-4cc2-8ad1-9dbf689e2fdf)


Así mismo, en el prompt diseñado, se observa que cada vez que se selecciona una opción, muestra una navegación por la herramienta, siendo útil para un usuario nuevo, sirviendo como una pequeña guía.

![image](https://github.com/ferhs343/Sec-Ops/assets/114626248/d95c2537-c7ac-45fa-848a-2067ff07df3e)


# Uso de la herramienta

Ahora, pasaremos a describir el uso de las funciones de la herramienta.

## Opción Attack detection

La opción "Attack detection" está pensada con el principal proposito de detectar ataques básicos de un PCAP, mediante la detección de patrones maliciosos, examinando diferentes paquetes de una transmisión.

Actualmente, Sec-Ops tiene disponibles [n] ataques para detectar, las cuales se listan a continuación:

* Denegación de servicio
  * TCP SYN Flood
  * TCP RST Flood
  * UDP Flood
  * ICMP Flood
  * Técnica Slowloris
  * Amplificación DNS
* Inyección SQL
* Fuerza bruta
  * SSH
  * FTP
  * RDP
  * MYSQL
* Tunelización DNS
* Inyecciones de código
* Ataques a redes locales
  * Vlan hopping
  * ARP spoofing
  * DHCP spoofing
  * Ataque a STP
  * Ataque a HSRP
  * Envenenamiento
















