# Sec-Ops

CONTINUA EN DESARROLLO .....

![image](https://user-images.githubusercontent.com/114626248/234671924-25a0bd03-3506-4344-a37b-ed31b58981a8.png)

# ¿Qué es?

Sec-Ops, la herramienta ideal para detectar ataques básicos en un archivo PCAP, acelerando el proceso de análisis y llegar a una conclusión en segundos, así mismo, Sec-Ops fue desarrollado para automatizar procesos de ataques a redes LAN, Sec-Ops fue creado con el fin de mezclar Red Team y Blue Team, siendo diseñado para tener una funcionalidad amigable para los usuarios.

# Un vistazo a la herramienta

Al ejecutar Sec-Ops, la herramienta primero que nada detectará si en tu sistema se encuentran instaladas las herramientas necesarias para que pueda funcionar, siendo estas Tshark, Scapy y Yersinia.

Al no contar con alguna(s) herramientas instaladas, Sec-Ops en automático comenzara la instalación de las mismas.

![image](https://user-images.githubusercontent.com/114626248/234672194-72a9a3c3-0f0f-4959-b9dd-e3817fc0158c.png)

En este ejemplo, se muestra que el usuario no tiene instaladas las herramientas Tshark y Yersinia, por lo que Sec-Ops detectará esto y comenzara la instalación de las mismas.

![image](https://user-images.githubusercontent.com/114626248/234672337-8e719d9e-b4da-4b58-897d-0dcec274cc37.png)

Una vez completada la instalación, Sec-Ops se volverá a ejecutar, detectando que las herramientas instaladas anteriormente efectivamente se encuentran en tu sistema operativo, por lo que Sec-Ops ya puede ejecutarse correctamente.

![image](https://user-images.githubusercontent.com/114626248/234672472-872603fd-fdc6-411a-887b-b9ab644cd1b6.png)

## Navegación por la herramienta

Como ya a sido mencionado anteriormente, Sec-Ops fué desarrollado para tener un uso amigable con el usuario. Observando la herramienta, se cuenta con un menú con diferentes opciones, tendrás que seleccionar una opción válida de acuerdo a la acción que deseas ejecutar.

![image](https://user-images.githubusercontent.com/114626248/234672657-76deb035-88b7-4b6d-8ceb-0713d85f1eb9.png)

En el siguiente ejemplo, se muestra como se a seleccionado la opcion 1, correspondiente a la funcionalidad de "PCAP analyze", para esta opción, están disponibles mas subopciones, por lo que se deberá seleccionar una. 

![image](https://user-images.githubusercontent.com/114626248/234672931-d3d7c7c9-a323-44ac-82b6-29d32e15554f.png)

![image](https://user-images.githubusercontent.com/114626248/234673161-b6e2637f-9e6e-4dc0-9692-54bd45aeb1f2.png)

Así mismo, en el prompt diseñado, se observa que cada vez que se selecciona una opción, muestra una navegación por la herramienta, siendo útil para un usuario nuevo, sirviendo como una pequeña guía.

![image](https://user-images.githubusercontent.com/114626248/234673269-ed24387f-22a6-43e9-8ca8-3c261bfd392c.png)

# Uso de la herramienta

Ahora, pasaremos a describir las funciones de la herramienta.

## Opción PCAP Analyzer

La opción "PCAP Analyzer" fue implementada con el principal proposito de detectar ataques básicos de un PCAP, filtrando los protocolos relevantes en cada ataque, y examinando cada paquete, buscando patrones que identifican si un ataque fue realizado.

Actualmente, Sec-Ops tiene disponibles [n] ataques para detectar, los cuales se listan en el menu de la opcion "PCAP Analyzer":

![image](https://user-images.githubusercontent.com/114626248/234681998-dc35f4c9-c9cd-4d2c-9593-9f85db2ced0c.png)

Supongamos que un analista en seguridad informática quiere detectar rapidamente si un ataque "ARP Spoofing" fue producido, por lo que deberá seleccionar la opción "6" del menú mencionado anteriormente.

![image](https://user-images.githubusercontent.com/114626248/234682563-419b0459-4b60-4198-b9d0-8f01aa8db1c7.png)

Sec-Ops le pedirá al analista en seguridad informática ingresar un archivo PCAP a analizar, por lo que DEBERÁ ingresar la ruta donde se encuentra dicho PCAP.

![image](https://user-images.githubusercontent.com/114626248/234682950-05946070-4907-4a6c-a389-fd21df8f73e6.png)

Sec-Ops validará si la ruta especificada existe, si esta es correcta, Sec-Ops iniciará el proceso de extracción de datos relevantes del archivo PCAP

![image](https://user-images.githubusercontent.com/114626248/234683244-f32a89a6-45f2-4e66-98a5-e68c6252a6dc.png)

En el caso de que se especifique una ruta incorrecta, Sec-Ops detectará que hay un error, por lo que volverá a solicitar la especificación de la ruta del archivo PCAP a analizar.

![image](https://user-images.githubusercontent.com/114626248/234683610-52ffabad-42a7-4e18-81aa-28316870d452.png)












