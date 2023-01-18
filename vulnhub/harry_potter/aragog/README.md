# Harry Potter - Aragog

[Link to VulnHub](https://www.vulnhub.com/entry/harrypotter-aragog-102,688/)

Aragor es la primera de tres CTFs de la serie de Harry Potter en la cual tienes que encontrar 2 horcruxes (hay un total de 8 horcruxes escondidos a lo largo de las máquinas de la serie) para poder derrotar a Voldemort.

## Reconocimiento

### Descubrimiento de puertos

Inicialmente tenemos que detectar los todos los puertos abiertos de manera rápida. Para ello hacemos un escaneo de puertos completo (`-p-`) filtrando por los puertos abiertos (`--open`) deshabilitando la resolución DNS (`-n`) y el descubrimiento de hosts (`-Pn`):

```bash
nmap -p- --open -Pn -n -v 10.0.0.100
```

Resultado:

```text
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-18 18:27 CET
Initiating Connect Scan at 18:27
Scanning 10.0.0.100 [65535 ports]
Discovered open port 22/tcp on 10.0.0.100
Discovered open port 80/tcp on 10.0.0.100
Completed Connect Scan at 18:28, 7.03s elapsed (65535 total ports)
Nmap scan report for 10.0.0.100
Host is up (0.0037s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 7.08 seconds
```

Con ese escaneo podemos concluir que tenemos abiertos los puertos 22 (SSH) y 80 (HTTP). Ahora que sabemos qué puertos están abiertos realizamos un escaneo en profundidad para saber qué servicios y versión de los mismos están expuestos en esos puertos (`-sCV`):

```bash
nmap -p22,80 -sCV -Pn -n 10.0.0.100
```

Resultado:

```text
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-18 18:32 CET
Nmap scan report for 10.0.0.100
Host is up (0.0090s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 48:df:48:37:25:94:c4:74:6b:2c:62:73:bf:b4:9f:a9 (RSA)
|   256 1e:34:18:17:5e:17:95:8f:70:2f:80:a6:d5:b4:17:3e (ECDSA)
|_  256 3e:79:5f:55:55:3b:12:75:96:b4:3e:e3:83:7a:54:94 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.04 seconds
```

Mediante esta consulta podemos concluir las versiones y servicios que se están exponiendo en ambos puertos:

* `22/tcp`: **SSH** - OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
* `80/tcp`: **HTTP** - Apache httpd 2.4.38 ((Debian))
