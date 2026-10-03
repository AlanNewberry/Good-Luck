# Good-Luck — Escáner de Puertos

> Escáner de puertos rápido, limpio y sin basura. TCP Connect, SYN stealth y UDP en un solo script.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)
![License](https://img.shields.io/badge/Licencia-MIT-green)
![Platform](https://img.shields.io/badge/Plataforma-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)

---

## Descripción

Escribí **Good-Luck** porque quería un escáner de puertos liviano, directo y sin dependencias innecesarias. Algo que pueda correr rápido desde la terminal, con salida estilo nmap, detección de servicios y exportación a JSON — todo en un único archivo Python.

Good-Luck soporta tres métodos de escaneo (TCP connect, SYN half-open y UDP), captura banners, identifica servicios y te muestra los resultados en una tabla limpia. Si necesitás algo más pesado, usá nmap. Si querés algo rápido y portable, Good-Luck es para vos.

---

## Características

- **Tres métodos de escaneo**: TCP connect, SYN stealth y UDP
- **Banner grabbing**: lectura directa del socket + fallback con HTTP HEAD
- **Detección de servicios**: vía `socket.getservbyport()` y análisis de banners
- **Escaneo multihilo**: `ThreadPoolExecutor` con cantidad de hilos configurable
- **Salida estilo nmap**: tabla con columnas PORT, STATE, SERVICE, VERSION
- **Exportación a JSON**: guardá los resultados con `-o resultado.json`
- **Contador de progreso**: sabé en todo momento cuántos puertos van
- **Sintaxis flexible de puertos**: rangos (`1-1024`), listas (`22,80,443`) y combinaciones (`22,80,100-200`)
- **Tests incluidos**: `test_goodluck.py` para verificar que todo funcione

---

## Métodos de escaneo

### TCP Connect (por defecto)

Realiza el handshake TCP completo (SYN → SYN-ACK → ACK). Es el método más confiable y no requiere privilegios de root. La contra es que es más ruidoso — el sistema operativo del objetivo registra la conexión completa.

```bash
python3 goodluck.py -t 192.168.1.1 -p 1-1024
```

### SYN Scan (stealth)

Envía solo el paquete SYN y analiza la respuesta sin completar el handshake. Es más sigiloso porque la conexión nunca se establece por completo. **Requiere privilegios de root** y tener **Scapy** instalado.

```bash
sudo python3 goodluck.py -t 192.168.1.1 -p 1-1024 --syn
```

### UDP Scan

Envía datagramas UDP a los puertos especificados. Los puertos que no responden se reportan como `open|filtered`, ya que UDP no tiene mecanismo de confirmación y es imposible distinguir entre un puerto abierto que no responde y uno filtrado por un firewall.

```bash
sudo python3 goodluck.py -t 192.168.1.1 -p 53,67,68,123,161 --udp
```

---

## Requisitos

- **Python 3.9** o superior
- **Scapy** — solo si vas a usar el escaneo SYN (`--syn`)
- Privilegios de **root/sudo** para escaneos SYN y UDP

### Dependencias

```
scapy   # solo para escaneo SYN
```

---

## Instalación

```bash
# Cloná el repositorio
git clone https://github.com/44Viciius/Good-Luck.git
cd Good-Luck

# Instalá las dependencias (opcional, solo para SYN scan)
pip install -r requirements.txt
```

No hace falta instalar nada más para el escaneo TCP connect básico.

---

## Uso

### Escaneo básico de puertos comunes

```bash
python3 goodluck.py -t 192.168.1.1 -p 22,80,443
```

### Escaneo de un rango completo

```bash
python3 goodluck.py -t 192.168.1.1 -p 1-1024
```

### Escaneo con rangos mixtos

```bash
python3 goodluck.py -t 10.0.0.5 -p 22,80,443,8000-8100
```

### Escaneo SYN stealth (requiere root)

```bash
sudo python3 goodluck.py -t 192.168.1.1 -p 1-1024 --syn
```

### Escaneo UDP

```bash
sudo python3 goodluck.py -t 192.168.1.1 -p 53,161,500 --udp
```

### Exportar resultados a JSON

```bash
python3 goodluck.py -t 192.168.1.1 -p 1-1024 -o resultado.json
```

### Aumentar la cantidad de hilos

```bash
python3 goodluck.py -t 192.168.1.1 -p 1-65535 --threads 200
```

### Escaneo completo con todas las opciones

```bash
sudo python3 goodluck.py -t 10.0.0.1 -p 1-1024 --syn --threads 150 -o escaneo_completo.json
```

---

## Argumentos CLI

| Argumento       | Descripción                                      | Por defecto      |
|-----------------|--------------------------------------------------|------------------|
| `-t`, `--target` | Dirección IP o hostname del objetivo             | *requerido*      |
| `-p`, `--ports`  | Puertos a escanear (rangos, listas o combinación)| *requerido*      |
| `--syn`          | Usar escaneo SYN stealth (requiere root + Scapy) | Desactivado      |
| `--udp`          | Usar escaneo UDP                                 | Desactivado      |
| `--threads`      | Cantidad de hilos concurrentes                   | 100              |
| `-o`, `--output` | Archivo de salida en formato JSON                | Ninguno          |

---

## Ejemplo de salida

```
  /$$$$$$                            /$$       /$$                           /$$                /$$$
 /$$__  $$                          | $$      | $$                          | $$               |_  $$
| $$  \__/  /$$$$$$   /$$$$$$   /$$$$$$$      | $$       /$$   /$$  /$$$$$$$| $$   /$$       /$$ \  $$
| $$ /$$$$ /$$__  $$ /$$__  $$ /$$__  $$      | $$      | $$  | $$ /$$_____/| $$  /$$/      |__/  | $$
| $$|_  $$| $$  \ $$| $$  \ $$| $$  | $$      | $$      | $$  | $$| $$      | $$$$$$/             | $$
| $$  \ $$| $$  | $$| $$  | $$| $$  | $$      | $$      | $$  | $$| $$      | $$_  $$        /$$  /$$/
|  $$$$$$/|  $$$$$$/|  $$$$$$/|  $$$$$$$      | $$$$$$$$|  $$$$$$/|  $$$$$$$| $$ \  $$      |__//$$$/
 \______/  \______/  \______/  \_______/      |________/ \______/  \_______/|__/  \__/         |___/

                                     By 44Viciius

[*] Objetivo: 192.168.1.1
[*] Puertos: 1-1024
[*] Método: TCP Connect
[*] Hilos: 100

PORT      STATE    SERVICE         VERSION
22/tcp    open     ssh             OpenSSH 8.9p1
80/tcp    open     http            Apache/2.4.52
443/tcp   open     https           nginx/1.18.0
3306/tcp  open     mysql           MySQL 8.0.32

[*] Escaneo completado en 4.82 segundos
[*] 4 puertos abiertos encontrados
```

---

## Limitaciones

- El escaneo SYN requiere privilegios de root y Scapy instalado
- El escaneo UDP no puede distinguir de forma confiable entre puertos abiertos y filtrados (limitación inherente del protocolo)
- El banner grabbing depende de que el servicio responda dentro del timeout — algunos servicios no envían banner
- No soporta escaneo de múltiples hosts en una sola ejecución
- No incluye evasión de firewalls ni técnicas de fragmentación de paquetes

---

## Aviso legal

Esta herramienta fue creada con fines **educativos y de auditoría de seguridad autorizada**. Usala únicamente en redes y sistemas sobre los que tengas permiso explícito para realizar pruebas. El escaneo de puertos no autorizado puede ser ilegal en tu jurisdicción. Yo no me hago responsable del mal uso que se le dé a esta herramienta.

---

## Autor

**Alan Newberry** (alias `44Viciius`)

---

## Licencia

Este proyecto está bajo la [Licencia MIT](LICENSE). Podés usarlo, modificarlo y distribuirlo libremente.
