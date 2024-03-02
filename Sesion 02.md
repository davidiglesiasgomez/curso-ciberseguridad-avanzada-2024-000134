# Sesión #2 23/02/2024

[Como tratar con el código de resultado de error: e_invalidarg (0x80070057)](https://recoverit.wondershare.es/windows-tips/error-result-code-e-invalidarg-0x80070057.html)

## 04 - Caso práctico. PingCastle

> Máquina DC-01. Controlador de Dominio Windows Server 2019 + BadBlood
>
> Ejecutar como administrador
>
> 1>Healthcheck
>
> Seleccionar dominio
>
> Resultados en fichero html (ojo que sobreescribe el anterior)
>
> Mala puntuación por Usuarios con Privilegios Elevados
>
> Probar a resolver "Ensure that the Recycle Bin feature is enabled"
>
> Ejecutar en PowerShell con privilegios de administrador:
>
> Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target 'ucha.local'
>
> Resolver la del caso práctico "Ensure that the NTLMv1 and old LM protocols are banned"
>
> Recordar usar el comando gpupdate /force para forzar la actualización de las políticas de grupo

## 05 - Caso Práctico. Forest Druid

> Máquina DC-01. Controlador de Dominio Windows Server 2019 + BadBlood
>
> Enfoque de árbol de relaciones entre objetos
>
> Probar a eliminar algún usuario de algún grupo y ver cómo afecta al grafo

## 06 - Caso Práctico. Lynis y OpenScap. Errores de bastionado y vulnerabilidades en Linux

### Lynis

```bash
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 013baa07180c50a7101097ef9de922f1c2fde6c4
sudo apt install apt-transport-https
echo "deb https://packages.cisofy.com/community/lynis/deb/ stable main" | sudo tee /etc/apt/sources.list.d/cisofy-lynis.list
sudo apt update
sudo apt install lynis

Ejecutar como root
sudo lynis audit system
```

> Establecer contraseña del gestor de arranque para evitar por ejemplo, cambiar el arranque de linux y hacerlo con una shell y poder cambiar por ejemplo la contraseña del usuario administrador
>
> init=/bin/bash

### OpenScap

```bash
sudo apt-get install libopenscap8
wget https://security-metadata.canonical.com/oval/com.ubuntu.$(lsb_release -cs).usn.oval.xml.bz2
bunzip2 com.ubuntu.$(lsb_release -cs).usn.oval.xml.bz2

Ejecutar con el fichero de políticas
oscap oval eval --report vulnerabilidades.html com.ubuntu.$(lsb_release -cs).usn.oval.xml
```

## Análisis de vulnerabilidades

Proceso sistemático para identificar y evaluar las vulnerabilidades de seguridad en un sistema informático.

### CVEs y CVSS Scores

Los CVE (Common Vulnerabilities and Exposures) son un método de seguimiento exclusivo de vulnerabilidades que han sido informadas públicamente.

El CVSS (Common Vulnerability Scoring System) se utiliza para ayudar a clasificar las vulnerabilidades en función de sus atributos.

## 07 - Caso Práctico. OpenVas. Analisis de vulnerabilidades automatizado

OpenVAS (GreenBone) es una suite de software que ofrece un marco de trabajo para integrar servicios y herramientas especializadas en el escaneo y análisis de vulnerabilidades de seguridad en sistemas informáticos

```bash
Máquina Ubuntu22.04 + OpenVas

sudo docker compose -f docker-compose.yml -p greenbone-community-edition pull notus-data vulnerability-tests scap-data dfn-cert-data cert-bund-data report-formats data-objects
sudo docker compose -f docker-compose.yml -p greenbone-community-edition up -d notus-data vulnerability-tests scap-data dfn-cert-data cert-bund-data report-formats data-objects
curl -f -L https://greenbone.github.io/docs/latest/_static/docker-compose-22.4.yml -o docker-compose.yml
sudo docker compose -f docker-compose.yml -p greenbone-community-edition pull
sudo docker compose -f docker-compose.yml -p greenbone-community-edition up -d
xdg-open "http://127.0.0.1:9392" 2>/dev/null >/dev/null &
```
