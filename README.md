# Simulador CLI de Java Keytool en Python

Proyecto académico de simulación en línea de comandos (CLI) de la herramienta oficial `keytool` de Java para el módulo de **Seguridad y Servicios (DAM2)**.

Desarrollado con Python y la biblioteca `cryptography`, implementa:

- Operaciones asimétricas con pares **RSA de 2048 bits**.
- Gestión de certificados **X.509**.
- Extracción de peticiones de firma (**CSR** en formato PEM).
- Persistencia segura de almacenes **PKCS#12** cifrados con contraseña.

---

## 1. Integrantes del Proyecto

- **Adrian Iturbe Moreno**
- **Àlex Garcia Rossell**

---

## 2. Requisitos e Instalación

El proyecto requiere **Python 3.12+** y la librería `cryptography`.

### 2.1. Creación y activación del entorno virtual

**En Windows (PowerShell):**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**En Linux / macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2.2. Instalación de dependencias

Una vez activado el entorno virtual (`.venv`), instala los paquetes requeridos:

```bash
pip install cryptography
```

Opcionalmente, mediante el archivo de manifiesto:

```bash
pip install -r requirements.txt
```

---

## 3. Guía de Uso del Simulador

El ejecutable principal es `Pytool.py` y acepta tanto la sintaxis habitual de Linux/Python con doble guion (`--genkeypair`) como la sintaxis oficial de Java Keytool con un solo guion (`-genkeypair`).

### 3.1. Menú de ayuda (`-help` / `--help`)

Despliega el listado con la sintaxis, las operaciones disponibles y las opciones:

```bash
python Pytool.py --help
# o también:
python Pytool.py -help
```

### 3.2. Generación de par de claves y KeyStore (`-genkeypair`)

Genera un par RSA de 2048 bits, emite un certificado autofirmado X.509 y almacena la clave y el certificado en un contenedor estándar PKCS#12 protegido por contraseña.

**Modo interactivo** (solicita los datos en tiempo real):

```bash
python Pytool.py -genkeypair
```

El programa solicitará la contraseña, el alias identificador y los campos del *Distinguished Name* (CN, OU, O, L, ST, C).

**Modo desatendido** (parámetros directos por consola):

```bash
python Pytool.py -genkeypair -alias miServidor -keystore keystore.p12 -keysize 2048 -dname "CN=miweb.com, OU=Seguridad, O=MiEmpresa, L=Malaga, ST=Malaga, C=ES" -storepass 123456
```

### 3.3. Extracción de solicitud de firma CSR (`-certreq`)

Carga la clave privada y los atributos del certificado del almacén para generar una solicitud de certificación estándar (CSR) serializada en formato PEM (`.csr`).

**Modo interactivo:**

```bash
python Pytool.py -certreq
```

**Modo directo por parámetros:**

```bash
python Pytool.py -certreq -alias miServidor -keystore keystore.p12 -file solicitud.csr -storepass 123456
```

### 3.4. [Ampliación] Inspección del KeyStore (`-list`)

Descifra de forma segura el contenedor PKCS#12 para auditar en pantalla los datos del titular (*Subject*), la entidad emisora (*Issuer*), el número de serie y la validez temporal del certificado.

```bash
python Pytool.py -list -keystore keystore.p12 -storepass 123456
```

> **Opcional:** añade `-v` para mostrar adicionalmente la huella digital SHA-256.

### 3.5. [Ampliación] Comandos adicionales

**Exportar certificado a archivo PEM (`--exportcert`):**

```bash
python Pytool.py --exportcert -keystore keystore.p12 -file certificado.crt -storepass 123456
```

**Inspeccionar un certificado externo (`--printcert`):**

```bash
python Pytool.py --printcert -file certificado.crt
```

---

## 4. Matriz de Pruebas Ejecutadas

### 4.1. Suite de pruebas unitarias automatizadas

Las funciones básicas de validación y generación criptográfica están verificadas mediante la suite automatizada `unittest`:

```bash
python -m unittest tests/test_simulator.py
```

| ID    | Función                  | Entrada                                 | Resultado esperado         | Estado     |
|-------|--------------------------|-----------------------------------------|----------------------------|------------|
| UT-01 | `validate_password`      | `"12345"` (longitud < 6)                | `False`                    | ✅ Superado |
| UT-02 | `validate_password`      | `"123456"` (longitud ≥ 6)               | `True`                     | ✅ Superado |
| UT-03 | `validate_alias`         | `""` o espacios en blanco               | `False`                    | ✅ Superado |
| UT-04 | `validate_alias`         | `"miClave"`                             | `True`                     | ✅ Superado |
| UT-05 | `validate_dname`         | Diccionario con CN vacío                | `False`                    | ✅ Superado |
| UT-06 | `validate_dname`         | `{"CN": "Adrian", "C": "ES"}`           | `True`                     | ✅ Superado |
| UT-07 | `generate_rsa_keypair`   | `key_size=2048`                         | `key.key_size == 2048`     | ✅ Superado |

### 4.2. Pruebas funcionales y control de excepciones (CLI)

| ID    | Caso de prueba            | Comando                                         | Comportamiento esperado                                                    | Estado      |
|-------|---------------------------|-------------------------------------------------|----------------------------------------------------------------------------|-------------|
| CP-01 | Menú de ayuda             | `python Pytool.py -help`                        | Muestra la sintaxis y finaliza con código 0.                               | ✅ Correcto |
| CP-02 | Generación nominal        | `-genkeypair -alias test -storepass 123456`     | Genera clave RSA 2048 y crea el almacén `keystore.p12`.                    | ✅ Correcto |
| CP-03 | Contraseña corta          | `-genkeypair` con contraseña `"123"`            | Deniega la creación avisando de que requiere mínimo 6 caracteres.          | ✅ Correcto |
| CP-04 | Alias duplicado           | `-genkeypair -alias test` sobre almacén existente | Deniega la operación informando de que el alias ya está presente.        | ✅ Correcto |
| CP-05 | Almacén inexistente       | `-certreq -keystore no_existe.p12`              | Notifica que el almacén no existe sin arrojar trazas de error.             | ✅ Correcto |
| CP-06 | Contraseña incorrecta     | `-certreq` con credenciales erróneas            | Captura `ValueError` y avisa de contraseña incorrecta.                     | ✅ Correcto |
| CP-07 | Exportación CSR           | `-certreq -alias test -storepass 123456`        | Genera el archivo `.csr` serializado en estándar PEM.                      | ✅ Correcto |
| CP-08 | Inspección del KeyStore   | `-list -keystore keystore.p12`                  | Descifra el almacén e imprime sujeto, emisor, serial y caducidad.          | ✅ Correcto |

---

## 5. Estructura del Proyecto

```text
Keytool/
├── modules/
│   ├── __init__.py           # Declaración del paquete modular
│   ├── cli_ui.py             # Formatos, colores ANSI y banners de consola
│   ├── crypto_utils.py       # Algoritmos criptográficos (RSA, X.509, CSR)
│   ├── keystore_manager.py   # Persistencia y gestión segura de PKCS#12
│   └── validator.py          # Validaciones de contraseñas, alias y DNAME
├── tests/
│   └── test_simulator.py     # Suite de pruebas unitarias automatizadas
├── Pytool.py                 # Punto de entrada ejecutable de la CLI
├── README.md                 # Documentación técnica obligatoria
└── requirements.txt          # Lista de dependencias del entorno
```
