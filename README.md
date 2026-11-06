# GitSecrets

Escáner de secretos en el **historial** de un repositorio git, hermano de
[WebScan](../webscan), [SubdomainEnum](../subdomain-enum) y
[PwCheck](../pwcheck). Muchas veces alguien sube sin querer una clave o
contraseña, y aunque la borre en un commit posterior, **sigue quedando
guardada para siempre** en las versiones viejas de ese archivo. Esta
herramienta recorre todo ese historial, no solo el estado actual.

## Cómo funciona

Para cada commit, compara su contenido contra el del commit anterior y
revisa **solo las líneas agregadas** — así sabe en qué commit exacto se
introdujo cada secreto, en vez de repetir el mismo hallazgo en cada commit
posterior mientras nadie lo toca.

Dos técnicas de detección, combinadas:

| Técnica | Qué detecta |
|---|---|
| **Firmas conocidas** | Formatos fijos de proveedores: claves de AWS, GitHub, Slack, Google, Stripe, Twilio, JWT, bloques de clave privada. Alta confianza. |
| **Entropía** | Variables con nombre sospechoso (`api_key`, `secret`, `token`, `password`...) cuyo valor parece aleatorio de verdad (se mide con entropía de Shannon), descartando placeholders obvios como `changeme` o `your_api_key_here`. |

Para cada hallazgo, además indica si el secreto **sigue expuesto en la
versión actual** del archivo, o si ya fue removido y solo queda en el
historial — son dos urgencias distintas (si sigue en HEAD, es doblemente
grave; si ya no está, igual hay que rotar la credencial, porque el
historial sigue siendo público si el repo lo es).

## Instalación (Windows / PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Uso

```powershell
# Escanea el historial de un repo que ya tienes clonado
python -m gitsecrets scan C:\ruta\a\mi-repo

# Todas las ramas, no solo la actual
python -m gitsecrets scan C:\ruta\a\mi-repo --all-branches

# Reporte en HTML o JSON
python -m gitsecrets scan C:\ruta\a\mi-repo --format html -o reporte.html

# Repos muy grandes: limita cuántos commits revisar
python -m gitsecrets scan C:\ruta\a\mi-repo --max-commits 2000
```

El código de salida es `2` si encontró algo (útil para CI/CD), `0` si no.

## Seguridad de la propia herramienta

- **El secreto nunca se muestra completo**: en los hallazgos, en los
  reportes (texto/JSON/HTML) ni en la terminal — solo sus primeros
  caracteres.
- **Solo lee**: nunca modifica el repositorio, no hace commits, no
  reescribe historial, no se conecta a ningún servidor externo.
- Revisa un repositorio **que ya tienes en tu disco**: no clona nada por
  ti, así que no hay que pedir autorización para un objetivo externo.

## Pruebas

```powershell
python -m pytest -q
```

Construye un repositorio git real y temporal (con GitPython) con una
historia conocida: una clave de AWS que se agrega y luego se quita, y un
secreto genérico que nunca se toca, para validar ambas rutas de detección
y que el valor completo jamás termine en ningún reporte.

## Ideas para siguientes versiones

- Más firmas de proveedores (Azure, GCP service accounts, SendGrid...).
- Modo `--pre-commit`: revisar solo lo que se está por confirmar, antes
  de que llegue a quedar en el historial.
- Integración como GitHub Action para que corra en cada pull request.
