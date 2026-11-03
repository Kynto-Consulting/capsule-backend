# Fixtures SARIF (paquete B7)

Todas son **salida real** de cada herramienta, ejecutada el 2026-11-02 en Windows 11 sobre pequenas fuentes de prueba escritas para esto
(no hay ninguna fixture escrita a mano a partir de la documentacion). Los unicos cambios hechos a la salida son los dos de abajo.

| Archivo | Herramienta y comando | Fuente analizada |
|---|---|---|
| `semgrep-1.183.0.sarif` | Semgrep OSS 1.183.0 (`pip install semgrep==1.183.0`): `semgrep --config rules --sarif --metrics=off src` | las reglas propias de `deploy/forgejo/sast/rules` sobre una copia de `deploy/forgejo/sast/tests` (35 resultados) |
| `gitleaks.sarif` | gitleaks (`go install github.com/zricethezav/gitleaks/v8@v8.21.2`): `gitleaks detect --no-git --source . --report-format sarif` | un directorio con tokens de formato real pero **inventados** (GitHub PAT, clave AWS, clave Stripe): 3 resultados |
| `trivy-0.76.1.sarif` | Trivy 0.76.1 (zip oficial de GitHub Releases, SHA-256 comprobado contra `trivy_0.76.1_checksums.txt` de la misma release; ejecutado desde otro directorio): `trivy fs --format sarif --scanners vuln,misconfig,secret` | un `package-lock.json` con lodash 4.17.15 y minimist 1.2.0 y un `Dockerfile` con malas practicas: 13 resultados (9 vulnerabilidades, 4 DS-*) |
| `gosec-dev.sarif` | gosec v2.22.0 (`go install github.com/securego/gosec/v2/cmd/gosec@v2.22.0`; el binario se reporta como `dev`): `gosec -fmt sarif ./...` | un `main.go` con md5, SQL concatenado, `ListenAndServe` sin timeouts: 4 resultados |
| `osv-scanner-1.9.2.sarif` | osv-scanner 1.9.2 (`go install github.com/google/osv-scanner/cmd/osv-scanner@v1.9.2`): `osv-scanner scan --format sarif -L package-lock.json` | el mismo `package-lock.json`: 8 resultados |
| `osv-scanner-1.9.2.json` | el mismo comando con `--format json` | el mismo `package-lock.json`: 8 grupos con `max_severity` |

Cambios sobre la salida:

1. **Rutas**: gosec, osv-scanner y trivy escriben rutas absolutas de la maquina donde corrieron; se reescribieron a `/workspace/acme/<repo>/...`
   (`file:///workspace/acme/...` donde era un URI). El parser las vuelve relativas al repositorio (`paths.go`).
2. **Secretos**: en `gitleaks.sarif` el valor que gitleaks escribe en `snippet.text` se sustituyo por `@@SECRET_1@@`, `@@SECRET_2@@` y `@@SECRET_3@@`
   para que ningun archivo del repositorio contenga una cadena que un escaner de secretos marque. Las pruebas (`helpers_test.go`) las
   reemplazan en tiempo de ejecucion por valores inventados armados a trozos y comprueban que esos valores no aparecen en nada de lo que el
   paquete guarda, devuelve o publica.

Ademas el JSON se volvio a serializar con sangria (mismo contenido).

Lo que estas salidas muestran y que el parser tiene en cuenta (verificado contra ellas, no supuesto):

- osv-scanner 1.9.2 no escribe severidad en el SARIF (todo `warning`, sin `security-severity` ni tags): por eso el flujo de CI sube su JSON nativo.
- gosec marca `level: error` en TODOS los resultados; la severidad real esta en las etiquetas de la regla (`MEDIUM`) y en su texto de ayuda.
- Semgrep OSS sin sesion escribe `fingerprints.matchBasedId/v1 = "requires login"` (inutil) y no escribe `partialFingerprints` ni `level` en los resultados
  (el nivel esta en `defaultConfiguration.level` de la regla): la huella se calcula con regla + ruta + hash del contexto.
- gitleaks escribe el valor del secreto en `region.snippet.text`, y rutas relativas al directorio escaneado.
- trivy trae `security-severity` (CVSS) y la severidad como etiqueta; sus rutas son relativas y la raiz va en `originalUriBaseIds`.
