# DIP C-Server (Betriebs-Runbook)

Dieser Ordner enthält den performanten, DIP-kompatiblen API-Server in C.

## Voraussetzungen

- Linux/macOS mit `gcc`, `make`, `curl`
- Datenquellen im Workspace-Root (`drs*`, `pp*`, `stammdaten/`)
- Optional für Verifikation/Tools: Python aus `.venv`

## Build-Profile

```bash
cd server
make build          # Standardprofil (-O2)
make build-debug    # Debugprofil (-O0 -g3)
make build-release  # Releaseprofil (-O3 -DNDEBUG -flto)
make build-asan     # Debug + ASan/UBSan
```

## Start

```bash
cd server
DATA_ROOT=.. REBUILD_INTERVAL_SEC=0 ./bin/dip_server --port 8080 --workers 4
```

Wichtige Umgebungsvariablen:
- `DATA_ROOT`: Root mit Rohdaten (`drs*`, `pp*`, `stammdaten/`)
- `SNAPSHOT_DIR`: Speicherort für `snapshot.bin`/`snapshot_manifest.json`
- `REBUILD_INTERVAL_SEC`: `0` = nur manueller Rebuild, `>0` = periodisch
- `SERVER_PORT`, `SERVER_WORKERS`, `SERVER_BACKLOG`, `SERVER_PIN_CPU`

## Healthcheck und Betrieb

```bash
curl -i http://127.0.0.1:8080/health
curl -i http://127.0.0.1:8080/drucksache?format=json
curl -i http://127.0.0.1:8080/drucksache?format=xml
```

Admin-Rebuild (auth-geschützt):

```bash
curl -i "http://127.0.0.1:8080/admin/rebuild?apikey=<KEY>"
```

## Verifikation

```bash
cd server
make m1-verify      # gesamter Regression- und Verifikationslauf
make m7-smoke       # Deployment-Smoke (autostart auf Port 18080)
make m7-verify      # Build-Matrix + Deployment-Smoke
```

## Logging

- Server schreibt strukturierte Request-Logs auf `stdout`.
- Für längere Lastläufe empfiehlt sich Umleitung in Datei oder Journal:

```bash
./bin/dip_server --port 8080 --workers 4 >>server.log 2>&1
```

## Tuning-Hinweise

- Workerzahl: typischerweise `= CPU-Kerne`.
- Für reproduzierbare Latenztests: CPU-Frequenz-Scaling und Hintergrundlast minimieren.
- Snapshot-Rebuilds über `/admin/rebuild` außerhalb von Peakzeiten auslösen.

## Referenzvergleich (Bundestag API)

```bash
cd server
DIP_API_KEY=<public-key> make parity-m0
```

Damit werden repräsentative Requests lokal gegen die Bundestag-API verglichen.
