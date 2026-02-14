.PHONY: all build build-debug build-release build-asan run clean parity-m0 m1-verify loadtest benchmark-m2 m7-smoke m7-verify m11-parity m11-verify

CC := gcc
CFLAGS_COMMON := -std=c11 -Wall -Wextra -Wpedantic -pthread
CFLAGS := $(CFLAGS_COMMON) -O3 -flto -march=native -mtune=native -fno-plt
CFLAGS_DEBUG := $(CFLAGS_COMMON) -O0 -g3
CFLAGS_RELEASE := $(CFLAGS_COMMON) -O3 -DNDEBUG -flto
CFLAGS_ASAN := $(CFLAGS_DEBUG) -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS := -pthread -flto
LDFLAGS_RELEASE := $(LDFLAGS) -flto
LDFLAGS_ASAN := $(LDFLAGS) -fsanitize=address,undefined
TARGET := bin/dip_server
SRC := src/main.c src/snapshot.c

all: build

build: $(TARGET)

$(TARGET): $(SRC)
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

build-debug: $(SRC)
	@mkdir -p bin
	$(CC) $(CFLAGS_DEBUG) -o $(TARGET) $(SRC) $(LDFLAGS)

build-release: $(SRC)
	@mkdir -p bin
	$(CC) $(CFLAGS_RELEASE) -o $(TARGET) $(SRC) $(LDFLAGS_RELEASE)

build-asan: $(SRC)
	@mkdir -p bin
	$(CC) $(CFLAGS_ASAN) -o $(TARGET) $(SRC) $(LDFLAGS_ASAN)

run: build
	./$(TARGET)

clean:
	rm -rf bin

parity-m0:
	@if [ -z "$$DIP_API_KEY" ]; then \
		echo "ERROR: DIP_API_KEY ist nicht gesetzt"; \
		exit 2; \
	fi
	python3 tools/parity_harness.py \
		--cases tests/parity/m0_cases.json \
		--local-base-url http://127.0.0.1:8080 \
		--remote-base-url https://search.dip.bundestag.de/api/v1 \
		--output-json tests/parity/m0_report.json

m1-verify:
	/home/mathias/bundestag/.venv/bin/python tests/m1/verify_m1.py

loadtest:
	/home/mathias/bundestag/.venv/bin/python tools/load_tester.py $(LOADTEST_ARGS)

benchmark-m2:
	@mkdir -p tests/load
	/home/mathias/bundestag/.venv/bin/python tools/load_tester.py \
		--mode single \
		--endpoint /health \
		--auth-mode none \
		--concurrency 1,2,4,8,16,32 \
		--duration-sec 10 \
		--warmup-sec 2 \
		--output-json tests/load/m2_single_health.json \
		--output-md tests/load/m2_single_health.md
	/home/mathias/bundestag/.venv/bin/python tools/load_tester.py \
		--mode mixed \
		--auth-mode none \
		--concurrency 1,2,4,8,16,32 \
		--duration-sec 10 \
		--warmup-sec 2 \
		--output-json tests/load/m2_mixed.json \
		--output-md tests/load/m2_mixed.md
	/home/mathias/bundestag/.venv/bin/python tools/load_tester.py \
		--mode mixed \
		--auth-mode none \
		--endpoints-file tests/load/m2_complex_filters_endpoints.json \
		--concurrency 1,2,4,8,16,32 \
		--duration-sec 10 \
		--warmup-sec 2 \
		--output-json tests/load/m2_complex_filters.json \
		--output-md tests/load/m2_complex_filters.md

m7-smoke: build
	AUTO_START=1 BASE_URL=http://127.0.0.1:18080 tools/smoke_deploy.sh

m7-verify: build-debug build-release build-asan m7-smoke

m11-parity:
	@if [ -z "$$DIP_API_KEY" ]; then \
		echo "ERROR: DIP_API_KEY ist nicht gesetzt"; \
		exit 2; \
	fi
	python3 tools/parity_harness.py \
		--cases tests/parity/m11_cases.json \
		--local-base-url http://127.0.0.1:8080 \
		--remote-base-url https://search.dip.bundestag.de/api/v1 \
		--api-key "$$DIP_API_KEY" \
		--output-json tests/parity/m11_report.json

m11-verify: m1-verify
