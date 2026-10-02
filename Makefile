CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -Iinclude -Ithird_party/unity -Ithird_party/sha256
SRC     = $(filter-out src/main.c, $(wildcard src/*.c)) $(wildcard third_party/sha256/*.c)
TESTS   = $(wildcard tests/test_*.c)
UNITY   = third_party/unity/unity.c

all: app

app: $(SRC) src/main.c
	$(CC) $(CFLAGS) -o app $^

test: $(TESTS:tests/%.c=build/%)
	@for t in $^; do echo "== $$t =="; ./$$t || exit 1; done

build/%: tests/%.c $(SRC) $(UNITY)
	@mkdir -p build
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -rf build app app.exe
