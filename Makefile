BIN = bin

all: $(BIN)
	gcc ping.c -o $(BIN)/ping

$(BIN):
	mkdir -p $@
