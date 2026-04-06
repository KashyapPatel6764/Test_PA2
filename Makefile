CC      = gcc
CFLAGS  = -Wall -Wextra -g -Iinclude
LDFLAGS =

OBJ_DIR = obj
SRC     = src

.PHONY: all clean

all: server client

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(OBJ_DIR)/protocol.o: $(SRC)/protocol.c include/protocol.h | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

server: $(SRC)/server.c $(OBJ_DIR)/protocol.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

client: $(SRC)/client.c $(OBJ_DIR)/protocol.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -rf $(OBJ_DIR) server client received_* *.log
