NAME = brain-repl
BIN = $(NAME)
CFLAGS = -Os -fstack-protector -fPIE -fPIC -pie -Wl,-pie \
		 -m32 -Wno-unused-result
CC = gcc

.PHONY: test clean

all: $(BIN)

$(NAME): $(NAME).c
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f $(BIN) *\.o
