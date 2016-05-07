#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>


#define CHUNK_SZ 4

uint8_t tape[100];
uint8_t *tape_ptr;
char *cmd;


#define p_str(msg) \
    write(1, msg, sizeof(msg) - 1)


int handle_newline() {
    uint8_t c;
    if (read(0, &c, sizeof(c)) != 1) {
        p_str("Newline read failed\n");
        exit(1);
    }
    
    if (c != '\n') {
        p_str("Expected newline\n");
        return -1;
    }

    return 0;
}


int handle_cmd() {
    int i;

    switch (*cmd) {
        case '>':
            tape_ptr++;
            break;

        case '<':
            tape_ptr--;
            break;

        case 'W':
            // Write int value into tape
            if (read(0, tape_ptr, CHUNK_SZ) != CHUNK_SZ) {
                p_str("Did not read enough\n");
                return -1;
            }
            if (handle_newline() < 0) {
                return -1;
            }

            break;

        case 'R':
            // Print current chunk
            for (i = 0; i < CHUNK_SZ; i++) {
                dprintf(1, "%02hhx", tape_ptr[i]);
            }
            p_str("\n");

            break;

        default:
            p_str("Invalid command!\n");
            return -1;
    }

    return 0;
}


void run_interpreter() {
    uint8_t c;

    p_str("Welcome to the interpeter\n");

    while (1) {
        p_str("> ");
        if (read(0, &c, sizeof(c)) != 1) {
            p_str("read() failed");
            break;
        }
        cmd = &c;

        if (handle_newline() < 0) {
            return;
        }

        if (handle_cmd() != 0) {
            break;
        }
    }

    p_str("bye!\n");
}


int main(int argc, char **argv) {
    int i;

    // Randomize tape
    int fd = open("/dev/urandom", 0);
    if (fd == -1 ||
            read(fd, tape, sizeof(tape)) != sizeof(tape)) {
        p_str("Unexpected error; contact CTF admins\n");
        return 1;
    }

    // Set pointer to tape
    tape_ptr = tape;

    run_interpreter();

    return 0;
}
