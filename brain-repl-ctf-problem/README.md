# Brain-repl problem for U of M FB CTF 2016

## Files:

* `brain-repl`: binary to exploit
* `brain-repl.c`: source code for binary
* `Makefile`: Makefile to build
* `run_brain_repl.sh`: script to run brain-repl as a server process
* `flag.txt`: When running competition, put value of flag in this file


## Notes:

The `brain-repl` binary reads/writes via stdin/stdout. To get a server process
running, a utility such as socat must be used. The `run_brain_repl.sh` script
shows how to run the program with socat.

Also, the binary should be run with ASLR and NX (aka DEP) enabled.
