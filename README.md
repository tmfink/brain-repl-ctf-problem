# brain-repl CTF problem/writeup

This repo contains the a binary exploitation challenge and solution script.

You can read the full writeup on my blog post:

https://travisf.net/brain-repl-writeup

## Files

* `brain-repl-ctf-problem.tgz`: archive with problem
* `brain-repl-ctf-problem/Makefile`: was used to build problem
* `brain-repl-ctf-problem/README.md`: problem readme
* `brain-repl-ctf-problem/brain-repl`: challenge binary
* `brain-repl-ctf-problem/brain-repl.c`: challenge source code
* `brain-repl-ctf-problem/flag.txt`: sample flag file (the name is public)
* `brain-repl-ctf-problem/run_brain_repl.sh`: script to run the binary
* `debug_brain_repl.sh`: debug script to run binary with socat with or without GDB
* `gdb_cmds.gdb`: GDB command file (used by `debug_brain_repl.sh`)
* `solve_brain_repl.py`: solution script
