#!/bin/bash

socat TCP4-LISTEN:2600,fork,reuseaddr EXEC:./brain-repl
