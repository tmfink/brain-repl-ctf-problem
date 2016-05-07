set disable-randomization off
catch exec
r

# Hit exec catchpoint

# Set breakpoints

hbreak main


# Continue executing (until we hit a breakpoint)
c

