# TRACES

Simple syscall tracer program.

## Usage

```bash
git clone https://git.sr.ht/~oled/traces
cd traces/
gcc traces.c -o traces
./traces /bin/echo Hello, World!
```

## IMPORTANT

`traces` currently only supports x86_64 linux.

## Features

- Syscall support more than 200.
- Colored output.
- Register details.

# Author

Created by **oled**
