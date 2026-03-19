# WatCTF Fall 2025 horse-drawn Writeup

This is how it must have felt in the Year of Our Ford.

```bash
ssh hexed@challs.watctf.org -p 8022
```

## Understand the challenge

**Output**

```
lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you 
Connection to challs.watctf.org closed.
```

**main.py**

```python
#!/usr/bin/env python3
import sys
assert sys.stdout.isatty()
flag = open("/flag.txt").read().strip()
to_print = flag + '\r' + ('lmao no flag for you ' * 32)
print(to_print)
```

The `\r` *carriage return* character between the flag and the repeated "lmao" text moves the cursor back to the beginning of the line.

The "lmao no flag for you" text then overwrites the flag text on the same line
You only see the final overwritten text

## Solution

Since the script checks `sys.stdout.isatty()`, you need to make stdout not a TTY to bypass this check. You can do this by redirecting output:

```bash
ssh hexed@challs.watctf.org -p 8022 > output.txt
```

And open `output.txt` in vscode

```
watctf{im_more_of_a_tram_fan_personally}
lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you lmao no flag for you 
```