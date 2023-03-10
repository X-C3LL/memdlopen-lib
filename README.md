# memdlopen-lib

An updated version of m1m1x's [memdlopen project](https://github.com/m1m1x/memdlopen) (based on [Nologin's paper](http://www.nologin.org/Downloads/Papers/remote-library-injection.pdf)).

# Usage
It's just a PoC. Read your shared object from a socket or any covert channel and then pass the buffer + size to the function `memdlopen()` and use the returned handler as it was generated by a normal `dlopen()`:

```c
    so = malloc(/* size */);
    //...
    // Copy contents to "so" buffer
    //...
    handler = memdlopen(so, st.st_size, flags); //flags == RLTD_NOW, RLTD_LAZY, etc. 
```

If you wanna see some `printfs` uncomment the `#define DEBUG` line.
# Update 
The PoC was built on:
```bash
=> lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 22.04.1 LTS
Release:    22.04
Codename:   jammy

=> ldd --version 
ldd (Ubuntu GLIBC 2.35-0ubuntu3.1) 2.35
```

If you have a diff libc you will need to update the signatures at `memdlopen.h`. To facilitate that you can use this [crappy script](https://gist.github.com/X-C3LL/0fb8cb32a6eb61c8af45e933bbc51a77):
```bash

➜  research python3 hookity.py ef896a699bb1c2e4e231642b2e1688b2f1a61e.debug 2>/dev/null
  -=[ Hookity - @TheXC3LL ]=-


[*] Opening ef896a699bb1c2e4e231642b2e1688b2f1a61e.debug
[*] Analyzing file...
-------[ Signatures ]-------
sym.__GI___close_nocancel:45e04489ffe8:6
sym.__open_nocancel:ec98000000e8:6
sym.__mmap:9d20ffffffe8:6
sym.__GI___fstat64:85f0feffffe8:6
```

# Author
Juan Manuel Fernández ([@TheXC3LL](https://twitter.com/TheXC3LL))
