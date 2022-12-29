 #include <stdio.h>
 #include <string.h>
 #include <dlfcn.h>
 #include <sys/mman.h>
 #include <stdint.h>
 #include <stdlib.h>
 #include <unistd.h>
 #include <sys/stat.h> 
 #include <stdbool.h>

void* memdlopen(void* buffer, size_t size, int flags);

