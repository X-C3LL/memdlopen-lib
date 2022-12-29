#define _GNU_SOURCE
#include "memdlopen.h"



typedef struct {
    void * data;
    size_t size;
    size_t current;
} lib_t;

lib_t libdata;


char stub[] = {0x55, 0x48, 0x89, 0xe5, 0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xd0, 0xc9, 0xc3};
size_t stub_length = 18;

int     my_open(const char *pathname, int flags); 
ssize_t my_read(int fd, void *buf, size_t count);
void *  my_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int     my_fstat(int fd, struct stat *buf);
int     my_close(int fd);


/**** Stuff to change if you have a diff lib *****/
const char read_pattern[] = {0x48, 0x29, 0xc2, 0x48,  0x8d, 0x34,  0x07, 0x44, 0x89, 0xff, 0xe8};
#define read_pattern_length 11


const char mmap_pattern[] = {0x9d, 0x20, 0xff, 0xff, 0xff, 0xe8};
#define mmap_pattern_length 6


const char fxstat_pattern[] = {0x85, 0xf0, 0xfe, 0xff, 0xff, 0xe8};
#define fxstat_pattern_length 6


const char close_pattern[] = {0x45, 0xe0, 0x44, 0x89, 0xff, 0xe8};
#define close_pattern_length 6


const char open_pattern[] = {0xec, 0x98, 0x00, 0x00, 0x00, 0xe8};
#define open_pattern_length 6 


const char* patterns[] = {read_pattern, mmap_pattern, fxstat_pattern, close_pattern,
                          open_pattern, NULL};
const size_t pattern_lengths[] = {read_pattern_length, mmap_pattern_length, 
                                  fxstat_pattern_length, close_pattern_length, open_pattern_length, 0};
const char* symbols[] = {"read", "mmap", "fstat", "close", "open", NULL};
uint64_t functions[] = {(uint64_t)&my_read, (uint64_t)&my_mmap,  (uint64_t)&my_fstat, 
                        (uint64_t)&my_close, (uint64_t)&my_open, 0}; 
char *fixes[6] = {0};
uint64_t fix_locations[6] = {0};

#define LIBC "/lib/x86_64-linux-gnu/libc.so.6"
#define LD "ld-linux-x86-64.so.2"

//#define DEBUG 1 // Uncomment this line for debugging

/*************************/

size_t page_size;
uint64_t first = 0;

bool find_ld_in_memory(uint64_t *addr1, uint64_t *addr2) {
    FILE* f = NULL;
    char  buffer[1024] = {0};
    char* tmp = NULL;
    char* start = NULL;
    char* end = NULL;
    bool  found = false;

    if ((f = fopen("/proc/self/maps", "r")) == NULL){
        return found;
    }

    while ( fgets(buffer, sizeof(buffer), f) ){
        if ( strstr(buffer, "r-xp") == 0 ) {
            continue;
        }
        if ( strstr(buffer, LD) == 0 ) {
            continue;        
        }

        buffer[strlen(buffer)-1] = 0;
        tmp = strrchr(buffer, ' ');
        if ( tmp == NULL || tmp[0] != ' ')
            continue;
        ++tmp;

        start = strtok(buffer, "-");
        *addr1 = strtoul(start, NULL, 16);
        end = strtok(NULL, " ");
        *addr2 = strtoul(end, NULL, 16);
        found = true;
    }
    fclose(f);
    return found;
}


/* hooks */

int my_open(const char *pathname, int flags) {
    void *handle;
    int (*mylegacyopen)(const char *pathnam, int flags);

    handle = dlopen (LIBC, RTLD_NOW);
    mylegacyopen = dlsym(handle, "open");
    if (strstr(pathname, "magic.so") != 0){
        #if DEBUG
            printf("\t[+] Open called with magic word. Returning magic FD (0x69)\n");
        #endif
        return 0x69;
    }
    return mylegacyopen(pathname, flags);
}

ssize_t my_read(int fd, void *buf, size_t count){
    void *handle;
    ssize_t (*mylegacyread)(int fd, void *buf, size_t count);

    handle = dlopen (LIBC, RTLD_NOW);
    mylegacyread = dlsym(handle, "read");
    if (fd == 0x69){
        size_t size = 0;
        if ( libdata.size - libdata.current >= count ) {
            size = count;
        } else {
            size = libdata.size - libdata.current;
        }
        memcpy(buf, libdata.data + libdata.current, size);
        libdata.current += size;
        #if DEBUG
            printf("\t[+] Read called with magic FD. Returning %ld bytes from memory\n", size);
        #endif
        return size;
    }
    size_t ret =  mylegacyread(fd, buf, count);
    #if DEBUG
        printf("Size: %ld\n",ret);
    #endif
    return ret;
}

void * my_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset){
    int mflags = 0;
    void * ret = NULL;
    uint64_t start = 0;
    size_t size = 0;

    if ( fd == 0x69 ) {
        mflags = MAP_PRIVATE|MAP_ANON;
        if ( (flags & MAP_FIXED) != 0 ) {
            mflags |= MAP_FIXED;
        }
        ret = mmap(addr, length, PROT_READ|PROT_WRITE|PROT_EXEC, mflags, -1, 0);
        size = length > libdata.size - offset ? libdata.size - offset : length;
        memcpy(ret, libdata.data + offset, size);
        mprotect(ret, size, prot);
        if (first == 0){
            first = (uint64_t)ret;
        }
        #if DEBUG
            printf("\t[+] Inside hooked mmap (fd: 0x%x)\n", fd);
        #endif
        return ret;
    }
    return mmap(addr, length, prot, flags, fd, offset);
}


int my_fstat(int fd, struct stat *buf){
    void *handle;
    int (*mylegacyfstat)(int fd, struct stat *buf);


    handle = dlopen (LIBC, RTLD_NOW);
    mylegacyfstat = dlsym(handle, "fstat64");

    if ( fd == 0x69 ) {
        memset(buf, 0, sizeof(struct stat));
        buf->st_size = libdata.size;
        buf->st_ino = 0x666; // random number
        #if DEBUG
            printf("\t[+] Inside hooked fstat64 (fd: 0x%x)\n", fd);
        #endif
        return 0;
    }
    return mylegacyfstat(fd, buf);
}

int my_close(int fd) {
    if (fd == 0x69){
        #if DEBUG
            printf("\t[+] Inside hooked close (fd: 0x%x)\n", fd);
        #endif
        return 0;
    }
    return close(fd);
}


/* Patch ld.so */
bool search_and_patch(uint64_t start_addr, uint64_t end_addr, const char* pattern, const size_t length, const char* symbol, const uint64_t replacement_addr, int position) {

    bool     found = false;
    int32_t  offset = 0;
    uint64_t tmp_addr = 0;
    uint64_t symbol_addr = 0;
    char * code = NULL;
    void * page_addr = NULL;

    tmp_addr = start_addr;
    while ( ! found && tmp_addr+length < end_addr) {
        if ( memcmp((void*)tmp_addr, (void*)pattern, length) == 0 ) {
            found = true;
            continue;
        }
        ++tmp_addr;
    }

    if ( ! found ) {
        return false;
    }

    offset = *((uint64_t*)(tmp_addr + length));
    symbol_addr = tmp_addr + length + 4 + offset;

    //Save data to fix later
    fixes[position] = malloc(stub_length * sizeof(char));
    memcpy(fixes[position], (void*)symbol_addr, stub_length);
    fix_locations[position] = symbol_addr;
    #if DEBUG
        printf("[*] Symbol: %s - Addr: %lx\n", symbol, fix_locations[position]);
    #endif

    code = malloc(stub_length * sizeof(char));
    memcpy(code, stub, stub_length);
    memcpy(code+6, &replacement_addr, sizeof(uint64_t));

    page_addr = (void*) (((size_t)symbol_addr) & (((size_t)-1) ^ (page_size - 1)));
    mprotect(page_addr, page_size, PROT_READ | PROT_WRITE); 
    memcpy((void*)symbol_addr, code, stub_length);
    mprotect(page_addr, page_size, PROT_READ | PROT_EXEC); 
    return true;
}


/* remove hooks */
bool fix_hook(char *fix, uint64_t addr){
    void *page_addr = (void*) (((size_t)addr) & (((size_t)-1) ^ (page_size - 1)));
    mprotect(page_addr, page_size, PROT_READ | PROT_WRITE);
    memcpy((void *)addr, fix, stub_length);
    mprotect(page_addr, page_size, PROT_READ | PROT_EXEC);
    return true;
}

extern void restore(void){
    int i = 0;
    #if DEBUG
        printf("---------------------------------------\n");
        printf("[*] Fixing hooks\n");
    #endif
    while ( patterns[i] != NULL ) {
           if ( ! fix_hook(fixes[i], fix_locations[i]) ) {
               return;
           }
           ++i;
    }
    return;
}


/* Export function */
extern void* memdlopen(void* buffer, size_t size, int flags){
    uint64_t start = 0;
    uint64_t end = 0;
    size_t i = 0;
    
    page_size = sysconf(_SC_PAGESIZE);

    /* Set libdata info */
    libdata.data = buffer;
    libdata.size = size;
    libdata.current = 0;

    if (!find_ld_in_memory(&start, &end)){
        return NULL;
    }
    #if DEBUG
        printf("[*] ld.so found in range [0x%lx-0x%lx]\n", start, end);
        printf("-------------[ Patching  ]-------------\n");
    #endif
    while ( patterns[i] != NULL ) {
        if ( ! search_and_patch(start, end, patterns[i], pattern_lengths[i], symbols[i], functions[i], i) ) {     
            return NULL;
        } 
        ++i;
    }
    #if DEBUG
        printf("---------------------------------------\n");
    #endif
    void *handler = dlopen("./magic.so", flags);
    restore();
    return handler;
}


