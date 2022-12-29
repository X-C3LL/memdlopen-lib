#include "../lib/memdlopen.h"

int main(int argc, char **argv){
    struct stat st;
    void *so = NULL;
    size_t data = 0;
    FILE *file;
    void *handler;

    stat("/home/vagrant/research/php/backdoor/adepts/test.so", &st);
    file = fopen("/home/vagrant/research/php/backdoor/adepts/test.so", "r");
    so = malloc(st.st_size);
    data = fread(so, 1, st.st_size, file);
    fclose(file);
    handler = memdlopen(so, st.st_size, RTLD_NOW); 
    return 1;
}

