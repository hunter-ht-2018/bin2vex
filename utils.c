#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

uint8_t* load_file_data(char* filename, size_t* size) {
    FILE* f = fopen(filename, "rb");
    if(f == NULL) {
    	return NULL;
    }
    fseek(f, 0, SEEK_END);
    *size = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t* data = (uint8_t*)malloc(*size);
    if(NULL == data) {
        return NULL;
    }

    int count = fread (data, *size, 1, f);
    fclose(f);
    if(count != 1) {
        free(data);
    	return NULL;
    }
    return data;
}
