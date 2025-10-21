#ifndef FILE_IO_H
#define FILE_IO_H

#include <stdlib.h>

unsigned char* read_file(const char* filename, size_t* file_size);
int write_file(const char* filename, const unsigned char* data, size_t data_size);

#endif