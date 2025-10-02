#ifndef ECB_H
#define ECB_H

#include <stdlib.h>

void pkcs7_pad(unsigned char** data, size_t* data_len);
int pkcs7_unpad(unsigned char** data, size_t* data_len);

#endif