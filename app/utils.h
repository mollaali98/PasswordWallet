#ifndef UTIL_H_
#define UTIL_H_

#include "waallet.h"

void info_print(const char* str);

void warning_print(const char* str);

void error_print(const char* str);

void print_wallet(const wallet_t* wallet);

void is_error(int error_code);

void show_help();

void show_version();

#endif // UTIL_H_