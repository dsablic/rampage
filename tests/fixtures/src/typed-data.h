/* SPDX-License-Identifier: Apache-2.0; original owned typed-data fixture. */
#include <stdint.h>

enum TypedMode { MODE_OFF = 0, MODE_READY = 7, MODE_FAULT = -3 };

struct TypedRecord {
    enum TypedMode mode;
    int32_t value;
    char label[8];
};
