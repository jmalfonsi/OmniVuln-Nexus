#include <stddef.h>
#include <stdint.h>

extern "C" {
#include "vuln.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parse_packet(data, size);
    return 0;
}