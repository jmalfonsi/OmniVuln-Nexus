#include <stddef.h>
#include <string.h>

int parse_packet(const unsigned char *data, size_t size) {
    char dst[8];

    if (size == 0) {
        return 0;
    }

    // Vulnérabilité volontaire : size peut être > 8
    memcpy(dst, data, size);

    return dst[0];
}