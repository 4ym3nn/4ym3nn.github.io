int64_t check3(int64_t arg1) {
    char buffer1[0x6c8];
    int64_t cookie = __security_cookie ^ (int64_t)&buffer1;

    // Initial data block setup
    uint8_t data[16] = {0};
    *(uint32_t*)(data + 4) = 0x530053; // 'S\0S'
    *(uint16_t*)(data + 8) = 0x57;      // 'W'

    int i = 0;
    uint16_t* out = (uint16_t*)data;

    while (i < 8) {
        uint8_t result = 0;

        switch (i) {
            case 0:
                result = data[6] ^ 0x03;
                break;
            case 1:
                result = data[0] ^ 0x11;
                break;
            case 5:
                result = data[8] ^ 0x18;
                break;
            case 6:
                result = data[10] ^ 0x1D;
                break;
            case 7:
                result = data[12] ^ 0x16;
                break;
        }

        if (result)
            *out = (uint16_t)result;

        out++;
        i++;
    }

    // Prepare and parse input strings
    char format[24] = "ord(%s[%d])";
    char input[128] = {0};
    char output[24] = {0};

    uint16_t* resultData = (uint16_t*)output;
    int index = 0;

    while (index < 12) {
        snprintf(input, sizeof(input), format, (char*)data, index);
        resultData[index] = ((int (*)(char*))arg1)(input);
        index++;
    }

    // Collect specific characters from buffer
    char a = output[12];
    char b = output[14];
    char c = output[4];
    char d = output[6];

    // Prepare comparison format
    char cmp_buffer[1024] = {0};
    char extra[256] = {0};

    snprintf(cmp_buffer, sizeof(cmp_buffer), "%d + 2 == %d and %d == %d and (...)", b);

    for (int k = 0; k < 3; ++k) {
        snprintf(extra, sizeof(extra), " and %d > 48 and %d < 57", ((char*)&a)[k], ((char*)&a)[k]);
        strcat(cmp_buffer, extra);
    }

    int64_t result = ((int (*)(char*))arg1)(cmp_buffer);
    __security_check_cookie(cookie ^ (int64_t)&buffer1);
    return result;
}
