#include <stdio.h>
#include <stdint.h>
#include <string.h>

void rc4(uint8_t *key, int keylen, uint8_t *data, int len) {
    uint8_t s[256];
    int i, j = 0;
    for (i = 0; i < 256; i++) s[i] = i;
    for (i = 0; i < 256; i++) {
        j = (j + s[i] + key[i % keylen]) % 256;
        uint8_t tmp = s[i]; s[i] = s[j]; s[j] = tmp;
    }
    i = j = 0;
    for (int x = 0; x < len; x++) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        uint8_t tmp = s[i]; s[i] = s[j]; s[j] = tmp;
        data[x] ^= s[(s[i] + s[j]) % 256];
    }
}

uint32_t hash_function(uint8_t *data, int len) {
    uint32_t result = 0x1505;
    for (int i = 0; i < len; i++) {
        result = (result * 0x21) ^ data[i];
    }
    return result;
}

uint32_t hash_utf16_string(uint8_t *data, int len) {
    int i;
    for (i = 0; i + 1 < len; i += 2) {
        if (data[i] == 0 && data[i + 1] == 0)
            break;
    }
    return hash_function(data, i);
}

int RC4decryptCheckHash(uint8_t *enc_data, int enc_len, uint8_t *key, uint8_t *data_base, int key_len, uint32_t expected_hash) {
    uint8_t decrypted[256];
    memcpy(decrypted, enc_data, enc_len);
    
    uint8_t rc4_key[256];
    memcpy(rc4_key, key, key_len);
    for (int i = 0; i < key_len && i < 8; i++) {
        rc4_key[i + key_len] = data_base[i];
    }
    
    rc4(rc4_key, key_len + 8, decrypted, enc_len);
    
    uint32_t h = hash_utf16_string(decrypted, enc_len);
    if (h == expected_hash) {
        return 1;
    }
    return 0;
}

uint64_t Check4(int64_t arg1) {
    uint8_t data_180009000 = 0x7a;
    uint8_t data_180009001 = 0x6d;
    uint8_t data_180009002 = 0xcc;
    uint8_t data_180009003;
    uint8_t data_180009004;
    uint8_t data_180009005;
    uint8_t data_180009006;
    uint8_t data_180009007 = 0xcc;
    
    uint8_t data_base[8] = {data_180009000, data_180009001, data_180009002, data_180009003, 
                           data_180009004, data_180009005, data_180009006, data_180009007};
    
    char ord1 = (*(uint64_t*)arg1)("ord(PASSWORD[1])");
    char ord2 = (*(uint64_t*)arg1)("ord(PASSWORD[2])");
    char ord3 = (*(uint64_t*)arg1)("ord(PASSWORD[3])");
    
    uint32_t expected_hash1 = 0x6293def8;
    uint8_t enc_data1[] = {0xf2, 0x1e, 0x2a, 0xf4, 0x21, 0xef, 0xf7, 0x29, 0x1b, 0x8b,
                          0x96, 0x17, 0x78, 0x8b, 0x32, 0x90, 0x87, 0xb4, 0x58, 0xb5,
                          0xe1, 0xed, 0xb9, 0x48, 0x3e, 0xd9, 0x1a};
    
    uint8_t key0to4int[30];
    memset(key0to4int, 0, 30);
    
    if (!RC4decryptCheckHash(enc_data1, 0x1a, key0to4int, data_base, 2, expected_hash1)) {
        return 0;
    }
    
    int32_t key0to4 = (*(uint64_t*)arg1)(key0to4int);
    data_180009004 = ord1;
    data_180009005 = ord2;
    data_180009003 = (int8_t)(key0to4 >> 3) ^ 0x36;
    data_180009006 = ord3 ^ ord1 ^ ord2 ^ 0x10;
    
    uint8_t enc_data2[] = {0xd0,0xe9,0xc1,0x5a,0x9e,0x0c,0x28,0x31,0x58,0x24,0x5d,0x68,0x54,0x8d,0x6f,0xe7,
                          0xf6,0xdb,0xd7,0xe5,0xc0,0x4b,0x28,0x46,0xe7,0xa4,0x7e,0xcd,0x07,0xf8,0xf4,0x41};
    
    uint8_t ord9[192];
    memset(ord9, 0, 192);
    
    if (!RC4decryptCheckHash(enc_data2, 0x20, ord9, data_base, 8, 0x69fa99d)) {
        return 0;
    }
    
    int16_t ordd9 = (*(uint64_t*)arg1)(ord9);
    
    if (((key0to4 & 0x64) ^ (uint32_t)ordd9) != (*(uint64_t*)arg1)("int(KEY[11:13])")) {
        return 0;
    }
    
    int16_t ord10 = (*(uint64_t*)arg1)(ord9);
    
    uint32_t var_2a0_1 = 0xa7d53695;
    uint8_t enc_data3[] = {0xd6,0xe9,0xdd,0x5a,0x8e,0x0c,0x28,0x31,0x43,0x24,0x59,0x68,0x5e,0x8d,0x67,0xe7,
                          0x91,0xdb,0xa2,0xe5,0xa0,0x4b,0x31,0x46,0x90,0xa4,0x67,0xcd,0x6b,0xf8,0xeb,0x41,0x20,0x94};
    
    uint8_t key02[128];
    memset(key02, 0, 128);
    
    if (!RC4decryptCheckHash(enc_data3, 0x22, key02, data_base, 8, var_2a0_1)) {
        return 0;
    }
    
    int32_t result = (uint32_t)ord10 == (*(uint64_t*)arg1)("int(KEY[0:2],16)") - 7;
    return (uint64_t)result;
}
