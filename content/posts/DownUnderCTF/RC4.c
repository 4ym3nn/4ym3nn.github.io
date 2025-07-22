uint64_t sub_1800013f0(int64_t arg1, int32_t arg2, void* arg3, int32_t arg4) {
    uint8_t state[0x138];
    uint8_t* state_ptr = state;
    uint64_t cookie = __security_cookie ^ (uint64_t)state_ptr;

    // Load data into SIMD registers
    __m128i zmm2 = *(__m128i*)data_180007930;
    __m128i zmm3 = *(__m128i*)data_180007950;

    void* rdx = state + 0x8; // offset into state buffer
    uint64_t limit = (uint64_t)(uint32_t)arg4;
    uint32_t rcx = 8;
    uint8_t* rbx = (uint8_t*)arg3;

    // First SIMD processing loop
    do {
        rdx = (uint8_t*)rdx + 0x10;

        __m128i t0 = _mm_add_epi32(_mm_shuffle_epi32(_mm_set1_epi32(rcx - 8), 0), zmm2);
        __m128i t1 = _mm_add_epi32(_mm_shuffle_epi32(_mm_set1_epi32(rcx - 4), 0), zmm2);

        t0 = _mm_and_si128(t0, zmm3);
        t1 = _mm_and_si128(t1, zmm3);

        t0 = _mm_packus_epi16(t0, t0);
        t1 = _mm_packus_epi16(t1, t1);

        *((uint32_t*)((uint8_t*)rdx - 0x18)) = _mm_cvtsi128_si32(t0);
        *((uint32_t*)((uint8_t*)rdx - 0x14)) = _mm_cvtsi128_si32(t1);

        __m128i t2 = _mm_add_epi32(_mm_shuffle_epi32(_mm_set1_epi32(rcx), 0), zmm2);
        __m128i t3 = _mm_add_epi32(_mm_shuffle_epi32(_mm_set1_epi32(rcx + 4), 0), zmm2);

        t2 = _mm_and_si128(t2, zmm3);
        t3 = _mm_and_si128(t3, zmm3);

        t2 = _mm_packus_epi16(t2, t2);
        t3 = _mm_packus_epi16(t3, t3);

        *((uint32_t*)((uint8_t*)rdx - 0x10)) = _mm_cvtsi128_si32(t2);
        *((uint32_t*)((uint8_t*)rdx - 0x0c)) = _mm_cvtsi128_si32(t3);

        rcx += 0x10;
    } while (rcx - 8 < 0x100);

    // RC4-like state manipulation
    uint64_t result = 0;
    uint8_t* rcx_1 = state_ptr;
    uint64_t rdi = 0;

    for (int32_t i = 0; i < 0x100; ++i) {
        uint8_t r9 = *rcx_1++;
        uint64_t idx = modu(i, arg2);
        rdi = *(uint8_t*)((uint8_t*)arg1 + idx) + rdi + r9;
        result = *(uint8_t*)(state_ptr + rdi);
        *(rcx_1 - 1) = result;
        *(state_ptr + rdi) = r9;
    }

    uint64_t r9_1 = 0;
    uint64_t i_2 = (uint64_t)(uint32_t)arg4;

    if (i_2 != 0) {
        do {
            r11 = (r11 + 1) & 0xFF;
            rbx++;
            uint8_t rdx_5 = *(state_ptr + r11);
            r9_1 = (r9_1 + rdx_5) & 0xFF;
            *(state_ptr + r11) = *(state_ptr + r9_1);
            *(state_ptr + r9_1) = rdx_5;
            result = (*(state_ptr + r11) + rdx_5) & 0xFF;
            *(rbx - 1) ^= *(state_ptr + result);
            i_2--;
        } while (i_2 != 0);
    }

    __security_check_cookie(cookie ^ (uint64_t)state_ptr);
    return result;
}
