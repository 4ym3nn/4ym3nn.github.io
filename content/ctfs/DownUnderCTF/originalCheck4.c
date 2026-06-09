180001ae0    uint64_t Mod1::findC13Lines(
180001ae0      int64_t arg1)

180001b0e        void var_2c8
180001b0e        int64_t rax_1 = __security_cookie ^ &var_2c8
180001b1b        int32_t var_270
180001b1b        __builtin_wcscpy(dest: &var_270, src: u"ord(PASSWORD[1])")
180001b6f        int32_t var_248
180001b6f        __builtin_wcscpy(dest: &var_248, src: u"ord(PASSWORD[2])")
180001bac        int32_t var_220
180001bac        __builtin_wcscpy(dest: &var_220, src: u"ord(PASSWORD[3])")
180001be9        char rax_2 = (*arg1)(&var_270)
180001bf2        char rax_3 = (*arg1)(&var_248)
180001bfb        char rax_4 = (*arg1)(&var_220)
180001c00        int32_t var_2a0 = 0x6293def8
180001c0f        int32_t var_298
180001c0f        __builtin_memcpy(dest: &var_298, src: "\xf2\x1e\x2a\xf4\x21\xef\xf7\x29\x1b\x8b\x96\x17\x78\x8b\x32\x90\x87\xb4\x58\xb5\xe1\xed\xb9\x48\x3e\xd9", n: 0x1a)
180001c3d        int128_t s
180001c3d        __builtin_memset(&s, c: 0, n: 0x1e)
180001c57        int128_t s_1
180001c57        __builtin_memset(s: &s_1, c: 0, n: 0x60)
180001c86        uint64_t result
180001c86        
180001c86        if (j_sub_180002060(&var_298, 0x1a, &s, &data_180009000, 2, var_2a0) == 0)
180001e83            result = 0
180001c86        else
180001c90            int32_t rax_6 = (*arg1)(&s)
180001c95            data_180009004 = rax_2
180001c9e            data_180009005 = rax_3
180001cae            var_298 = 0x5ac1e9d0
180001cb6            data_180009003 = (rax_6 s>> 3).b ^ 0x36
180001cc6            data_180009006 = rax_4 ^ rax_2 ^ rax_3 ^ 0x10
180001cce            int32_t var_294_1 = 0x31280c9e
180001cdc            int32_t var_290
180001cdc            __builtin_strncpy(dest: &var_290, src: "X$]h", n: 4)
180001ce6            int32_t var_28c
180001ce6            __builtin_memcpy(dest: &var_28c, src: "\x54\x8d\x6f\xe7\xf6\xdb\xd7\xe5\xc0\x4b\x28\x46\xe7\xa4\x7e\xcd\x07\xf8\xf4\x41", n: 0x14)
180001d0e            void var_f8
180001d0e            memset(dest: &var_f8, c: 0, count: 0xc0)
180001d0e            
180001d43            if (j_sub_180002060(&var_298, 0x20, &var_f8, &data_180009000, 8, 0x69fa99d) == 0)
180001e83                result = 0
180001d43            else
180001d50                int16_t rax_8 = (*arg1)(&var_f8)
180001d5e                int112_t var_1e8
180001d5e                __builtin_wcscpy(dest: &var_1e8, src: u"11:13")
180001d5e                
180001d7d                if (((rax_6 & 0x64) ^ zx.d(rax_8)) != (*arg1)(&s))
180001e83                    result = 0
180001d7d                else
180001d99                    int16_t var_de
180001d99                    int16_t var_de_1 = var_de - 8
180001da3                    int16_t var_dc_1 = var_de - 9
180001dae                    int16_t var_da_1 = var_1e8:0xa.w
180001db9                    int16_t var_d8_1 = var_1e8:0xc.w
180001dc0                    int16_t rax_13 = (*arg1)(&var_f8)
180001dc5                    int32_t var_2a0_2 = 0xa7d53695
180001dd4                    var_298 = 0x5adde9d6
180001de0                    int32_t var_294_2 = 0x31280c8e
180001ded                    int32_t var_290_1
180001ded                    __builtin_strncpy(dest: &var_290_1, src: "C$Yh", n: 4)
180001dfa                    int32_t var_28c_1
180001dfa                    __builtin_memcpy(dest: &var_28c_1, src: "\x5e\x8d\x67\xe7\x91\xdb\xa2\xe5\xa0\x4b\x31\x46\x90\xa4\x67\xcd\x6b\xf8\xeb\x41\x20\x94", n: 0x16)
180001e02                    int128_t s_2
180001e02                    __builtin_memset(s: &s_2, c: 0, n: 0x80)
180001e02                    
180001e6a                    if (j_sub_180002060(&var_298, 0x22, &s_2, &data_180009000, 8, var_2a0_2) == 0)
180001e83                        result = 0
180001e6a                    else
180001e7a                        int32_t result_1
180001e7a                        result_1.b = zx.d(rax_13) == (*arg1)(&s_2) - 7
180001e7e                        result = zx.q(result_1)
180001e7e        
180001e8f        j___security_check_cookie(rax_1 ^ &var_2c8)
180001eb4        return result
