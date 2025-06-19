import random
import functools
import hashlib

 Initial nucleotide map
nm = {'A': 0, 'T': 1, 'G': 2, 'C': 3}

def fun1(nm_in):
    tmp = {}
    tmp['A'] = nm_in['T']
    tmp['T'] = nm_in['G']
    tmp['G'] = nm_in['C']
    tmp['C'] = nm_in['A']
    return tmp

def fun2(nm_in):
    s1 = "AGCT"
    s2 = "TCAG"
    s3 = "CTGA"
    total = sum(nm_in.values())
    tmp = {c: total for c in s1}
    for s in (s1, s2, s3):
        for i, c in enumerate(sorted(nm_in.keys())):
            tmp[c] -= nm_in[s[i]]
    return tmp

def fun3(nm_in):
    seed = 0
    for v in nm_in.values():
        seed ^= v
    random.seed(seed)
    class Unlucky(dict):
        def __init__(self, mapping):
            super().__init__(mapping)
            keys = list("ACGT")
            random.shuffle(keys)
            for i in range(4):
                self["ACGT"[i]] = mapping[keys[i]]
    new_nm = Unlucky(nm_in)
    return new_nm

def fun4(nm_in):
    class MM(type):
        def __new__(cls, name, bases, dct):
            return super().__new__(cls, name, bases, dct)
        def __call__(cls, *args, **kwargs):
            instance = super().__call__(*args, **kwargs)
            vals = list(instance.values())
            vals = vals[::2] + vals[1::2]
            for i, k in enumerate(sorted(instance.keys())):
                instance[k] = vals[i]
            return instance

    class MD(dict, metaclass=MM):
        pass

    new_nm = MD(dict(nm_in))
    return new_nm

 Run and print after each
print("Initial nm:", nm)
nm = fun1(nm)
print("After fun1, nm =", nm)
nm = fun2(nm)
print("After fun2, nm =", nm)
nm = fun3(nm)
print("After fun3, nm =", nm)
nm = fun4(nm)
print("After fun4, nm =", nm)
