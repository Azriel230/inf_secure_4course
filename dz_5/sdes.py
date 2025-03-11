def b2(x, k):
    return bin(x)[2:].zfill(k)
class SDes():
    P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    P8 = [6, 3, 7, 4, 8, 5, 10, 9]
    LS1 = [2, 3, 4, 5, 1]
    LS2 = [3, 4, 5, 1, 2]
    IP = [2, 6, 3, 1, 4, 8, 5, 7]
    IPinv = [4, 1, 3, 5, 7, 2, 8, 6]
    EP = [4, 1, 2, 3, 2, 3, 4, 1]
    P4 = [2, 4, 3, 1]
    SW = [5, 6, 7, 8, 1, 2, 3, 4]
    # таблицы замен
    S0 = [
        [1, 0, 3, 2],
        [3, 2, 1, 0],
        [0, 2, 1, 3],
        [3, 1, 3, 2]
    ]
    S1 = [
        [0, 1, 2, 3],
        [2, 0, 1, 3],
        [3, 0, 1, 0],
        [2, 1, 0, 3]
    ]

    def __init__(self):
        """
        раундовые ключи. рассчитываются в функции key_schedule
        """
        self.k1 = 0
        self.k2 = 0

    @staticmethod
    def pbox(x, p, nx):
        """
        перестановка бит в nx-битовом числе x по таблице перестановок p
        """
        y = 0
        np = len(p)
        for i in reversed(range(np)):
            if (x & (1 << (nx - p[i]))) != 0:
                y ^= (1 << (np - 1 - i))
        return y

    def p10(self, x):
        return self.pbox(x, self.P10, 10)

    def p8(self, x):
        return self.pbox(x, self.P8, 10)

    def p4(self, x):
        return self.pbox(x, self.P4, 4)

    def ip(self, x):
        return self.pbox(x, self.IP, 8)

    def ipinv(self, x):
        return self.pbox(x, self.IPinv, 8)

    def ep(self, x):
        return self.pbox(x, self.EP, 4)

    def sw(self, x):
        return self.pbox(x, self.SW, 8)

    def ls1(self, x):
        return self.pbox(x, self.LS1, 5)

    def ls2(self, x):
        return self.pbox(x, self.LS2, 5)

    @staticmethod
    def divide_into_two(k, n):
        """
        функция разделяет n-битовое число k на два (n/2)-битовых числа
        """
        n2 = n // 2
        mask = 2**n2 - 1
        l1 = (k >> n2) & mask
        l2 = k & mask
        return l1, l2

    @staticmethod
    def mux(l, r, n):
        """
        l, r - n-битовые числа
        возвращает число (2n-битовое), являющееся конкатенацией бит этих чисел
        """
        y = 0
        y ^= r
        y ^= l << n
        return y

    @staticmethod
    def apply_subst(x, s):
        """
        замена по таблице s
        """
        r = 2 * (x >> 3) + (x & 1)
        c = 2 * ((x >> 2) & 1) + ((x >> 1) & 1)
        return s[r][c]

    def s0(self, x):
        """
        замена по таблице s0
        """
        return self.apply_subst(x, self.S0)

    def s1(self, x):
        """
        замена по таблице s1
        """
        return self.apply_subst(x, self.S1)
    

    
    def key_schedule(self, key):
        """
        Алгоритм расширения ключа. Функция формирует из ключа шифрования key два
        раундовых ключа self.k1, self.k2
        """
        p10_key = self.p10(key)
        k5_1, k5_2 = self.divide_into_two(p10_key, 10)
        shift1_key1 = self.ls1(k5_1)
        shift1_key2 = self.ls1(k5_2)
        key1 = self.p8(self.mux(shift1_key1, shift1_key2, 5))
        shift2_key1 = self.ls2(shift1_key1)
        shift2_key2 = self.ls2(shift1_key2)
        key2 = self.p8(self.mux(shift2_key1, shift2_key2, 5))
        self.k1 = key1
        self.k2 = key2

        # print('After P10: {}'.format(b2(p10_key, 10)))
        # print('After LS-1: {} {}'.format(b2(shift1_key1, 5), b2(shift1_key2, 5)))
        # print('After P8 (K1): {}'.format(b2(key1, 8)))
        # print('After LS-2: {} {}'.format(b2(shift2_key1, 5), b2(shift2_key2, 5)))
        # print('After P8 (K2): {}\n'.format(b2(key2, 8)))
        # return key1, key2


    # Inputs
    # block = 4 bits block data (int number)
    # k = 8 bits subkey (int number)
    # Outputs
    # Out=4 bits block data (int number)
    def F(self, block, k):
        ep_block = self.ep(block)
        xor_block = ep_block ^ k
        l, r = self.divide_into_two(xor_block, 8)
        s0 = self.s0(l)
        s1 = self.s1(r)
        p = self.mux(s0, s1, 2)
        p4 = self.p4(p)

        # print('After E/P: {}'.format(b2(ep_block, 8)))
        # print('After xor with subkey: {}'.format(b2(xor_block, 8)))
        # print('After S0: {}'.format(b2(s0, 2)))
        # print('After S1: {}'.format(b2(s1, 2)))
        # print('After P4: {}\n'.format(b2(p4, 4)))
        return p4

    # Inputs
    # block = 8 bits block data (int number)
    # SK = 8 bits subkey (int number)
    # Outputs
    # Out=8 bits block data (int number)
    def f_k(self, block, SK):
        l,r = self.divide_into_two(block, 8)
        fr = self.F(r, SK)
        lfr = l ^ fr
        res = self.mux(lfr, r, 4)

        # print('block: {}'.format(b2(block, 8)))
        # print('SK: {}'.format(b2(SK, 8)))
        # print('L: {}    R: {}'.format(b2(l, 4), b2(r, 4)))
        # print('F(R, SK): {}'.format(b2(fr, 4)))
        # print('L xor F(R, SK): {}'.format(b2(lfr, 4)))
        # print('return: {}\n'.format(b2(res, 8)))
        return res
    
    # Inputs
    # block = 8 bits block data (int number)
    # K1 = 8 bits subkey (int number)
    # K2 = 8 bits subkey (int number)
    # Outputs
    # Out=8 bits block data (int number)
    def sdes(self, block, k1, k2):
        ip = self.ip(block)
        fk1 = self.f_k(ip, k1)
        sw = self.sw(fk1)
        fk2 = self.f_k(sw, k2)
        ip_inv = self.ipinv(fk2)

        # print('block: {}'.format(b2(block, 8)))
        # print('K1: {}    K2: {}'.format(b2(k1, 8), b2(k2, 8)))
        # print('After IP: {}'.format(b2(ip, 8)))
        # print('After f_k: {}'.format(b2(fk1, 8)))
        # print('After SW: {}'.format(b2(sw, 8)))
        # print('After f_k: {}'.format(b2(fk2, 8)))
        # print('After IPinv: {}\n'.format(b2(ip_inv, 8)))
        return ip_inv
    
    def encrypt(self, plaintext_block):
        return self.sdes(plaintext_block, self.k1, self.k2)

    def decrypt(self, cipherext_block):
        return self.sdes(cipherext_block, self.k2, self.k1)

    def decrypt_data(self, data, key):
        self.key_schedule(key)
        data_arr = []
        for item in data:
            data_arr.append(self.decrypt(item))
        return data_arr

    def encrypt_data(self, data, key):
        self.key_schedule(key)
        data_arr = []
        for item in data:
            data_arr.append(self.encrypt(item))
        return data_arr
    
    #Расшифрование в режиме СВС.
    def decrypt_CBC(self, data_crypt, key, vector):
        self.key_schedule(key)
        data = []
        cd = self.decrypt(data_crypt[0])
        d = vector ^ cd
        data.append(d)
        for i in range(1, len(data_crypt)):
            cd = self.decrypt(data_crypt[i])
            d = data_crypt[i-1] ^ cd
            data.append(d)
        return data


    #Шифрование в режиме СВС.
    def encrypt_CBC(self, data, key, vector):
        self.key_schedule(key)
        data_crypt = []
        ev = data[0] ^ vector
        e = self.encrypt(ev)
        data_crypt.append(e)
        for i in range(1, len(data)):
            ev = data[i] ^ e
            e = self.encrypt(ev)
            data_crypt.append(e)
        return data_crypt
    
    #Расшифрование в режиме OFB.
    def decrypt_OFB(self, data_crypt, key, vector):
        self.key_schedule(key)
        data = []
        cd = self.encrypt(vector)
        d = data_crypt[0] ^ cd
        data.append(d)
        for i in range(1, len(data_crypt)):
            cd = self.encrypt(cd)
            d = data_crypt[i] ^ cd
            data.append(d)
        return data


    #Шифрование в режиме OFB.
    def encrypt_OFB(self, data, key, vector):
        self.key_schedule(key)
        data_crypt = []
        ev = self.encrypt(vector)
        e = data[0] ^ ev
        data_crypt.append(e)
        for i in range(1, len(data)):
            ev = self.encrypt(ev)
            e = data[i] ^ ev
            data_crypt.append(e)
        return data_crypt