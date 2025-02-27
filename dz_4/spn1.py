
###############
# SPN1
###############


class SPN1():

    #p-box
    p = [0, 4, 8, 12, 1, 5,
         9, 13, 2, 6, 10, 14,
         3, 7, 11, 15]

    #S-box
    s = [14, 4, 13, 1, 2, 15, 11, 8,
         3, 10, 6, 12, 5, 9, 0, 7]
    
    as_ = []

    # ap_ = [2, 5, 6, 8, 4, 14, 0, 7, 11, 10, 12, 1, 15, 9, 3, 13]

    # s-box
    def sbox(self, x):
        return self.s[x]
    

    # Обратный s-box
    def asbox(self, x):
        self.as_ = [self.s.index(i) for i in range(len(self.s))]
        return self.as_[x]


    # p-box
    def pbox(self, x):
        y = 0
        for i in range(len(self.p)):
            if (x & (1 << i)) != 0:
                y ^= (1 << self.p[i])
        return y


    def apbox(self, x):
        y = 0
        for i in range(len(self.p)):
            if (x & (1 << self.p[i])) != 0:
                y ^= (1 << i)
        return y


    # break into 4-bit chunks
    def demux(self, x):
        y = []
        for i in range(0, 4):
            y.append((x >> (i*4)) & 0xf)
        return y


    #convert back into 16-bit state
    def mux(self, x):
        y = 0
        for i in range(0, 4):
            y ^= (x[i] << (i*4))
        return y

    def round_keys(self, k):
        rk = []
        rk.append((k >> 16) & (2**16-1))
        rk.append((k >> 12) & (2**16-1))
        rk.append((k >> 8) & (2**16-1))
        rk.append((k >> 4) & (2**16-1))
        rk.append(k & (2**16-1))
        return rk

    # Key mixing
    def mix(self, p, k):
        v = p ^ k
        return v

    #round function
    def round(self, p, k):
        #XOR key
        u = self.mix(p, k)
        v = []
        # run through substitution layer
        for x in self.demux(u):
            v.append(self.sbox(x))
        # run through permutation layer
        w = self.pbox(self.mux(v))
        return w

    def last_round(self, p, k1, k2):
        #XOR key
        u = self.mix(p, k1)
        v = []
        # run through substitution layer
        for x in self.demux(u):
            v.append(self.sbox(x))
        #XOR key
        u = self.mix(self.mux(v), k2)
        return u

    def encrypt(self, p, rk, rounds):
        x = p
        for i in range(rounds-1):
            x = self.round(x, rk[i])
        x = self.last_round(x, rk[rounds-1], rk[rounds])
        return x
    

    def encrypt_data(self, data, key, rounds):
        rk = self.round_keys(k=key)
        cypher_data = []
        for item in data:
            c = self.encrypt(p=item, rk=rk, rounds=rounds)
            cypher_data.append(c)
        return cypher_data


    #расшифрование
    def round_keys_to_decrypt(self, key):
        K = self.round_keys(key)
        L = []
        L.append(K[4])
        L.append(self.apbox(K[3]))
        L.append(self.apbox(K[2]))
        L.append(self.apbox(K[1]))
        L.append(K[0])
        return L


    # def decr_round(self, u, l):
    #     v = []
    #     for u_i in self.demux(u):
    #         v.append(self.asbox(u_i))
    #     v1 = self.mux(v)
    #     u2 = self.mix(self.apbox(v1), l)
    #     return u2


    # def decr_first_round(self, y, l1, l2):
    #     u = self.mix(y, l1)
    #     v = []
    #     for u_i in self.demux(u):
    #         v.append(self.asbox(u_i))
    #     v1 = self.mux(v)
    #     u2 = self.mix(self.apbox(v1), l2)
    #     return u2
    


    # def decrypt(self, y, rl, rounds):
    #     decr_y = self.decr_first_round(y=y, l1=rl[0], l2=rl[1])
    #     for i in range(2, rounds - 1):
    #         decr_y = self.decr_round(decr_y, rl[i])
    #     v = []
    #     for u_i in self.demux(decr_y):
    #         v.append(self.asbox(u_i))
    #     v1 = self.mux(v)
    #     return self.mix(v1, rl[4])

    def decrypt(self, y, rl, rounds):
        u = self.mix(y, rl[0])
        for i in range(rounds - 1):
            v = []
            for u_i in self.demux(u):
                v.append(self.asbox(u_i))
            v1 = self.mux(v)
            u = self.mix(self.apbox(v1), rl[i+1])
        v = []
        for u_i in self.demux(u):
            v.append(self.asbox(u_i))
        v4 = self.mux(v)
        res = self.mix(v4, rl[rounds])
        return res


    def decrypt_data(self, data, key, rounds):
        lk = self.round_keys_to_decrypt(key)
        decrypt_data = []
        for item in data:
            d = self.decrypt(item, lk, rounds)
            decrypt_data.append(d)
        return decrypt_data


    #Расшифрование в режиме СВС.
    def decrypt_CBC(self, data_crypt, key, vector, rounds):
        data = []
        lk = self.round_keys_to_decrypt(key)
        cd = self.decrypt(data_crypt[0], lk, rounds)
        d = vector ^ cd
        data.append(d)
        for i in range(1, len(data_crypt)):
            cd = self.decrypt(data_crypt[i], lk, rounds)
            d = data_crypt[i-1] ^ cd
            data.append(d)
        return data


    #Шифрование в режиме СВС.
    def encrypt_CBC(self, data, key, vector, rounds):
        rk = self.round_keys(k=key)
        data_crypt = []
        ev = data[0] ^ vector
        e = self.encrypt(ev, rk, rounds)
        data_crypt.append(e)
        for i in range(1, len(data)):
            ev = data[i] ^ e
            e = self.encrypt(ev, rk, rounds)
            data_crypt.append(e)
        return data_crypt


    #Расшифрование в режиме OFB.
    def decrypt_OFB(self, data_crypt, key, vector, rounds):
        data = []
        rk = self.round_keys(key)
        cd = self.encrypt(vector, rk, rounds)
        d = data_crypt[0] ^ cd
        data.append(d)
        for i in range(1, len(data_crypt)):
            cd = self.encrypt(cd, rk, rounds)
            d = data_crypt[i] ^ cd
            data.append(d)
        return data


    #Шифрование в режиме OFB.
    def encrypt_OFB(self, data, key, vector, rounds):
        rk = self.round_keys(k=key)
        data_crypt = []
        ev = self.encrypt(vector, rk, rounds)
        e = data[0] ^ ev
        data_crypt.append(e)
        for i in range(1, len(data)):
            ev = self.encrypt(ev, rk, rounds)
            e = data[i] ^ ev
            data_crypt.append(e)
        return data_crypt
    

    #Расшифрование в режиме CFB.
    def decrypt_CFB(self, data_crypt, key, vector, rounds):
        data = []
        rk = self.round_keys(k=key)
        cd = self.encrypt(vector, rk, rounds)
        d = data_crypt[0] ^ cd
        data.append(d)
        for i in range(1, len(data_crypt)):
            cd = self.encrypt(data_crypt[i-1], rk, rounds)
            d = data_crypt[i] ^ cd
            data.append(d)
        return data


    #Шифрование в режиме CFB.
    def encrypt_CFB(self, data, key, vector, rounds):
        data_crypt = []
        rk = self.round_keys(k=key)
        ev = self.encrypt(vector, rk, rounds)
        e = data[0] ^ ev
        data_crypt.append(e)
        for i in range(1, len(data)):
            ev = self.encrypt(e, rk, rounds)
            e = data[i] ^ ev
            data_crypt.append(e)
        return data_crypt


    #Расшифрование в режиме CTR.
    def decrypt_CTR(self, data_crypt, key, vector, rounds):
        data = []
        rk = self.round_keys(k=key)
        for i in range(len(data_crypt)):
            cd = self.encrypt(vector + i, rk, rounds)
            d = data_crypt[i] ^ cd
            data.append(d)
        return data


    #Шифрование в режиме CTR.
    def encrypt_CTR(self, data, key, vector, rounds):
        data_crypt = []
        rk = self.round_keys(k=key)
        for i in range(len(data)):
            ev = self.encrypt(vector + i, rk, rounds)
            e = data[i] ^ ev
            data_crypt.append(e)
        return data_crypt
    

def main():
    e = SPN1()
    x = int('1010010100010111', 2)
    rounds = 4
    k = int('01101100011101010100111100100001', 2)
    rk = e.round_keys(k)
    y = e.encrypt(x, rk, rounds)
    print('y={}'.format(bin(y)[2:].zfill(16)))


if __name__ == '__main__':
    main()