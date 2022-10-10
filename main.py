'''
    Name: An Phan
    Project 4: Public-key cryptography
'''
import random
from random import getrandbits
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
from base64 import b64decode
from Crypto.Hash import SHA256

class Public_key:

    def __init__(self):
        pass
    def generate_random_number(self, size):
    
        # generate random bits
        p = getrandbits(size)
        p |= (1 << size - 1) | 1
        return p
    def next_prime(self, num):
        while not self.miller_rabin(num, 128):
            num += 1
        return num
    # part 1
    def fast_modular_exponentiation(self, e, b, n):
        product = 1

        while e:
            if e & 0x01:
                product = product * b % n
            b = b * b % n
            e >>= 1
        return product
    
    # part 2
    def miller_rabin(self, n, k):

        # Edge case with prime = 2
        if n == 2:
            return True

        # Even number > 2 is not prime
        if n % 2 == 0:
            return False

        r, s = 0, n - 1

        # Factoring out powers of 2 
        while s % 2 == 0:
            r += 1
            s //= 2
        # Repeat k times
        for _ in range(k):
            # choose base a
            a = random.randint(2, n - 1)
            
            # compute x
            x = pow(a, s, n)

            # if x == 1, -1 -> continue outerloop
            if x == 1 or x == n - 1:
                continue
                
            # repeat number of factor count
            for _ in range(r - 1):

                # compute x
                x = pow(x, 2, n)
                
                # break if x == -1
                if x == n - 1:
                    break
            # definetly not a prime
            else:
                return False
        # probably prime with confidence
        return True

    # part 3a
    def diffie_hellman(self, g):        
        # Select a strong prime number p and (p-1) / 2 also be a prime --> at least 1024 bits
        p = self.generate_random_number(1028)
        
        # get nearest number is prime
        p = self.next_prime(p)

        
        while not self.miller_rabin((p - 1) //2, 128):
            
            p = self.generate_random_number(1028)
            p = self.next_prime(p)

        # select a random a as your private key
        a = self.generate_random_number(1028)
        # calculate your public key
        public_key = self.fast_modular_exponentiation(g, a, p)
        
        """
        print(f'public key: {public_key}')
        print(f'private key: {a}')
        print(f'p: {p}')
        """
        
        return a, p, public_key

    # part 3b
    def solve(self, g):
        a = 2612528647862839870978891369498308855740275972355961331205065926332319704243358653813456010499514634391124968974054387718234061497446111210933418468934134430645994114476939389370327501185132458555499165609273495697899193881222882537078431809193897089215374805364890531628071972118336999638155044722481541143663
        p = 1615872714573308946629922042462077189800529770664142227639386578251879870405238823567559074128067058617906808093896839251278162433377526307816292702280079149546772760725962207116054797517266445200239104588777226590038452294585547980259343063163992449489503726189892609447878286258912394156380378291430577232827
        public_key = 1140059427466241200014441481194762477055996149442340784735914775462337263129443904250712044305125856535621647834828031465178602924562967302224149070396193757202663698210830940283498929586634642197426534403983259178184679283547051237662412061906867666201150309933266182079963509197587989842867839890938244176474
        g_b = 1539567913026071656847873652168183938324411518370244554526158374791557795087722957879800327434860474893340039018626187145674094053582764658965885127171088558233424006311095669303500527381569017019566602499086823163601433359560810097772024140090127852521255417230346378037025164784246059912269867840542583952529
        
        # calculate shared key from g_b 
        shared_key_g_ab = self.fast_modular_exponentiation(g_b, a, p)
        #shared_key_g_ab = pow(g_b, a, p)
        #print(shared_key_g_ab)
        #print(f'shared key from g^b: {shared_key_g_ab}')
        shared_key_g_ab = (shared_key_g_ab).to_bytes((shared_key_g_ab.bit_length() + 7) // 8, byteorder='big', signed=False)

        
        hashed = hashlib.sha256(shared_key_g_ab).hexdigest()
        #print(shared_key_g_ab)

        # using the first 16 bytes (128-bits) of the digest.
        hashed = hashed[:32]

        print(hashed) # from print -> a4a1bd9ed628e86029362da71a1388dd 
        #hashed = bytes.fromhex(hashed)
        hashed = (int(hashed, base=16)).to_bytes(16, byteorder='big')
        print(hashed) # -> b'\xa4\xa1\xbd\x9e\xd6(\xe8`)6-\xa7\x1a\x13\x88\xdd'

        # from server
        iv = "d5dc2282718ea12e159480f13857e7ab"
        cipherText = "256a2ea715029320b711559d927bc8123b8f68cd865ca3fbfc7dcfecfda42a646d981e66f6c1bba3dfdae1eb756c0b88e54cd3cec97443a58f5494e98016636e4656a13c1492276bc4b7f717bae04e1514bb395d99f85018560aa19eb424b9b9"
        text_len = len(cipherText)

        iv = (int(iv, base=16)).to_bytes(16, byteorder='big')
        cipherText = (int(cipherText, base=16)).to_bytes(text_len, byteorder='big')

        de_cipher = AES.new(hashed, AES.MODE_CBC, iv)
        plaintext = unpad(de_cipher.decrypt(cipherText), AES.block_size)
        print("---")
        #print(plaintext)
if __name__ == "__main__":
    p = Public_key()

    
    # Test fast modular exponentiation function with value from slides
    t = p.fast_modular_exponentiation(131, 4235880211405804673, 12855544647099734480)
    # result = 1442355666387997457
    '''
    for i in range (1000000000000000000, 2000000000000000000):
        temp = p.miller_rabin (i, 5)
        if temp == True:
            print(f'with i = {i} -> {temp}')
    '''    
    #p.diffie_hellman(5)
    p.solve(5)
    