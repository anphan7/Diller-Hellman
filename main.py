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
from rsa import encrypt

class Public_key:

    def __init__(self):
        self.e = 65537
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
    def fast_modular_exponentiation(self, b, e, n):
        product = 1

        while e > 1:
            if e & 0x01:
                product = (product * b) % n
            b = b * b % n
            e >>= 1
        return (product * b) % n
    
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

        i = 0
        while not self.miller_rabin((p - 1) //2, 128):
            
            p = self.generate_random_number(1028)
            p = self.next_prime(p)
            print(i)
            i += 1
        # select a random a as your private key
        a = self.generate_random_number(1028)
        # calculate your public key
        public_key = self.fast_modular_exponentiation(g, a, p)
        
        
        print(f'public key: {public_key}')
        print(f'private key: {a}')
        print(f'p: {p}')
        
        
        return a, p, public_key

    # part 3b
    def solve(self, g):
        a = 2612528647862839870978891369498308855740275972355961331205065926332319704243358653813456010499514634391124968974054387718234061497446111210933418468934134430645994114476939389370327501185132458555499165609273495697899193881222882537078431809193897089215374805364890531628071972118336999638155044722481541143663
        p = 1615872714573308946629922042462077189800529770664142227639386578251879870405238823567559074128067058617906808093896839251278162433377526307816292702280079149546772760725962207116054797517266445200239104588777226590038452294585547980259343063163992449489503726189892609447878286258912394156380378291430577232827
        public_key = 1140059427466241200014441481194762477055996149442340784735914775462337263129443904250712044305125856535621647834828031465178602924562967302224149070396193757202663698210830940283498929586634642197426534403983259178184679283547051237662412061906867666201150309933266182079963509197587989842867839890938244176474
        g_b = 1333147125696503953347518202935147592026533985948546754934041360504024418154972070919225470393231338392620400426354370453812363039110558097819232839232047660511372351844133013079514566171886067578467267507733758325087801736349815838094976872520607417909798243262237700616012688676481032725435136718051915620805
        
        # calculate shared key from g_b 
        shared_key_g_ab = self.fast_modular_exponentiation(g_b, a, p)
        
        #print(shared_key_g_ab)
        print(f'shared key from g^b: {shared_key_g_ab}')
        shared_key_g_ab = (shared_key_g_ab).to_bytes((shared_key_g_ab.bit_length() + 7) // 8, byteorder='big', signed=False)

        
        hashed = hashlib.sha256(shared_key_g_ab).hexdigest()
        #print(shared_key_g_ab)

        # using the first 16 bytes (128-bits) of the digest.
        hashed = hashed[:32]

        print(hashed) # from print -> a4a1bd9ed628e86029362da71a1388dd 
        hashed = bytes.fromhex(hashed)
        print(hashed) # -> b'\xa4\xa1\xbd\x9e\xd6(\xe8`)6-\xa7\x1a\x13\x88\xdd'

        # from server
        iv = "a2ca2dfbd627fd720cc4460895e44d89"
        cipherText = "0a47587ca24d404fdbc7a38c1924682139de6705e275bcbb2815fd9c6c8490f11be251573420629240c5e6701af400c735aebd574758e40616176d3188bd62780be7279dea7c0dad4043c1291273950e743ef0d393b0d51c6a505df88ff0d808"
        text_len = len(cipherText)

        iv = bytes.fromhex(iv)
        cipherText = bytes.fromhex(cipherText)

        de_cipher = AES.new(hashed, AES.MODE_CBC, iv)
        plaintext = unpad(de_cipher.decrypt(cipherText), AES.block_size)
        print("---")
        print(plaintext)

    #part 4
    def gcd(self, a, b):
        while b != 0:
            a, b = b, a % b
        return a

    def is_coprime(self, a, b):
        return self.gcd(a, b) == 1

    def find_co_prime(self):
        
        while True:
            p = self.generate_random_number(1024)
            p = self.next_prime(p)
            q = self.generate_random_number(1024)
            q = self.next_prime(q)
            co_prime = (p - 1) * (q - 1)

            if self.gcd(co_prime, self.e):
                return p, q, co_prime

        
    def extended_gcd(self, a, b):
        x, previous_x = 0, 1
        while b:
            quotient = a // b
            a, b = b, a % b
            x, previous_x = previous_x - quotient * x, x
        return previous_x

    def find_RSA_parameter(self):

        while True:
            p, q, co_prime = self.find_co_prime()
            n = p * q
            d = self.extended_gcd(self.e, co_prime)
            if d > 0:
                break

        print(f'p = {p}\nq = {q}\nco-prime = {co_prime}\nn = {n}')        
        print(f'private key d = {d}')

        return d, n

    def encrypt(self, m):
        # message to be encrypt
        encrypt_message = int.from_bytes(m.encode(), 'big')

        # change this 
        n = 25767830560037755569533266620811636188795582908928879913730489704222277812715888157133494127530531605840704742550072619615086700766049406427172401203353043211253460122774217891708767416022991092242309243985851251349230887877660676245271378374638048993898230419733378781498358025145961549660026889187898746703203600058370225374320483577686583013190157615989364409519383603416605840056029429025381723468580449881905385586004490121537280898818707948546449817635035995348279211744225236349992472299907702247138088613582618586634953045956145232558271808948035925100158908726813252866111799646623249669035780942196179272563
        
        c_mesg = self.fast_modular_exponentiation(encrypt_message, self.e, n)
        print(f"Encrypted message: {c_mesg}")
    
    def decrypt(self):   

        # change this
        given = 23341521297748008218696402260980281729669231846233595459066403416544662403773789910813765802804275687256396681227921293287838442601299003583085196486374328671270819811586482165286578566715165246065386969728483742037678977811711553525473963584337059350594283616891842287621606670227637272656782011349927529754705805191834757923223549777231790712630007362542702975751750642589644396289231059366273299980563142989173756095464138483944522510293759285760370336996570553937554540091363920002201906805267203491706326783542948521709717860213625994998223030079314511613591873694171967248724870584499032215564787138162331310051
        d = 2480571936513392433101688803434710357738549713481427336858959969848152199832530301712852502412227045809985294120091065461519172301646485270137947711856727491642859452135168541110984842572730683445332087527758907865210456255552759608029313611632992830042631425272714447296536929988340501042237356667019442344759098312350611260099761011304440977558132696378927685912070017800327269650173631984404921589825980958314100798024713405318644198765378162180706581337920628885899093964479126374538197612376076606157774264987287409229490153558667602973544033178093648575854725914660972265374391572480518860567767244250619846913
        n = 25767830560037755569533266620811636188795582908928879913730489704222277812715888157133494127530531605840704742550072619615086700766049406427172401203353043211253460122774217891708767416022991092242309243985851251349230887877660676245271378374638048993898230419733378781498358025145961549660026889187898746703203600058370225374320483577686583013190157615989364409519383603416605840056029429025381723468580449881905385586004490121537280898818707948546449817635035995348279211744225236349992472299907702247138088613582618586634953045956145232558271808948035925100158908726813252866111799646623249669035780942196179272563
        show_ma = hex(self.fast_modular_exponentiation(given, d, n))

        b = bytes.fromhex(show_ma[2:])
        print(b.decode("ASCII"))

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
    #p.find_RSA_parameter()
    #p.encrypt('uninaugurated')
    #p.decrypt()