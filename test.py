'''
    Name: An Phan
    Project 4: Public-key cryptography

    The work flow:
        Part 3: Generate p (prime), a (private), and public_key (with fast modular)
                Pass to the server to obtain: g^b, ciphertext, and iv -> it need to be modified for new value
        Part 4: Find p, q, n, and co_prime number
                Pass to server to obtain the plain-text message -> change this in main()
                Pass to server to obtain the encrypted message -> change value of given in decrypt()
        
        Notes: since the program will be generate random value every time and we also need value from the server -> need change the value in programs


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
    def pre_prime(self, num):
        while not self.miller_rabin(num, 128):
            num -= 1
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
        p = self.next_prime(p)
        # get nearest number is prime
        next = self.next_prime(p)
        prev = self.pre_prime(p)
        i = 0
        while p <= (next + prev) // 2:
            p = self.generate_random_number(1028)
            p = self.next_prime(p)

            # get nearest number is prime
            next = self.next_prime(p)
            prev = self.pre_prime(p)
            i += 1
            print(1)


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
        # Pre-define for testing
        
        a = 2096063111482034634871195989807309328265843179706171265144426621022737032073232422517537093859647865723443141684375998686047694354958763848289158947898085531416747174809274828926854033528442623133875506216927195156294008923013148984660143001662476520756816953628838650976083963602656859567462039279342104634417
        p = 1615872714573308946629922042462077189800529770664142227639386578251879870405238823567559074128067058617906808093896839251278162433377526307816292702280079149546772760725962207116054797517266445200239104588777226590038452294585547980259343063163992449489503726189892609447878286258912394156380378291430577232827
        public_key = 319629524486650374100658549931811077534035884870468782347588473927851101763825607828758162500411338670506305610094331921484866580921501159646292434093827756999214502745813678106029936651869614241160393240005642996225174952249981850822350378940347933147284226156385836970958027627728001473429306686543092770987
        g_b = 486530448846712694531516714088653773521502416936135258121272091248177843511866832784938544534898267217149577829176756569605823966475189314504597828099394192623097977045243859795802524311947584142208038008176139515280245712746923500452165715267300223884282952025698550237062042948062245839010260375208414908751
        
        
        # calculate shared key from g_b 
        shared_key_g_ab = self.fast_modular_exponentiation(g_b, a, p)

        print(f'shared key from g^b: {shared_key_g_ab}')
        shared_key_g_ab = (shared_key_g_ab).to_bytes((shared_key_g_ab.bit_length() + 7) // 8, byteorder='big', signed=False)

        
        hashed = hashlib.sha256(shared_key_g_ab).hexdigest()
        #print(shared_key_g_ab)

        # using the first 16 bytes (128-bits) of the digest.
        hashed = hashed[:32]

        hashed = bytes.fromhex(hashed)

        # from server
        iv = "07e68e430cbbe98fcd8dce3d15f2d1bc"
        cipherText = "086d68cc22ba3dda516a5413100d1295f2ac980020388c005b3b21ed27b9164a131df4fe93a31163ba1c3100f28e12e3b8c9a4defa1c7f7a7f365f4672abf880"

        iv = bytes.fromhex(iv)
        cipherText = bytes.fromhex(cipherText)

        de_cipher = AES.new(hashed, AES.MODE_CBC, iv)
        plaintext = unpad(de_cipher.decrypt(cipherText), AES.block_size)
        print("---")
        print(plaintext.decode('ASCII'))

    #part 4
    def gcd(self, a, b):
        while b != 0:
            a, b = b, a % b
        return a
    def is_coprime(self, a, b):
        '''
            Find relatively prime to e = 65537
        '''
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
        n = 24390768926525385002502968247087879787379353211590061746648937364964992720131117453700305056356506058989477985783691680789351102851989781085616512431122681312564844722646914757672034013108498628959165278803816425459461346579708768690180197976306222625918511089468404061338455174186685960496997854781747921243922223840562926552996454008107124981150020956997923745095184438896651928112414196578576691134227400336538126270228549031197812426729101638150056192376018780921777678346388529166838048748155579127926450035201551605287736133516964188453726210816503006240165278767563377177283717952294806447141520901300223815843
        
        c_mesg = self.fast_modular_exponentiation(encrypt_message, self.e, n)
        print(f"Encrypted message: {c_mesg}")
    
    def decrypt(self):   

        # change this
        given = 3817887159248775637833380431740420574433178619604897851525815537997743832008252226952100489260733250578092360269592841090296221265872953361742078119274296919105911156729677455932230206718842167068296842311301251861680393607678056025927732106697123313728488437056329842905956725091495274574265481036236972190175207776162188740366015587451912374304000570625113651220368838931466557856598519347087330119897307073616449418049611617227806541929726087722827389734823614261852703863983454714007688746610234392572122894832468597494498325556004307778529078324208211541136274767851409327367827662203489809279861100310352431841
        
        
        d = 8797305276183027155487208194221024801472041003029828639810909584403352273043614360904036054780583337998280065122829912118325241759850686563342892119670994108158869029005413293892786364982508973424733339340595582114084369294461996647671994747454514097860167006925158844651393921104488803793704858192028279633740480425495055700210736921436118465404305094026631698776360074739380869390932830892110605953778388064795020142846389043641237762350503797944972650944849590351865153529854157133280612721240640600310529478794358400753372863468255716235233938691362163736140855077993927888579859244993442979576599774006630853713
        n = 24390768926525385002502968247087879787379353211590061746648937364964992720131117453700305056356506058989477985783691680789351102851989781085616512431122681312564844722646914757672034013108498628959165278803816425459461346579708768690180197976306222625918511089468404061338455174186685960496997854781747921243922223840562926552996454008107124981150020956997923745095184438896651928112414196578576691134227400336538126270228549031197812426729101638150056192376018780921777678346388529166838048748155579127926450035201551605287736133516964188453726210816503006240165278767563377177283717952294806447141520901300223815843
        show_ma = hex(self.fast_modular_exponentiation(given, d, n))

        b = bytes.fromhex(show_ma[2:])
        print(b.decode("ASCII"))

if __name__ == "__main__":
    p = Public_key()

    
    # Test fast modular exponentiation function with value from slides
    t = p.fast_modular_exponentiation(4235880211405804673, 131, 12855544647099734480) # result = 1442355666387997457

        
    p.diffie_hellman(5)
    #p.solve(5)
    #p.find_RSA_parameter()
    #p.encrypt('overimitative')
    #p.decrypt()