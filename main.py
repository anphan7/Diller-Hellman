'''
    Name: An Phan
    Project 4: Public-key cryptography
'''
import random
import os
from random import getrandbits
class Public_key:

    def __init__(self):
        pass
    def generate_prime(self, size):
    
        # generate random bits
        p = getrandbits(size)
        p |= (1 << size - 1) | 1
        return p
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

    # part 3
    def diffie_hellman(self):
        p = self.generate_prime(128)
        while not self.miller_rabin(p, 128):
            p += 1
        


        print(p)

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
    p.diffie_hellman()