from test import generate_large_prime


def mod_exp(g, s, p):
    # g^s%p
    number = 1
    while s:
        if s & 1:
            number = number * g % p
        s >>= 1
        g = g * g % p
    return number


def main():
    g = 5
    s = generate_large_prime(1024)
    print(s)
    #s = 1864744265515534340146922122742135479182019882426474833969776864823174284072620404264501522179633932413589396266795661127698658893905791370291795120689
    p = generate_large_prime(1024)
    #p = 3210878991512708756290816276823920453621107781879145816001281137411276548049727212877831098348397745925933874686685749897265019441661180859124477212827
    moded = mod_exp(g, s, p)

    print('s = {}\np = {}\nmoded = {}'.format(s, p, moded))

if __name__ == "__main__":
    main()