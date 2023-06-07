'''
GIFT-128-128 implementation
Date: 07 June 2023
Done by: Ray Beecham

Last modification on: 01 November 2017
'''
# Importing libraries which will be used for generating random numbers and seeding the random number generator
import random
import time

# S-Boxes GIFT_S and GIFT_S_inv are defined, which are lookup tables used for substitution in the GIFT algorithm
GIFT_S = [1, 10, 4, 12, 6, 15, 3, 9, 2, 13, 11, 7, 5, 0, 8, 14]
GIFT_S_inv = [13, 0, 8, 6, 2, 12, 4, 11, 14, 7, 1, 10, 3, 9, 15, 5]

# Bit Permutation tables GIFT_P and GIFT_P_inv are defined, which are lookup tables used for permutation in the GIFT algorithm
GIFT_P = [
    # Block size = 128 bits
    0, 33, 66, 99, 96,  1, 34, 67, 64, 97,  2, 35, 32, 65, 98,  3,
    4, 37, 70,103,100,  5, 38, 71, 68,101,  6, 39, 36, 69,102,  7,
    8, 41, 74,107,104,  9, 42, 75, 72,105, 10, 43, 40, 73,106, 11,
    12, 45, 78,111,108, 13, 46, 79, 76,109, 14, 47, 44, 77,110, 15,
    16, 49, 82,115,112, 17, 50, 83, 80,113, 18, 51, 48, 81,114, 19,
    20, 53, 86,119,116, 21, 54, 87, 84,117, 22, 55, 52, 85,118, 23,
    24, 57, 90,123,120, 25, 58, 91, 88,121, 26, 59, 56, 89,122, 27,
    28, 61, 94,127,124, 29, 62, 95, 92,125, 30, 63, 60, 93,126, 31
]
print(len(GIFT_P))

GIFT_P_inv = [
    # Block size = 128 bits
    0, 5, 10, 15, 16, 21, 26, 31, 32, 37, 42, 47, 48, 53, 58, 63,
    64, 69, 74, 79, 80, 85, 90, 95, 96, 101, 106, 111, 112, 117, 122, 127,
    12, 1, 6, 11, 28, 17, 22, 27, 44, 33, 38, 43, 60, 49, 54, 59,
    76, 65, 70, 75, 92, 81, 86, 91, 108, 97, 102, 107, 124, 113, 118, 123,
    8, 13, 2, 7, 24, 29, 18, 23, 40, 45, 34, 39, 56, 61, 50, 55,
    72, 77, 66, 71, 88, 93, 82, 87, 104, 109, 98, 103, 120, 125, 114, 119,
    4, 9, 14, 3, 20, 25, 30, 19, 36, 41, 46, 35, 52, 57, 62, 51,
    68, 73, 78, 67, 84, 89, 94, 83, 100, 105, 110, 99, 116, 121, 126, 115
]

# Round constants GIFT_RC are defined. These constants are used during the key expansion process.
# The first row is the identity permutation, which is the same as the first row of the s-box of GIFT. The second row is the inverse of the first row and so on.
GIFT_RC = [
    0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F,
    0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B,
    0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E,
    0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A,
    0x34, 0x29, 0x12, 0x24, 0x08, 0x11, 0x22, 0x04, 0x09, 0x13,
    0x26, 0x0c, 0x19, 0x32, 0x25, 0x0a, 0x15, 0x2a, 0x14, 0x28,
    0x10, 0x20
]

# Define the main function, which serves as the entry point of the program.
def main():
    random.seed(time.time())  # Seed the random number generator with the current time

    P = [random.randint(0, 15) for _ in range(32)]  # Generate a random plaintext of 128 bits
    K = [random.randint(0, 15) for _ in range(32)]  # Generate a random key of 128 bits

    # Print the plaintext and key in hexadecimal format
    print("Plaintext = ", end="")
    for i in range(32):
        print(f"{P[31-i]:x}", end="")
        if i % 2 == 1:  # Print a space after every 2 hexadecimal digits
            print(" ", end="")
    print()

    # Print the key in hexadecimal format
    print("masterkey = ", end="")
    for i in range(32):
        print(f"{K[31-i]:x}", end="")
        if i % 2 == 1:
            print(" ", end="")
    print("\n")

    enc128(P, K, 40, True)  # Encrypt the plaintext

    # Print the ciphertext in hexadecimal format
    print("Ciphertext = ", end="")
    for i in range(16):
        print(f"{P[15-i]:x}", end="")
        if i % 2 == 1:
            print(" ", end="")
    print("\n")

    dec128(P, K, 40, True)  # Decrypt the ciphertext

    # Print the plaintext in hexadecimal format
    print("Plaintext = ", end="")
    for i in range(16):
        print(f"{P[15-i]:x}", end="")
        if i % 2 == 1:
            print(" ", end="")
    print()

# The 'enc128() function is called with the provided arguments ('P', 'K', '40', True) to encrypt the plaintext using GIFT. The '40' specifies the number of rounds to be performed
# in the encryption process. The 'True' specifies that the details of the encryption process should be printed.
def enc128(input, masterkey, no_of_rounds, print_details):
    print("----------\nEncryption...\n----------")

    key = masterkey[:]

    # input = MSB [15][14]...[1][0] LSB
    # key = MSB [31][30]...[1][0] LSB
    if print_details:
        print("input = ", end="")
        for i in range(32):
            print(f"{input[31-i]:x}", end="")
            if i % 2 == 1:
                print(" ", end="")

        print("\nkey = ", end="")
        for i in range(32):
            print(f"{key[31-i]:x}", end="")
            if i % 2 == 1:
                print(" ", end="")
        print("\n")

    bits = [0] * 128
    perm_bits = [0] * 128
    key_bits = [0] * 128
    temp_key = [0] * 32

    for r in range(no_of_rounds):

        # SubCells
        for i in range(32):
            input[i] = GIFT_S[input[i]]

        if print_details:
            print(f"{r:02d}: after SubCells: ", end="")
            for i in range(32):
                print(f"{input[31-i]:x}", end="")
                if i % 2 == 1:
                    print(" ", end="")
            print()

        # PermBits
        # input to bits
        for i in range(32):
            for j in range(4):
                bits[4 * i + j] = (input[i] >> j) & 0x1

        # permute the bits
        print(max(GIFT_P))

        for i in range(128):
            perm_bits[GIFT_P[i]] = bits[i]

        # perm_bits to input
        for i in range(32):
            input[i] = 0
            for j in range(4):
                input[i] ^= perm_bits[4 * i + j] << j

        # key to key_bits
        if print_details:
            print(f"{r:02d}: after PermBits: ", end="")
            for i in range(32):
                print(f"{input[31-i]:x}", end="")
                if i % 2 == 1:
                    print(" ", end="")
            print()

        # AddRoundKey
        # input to bits
        for i in range(32):
            for j in range(4):
                bits[4 * i + j] = (input[i] >> j) & 0x1

        # key to key_bits
        for i in range(32):
            for j in range(4):
                key_bits[4 * i + j] = (key[i] >> j) & 0x1

        # add round key
        kbc = 0  # key_bit_counter
        for i in range(32):
            bits[4 * i] ^= key_bits[kbc]
            bits[4 * i + 1] ^= key_bits[kbc + 64]
            kbc += 1

        # add constant
        bits[3] ^= GIFT_RC[r] & 0x1
        bits[7] ^= (GIFT_RC[r] >> 1) & 0x1
        bits[11] ^= (GIFT_RC[r] >> 2) & 0x1
        bits[15] ^= (GIFT_RC[r] >> 3) & 0x1
        bits[19] ^= (GIFT_RC[r] >> 4) & 0x1
        bits[23] ^= (GIFT_RC[r] >> 5) & 0x1
        bits[63] ^= 1

        # bits to input
        for i in range(32):
            input[i] = 0
            for j in range(4):
                input[i] ^= bits[4 * i + j] << j

        if print_details:
            print(f"{r:02d}: after AddRoundKeys: ", end="")
            for i in range(32):
                print(f"{input[31-i]:x}", end="")
                if i % 2 == 1:
                    print(" ", end="")
            print()

        # key update
        # entire key>>32
        for i in range(32):
            temp_key[i] = key[(i + 8) % 32]
        for i in range(24):
            key[i] = temp_key[i]
        # k0>>12
        key[24] = temp_key[27]
        key[25] = temp_key[24]
        key[26] = temp_key[25]
        key[27] = temp_key[26]
        # k1>>2
        key[28] = ((temp_key[28] & 0xc) >> 2) | ((temp_key[29] & 0x3) << 2)
        key[29] = ((temp_key[29] & 0xc) >> 2) | ((temp_key[30] & 0x3) << 2)
        key[30] = ((temp_key[30] & 0xc) >> 2) | ((temp_key[31] & 0x3) << 2)
        key[31] = ((temp_key[31] & 0xc) >> 2) | ((temp_key[28] & 0x3) << 2)

        if print_details:
            print(f"{r:02d}: updated Key: ", end="")
            for i in range(32):
                print(f"{key[31-i]:x}", end="")
                if i % 2 == 1:
                    print(" ", end="")
            print("\n")

    if print_details:
        print("input = ", end="")
        for i in range(32):
            print(f"{input[31-i]:x}", end="")
            if i % 2 == 1:
                print(" ", end="")
        print("\nkey = ", end="")
        for i in range(32):
            print(f"{key[31-i]:x}", end="")
            print(f"{key[31-i]:x}", end="")
            if i % 2 == 1:
                print(" ", end="")
        print("\n")

    return

# The 'dec128()' function is called with the same arguments to decrypt the ciphertext back to the original plaintext.
def dec128(input, masterkey, no_of_rounds, print_details):
    print("----------\nDecryption...\n----------")

    key = masterkey[:]

    if print_details:
        print("input = ", end="")
        for i in range(32):
            print(f"{input[31-i]:x}", end="")
            if i % 2 == 1:
                print(" ", end="")
        print("\nkey = ", end="")
        for i in range(32):
            print(f"{key[31-i]:x}", end="")
            if i % 2 == 1:
                print(" ", end="")
        print("\n")

    # compute and store the round keys
    round_key_state = [[0] * 32 for _ in range(no_of_rounds)]
    bits = [0] * 128
    perm_bits = [0] * 128
    key_bits = [0] * 128
    temp_key = [0] * 32
    for r in range(no_of_rounds):
        # copy the key state
        for i in range(32):
            round_key_state[r][i] = key[i]

        # key update
        for i in range(32):
            temp_key[i] = key[(i + 8) % 32]
        for i in range(24):
            key[i] = temp_key[i]
        key[24] = temp_key[27]
        key[25] = temp_key[24]
        key[26] = temp_key[25]
        key[27] = temp_key[26]
        key[28] = ((temp_key[28] & 0xc) >> 2) ^ ((temp_key[29] & 0x3) << 2)
        key[29] = ((temp_key[29] & 0xc) >> 2) ^ ((temp_key[30] & 0x3) << 2)
        key[30] = ((temp_key[30] & 0xc) >> 2) ^ ((temp_key[31] & 0x3) << 2)
        key[31] = ((temp_key[31] & 0xc) >> 2) ^ ((temp_key[28] & 0x3) << 2)

    for r in range(no_of_rounds - 1, -1, -1):
        # AddRoundKey
        # input to bits
        for i in range(32):
            for j in range(4):
                bits[4 * i + j] = (input[i] >> j) & 0x1

        # key to key_bits
        for i in range(32):
            for j in range(4):
                key_bits[4 * i + j] = (round_key_state[r][i] >> j) & 0x1

        # add round key
        kbc = 0
        for i in range(32):
            bits[4 * i] ^= key_bits[kbc]
            bits[4 * i + 1] ^= key_bits[kbc + 64]
            kbc += 1

        # add round constant
        bits[3] ^= GIFT_RC[r] & 0x1
        bits[7] ^= (GIFT_RC[r] >> 1) & 0x1
        bits[11] ^= (GIFT_RC[r] >> 2) & 0x1
        bits[15] ^= (GIFT_RC[r] >> 3) & 0x1
        bits[19] ^= (GIFT_RC[r] >> 4) & 0x1
        bits[23] ^= (GIFT_RC[r] >> 5) & 0x1
        bits[63] ^= 1

        # bits to input
        for i in range(32):
            input[i] = 0
            for j in range(4):
                input[i] ^= bits[4 * i + j] << j

        if print_details:
            print(f"{r:02d}: after inverse AddRoundKeys: ", end="")
            for i in range(32):
                print(f"{input[31-i]:x}", end="")
                if i % 2 == 1:
                    print(" ", end="")
            print()

        # PermBits
        # input to bits
        for i in range(32):
            for j in range(4):
                bits[4 * i + j] = (input[i] >> j) & 0x1

        # permute the bits
        for i in range(128):
            perm_bits[GIFT_P_inv[i]] = bits[i]

        # perm_bits to input
        for i in range(32):
            input[i] = 0
            for j in range(4):
                input[i] ^= perm_bits[4 * i + j] << j

        if print_details:
            print(f"{r:02d}: after inverse PermBits: ", end="")
            for i in range(32):
                print(f"{input[31-i]:x}", end="")
                if i % 2 == 1:
                    print(" ", end="")
            print()

        # SubCells
        for i in range(32):
            input[i] = GIFT_S_inv[input[i]]

        if print_details:
            print(f"{r:02d}: after inverse SubCells: ", end="")
            for i in range(32):
                print(f"{input[31-i]:x}", end="")
                if i % 2 == 1:
                    print(" ", end="")
            print("\n")

    if print_details:
        print("input = ", end="")
        for i in range(32):
            print(f"{input[31-i]:x}", end="")
            if i % 2 == 1:
                print(" ", end="")
        print("\n")

    return

# The 'main()' function is called when the program is run from the command line with arguments.
if __name__ == "__main__":
    main()

''' The 'enc128()' and dec128()' functions implement the GIFT encryption and decryption algorithms, respectively. They take the input, master key, number of rounds, and a boolean
 flag for printing details as arguments. '''
