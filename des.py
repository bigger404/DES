# Initial Permutation Matrix
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Inverse Permutation Matrix
InvP = [40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25]

#Permutation made after each SBox substitution
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

# Initial permutation on key
PC_1 = [57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4]

# Permutation applied after shifting key (i.e gets Ki+1)
PC_2 = [14, 17, 11, 24, 1, 5, 3, 28,
        15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56,
        34, 53, 46, 42, 50, 36, 29, 32]

# Expand matrix to obtain 48bit matrix
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# SBOX represented as a three dimentional matrix
# --> SBOX[block][row][column]
SBOX = [        
[
 [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
 [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
 [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
 [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
],
[
 [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
 [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
 [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
 [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
],
[
 [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
 [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
 [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
 [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
],
[
 [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
 [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
 [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
 [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
],  
[
 [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
 [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
 [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
 [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
], 
[
 [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
 [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
 [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
 [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
], 

[[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
 [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
 [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
 [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
],
[
 [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
 [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
 [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
 [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]
]

# Shift Matrix for each round of keys
SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

def str_to_bitarray(s):
    # Converts string to a bit array.
    bitarr = list()
    for byte in s:                                  #convert every byte in s
        bits = bits_to_str(byte, 8)                 #single byte as bits
        l2=list()                                   #temp list
        for bit in bits:                            #get bits
            l2.append(int(bit))                     #put them in the list
        bitarr.extend(list(l2))                     #append to the return 
    return bitarr

def bits_to_str(data,size):                         #return a string of binary bits
    bitstr=bin(data)[2:] if isinstance(data, int) else bin(ord(data))[2:]
    while len(bitstr)<size:
        bitstr="0"+bitstr                           #pad return string to size
    return bitstr

def bitarray_to_str(bitArr):
    # Converts bit array to string
    bitstr=''.join([chr(int(i,2)) for i in [''.join([str(j) for j in bytes]) for bytes in splitby(bitArr,8)]])   
    return bitstr

def splitby(block, size):                           #split up a block by size
    return [block[loc:loc+size] for loc in range(0, len(block), size)]

class DES():
    def __init__(self):
        self.password = None
        self.plaintext = None
        self.keylist = list()

    def left_shift(self, a, b, round_num):
        # Shifts a list based on a round number
        num_shift = SHIFT[round_num]
        ### YOUR CODE HERE ###                      #basic slicing to get shift left by num_shift
        return a[num_shift:] + a[:num_shift], b[num_shift:] + b[:num_shift]
    
    def createKeys(self):
        # This functions creates the keys and stores them in keylist.
        # These keys should be generated using the password.
        ### YOUR CODE HERE ###
        #print("create those keys..")
        self.keylist = []                           #clear the keylist
        key = str_to_bitarray(self.password)        #convert the password to bits
        key = self.permute(key, PC_1)               #first permutation with PC_1
        left, right = splitby(key,28)               #split into left and right sides
        for k in range(16):                         #create the 16 keys
            left, right = self.left_shift(left, right, k)#shift using SHIFT table
            self.keylist.append(self.permute((left+right),PC_2))#join, permute, and save this key

    def XOR(self, a, b):
        # xor function - This function is complete
        return [i^j for i,j in zip(a,b)]

    def performRounds(self, text):
        # This function is used by the encrypt and decypt functions.
        # keys - A list of keys used in the rounds
        # text - The orginal text that is converted.
        ### YOUR CODE HERE ###
        blocks = splitby(text, 8)                   #split text into 8byte blocks
        output = list()                             #place to store some output
        for block in blocks:                        #process each block
            block = str_to_bitarray(block)          #convert this block to a bit array
            block = self.permute(block,IP)          #first permutation
            left, right = splitby(block, 32)        #split left and right halves
            tmp=None                                #place to store the right side
            for rnd in range(16):                   #do the 16 rounds
                expanded = self.permute(right, E)   #expand the right side for substitution
                tmp=self.XOR(self.keylist[rnd], expanded)#xor agaist the key for this round
                tmp=self.sbox_substition(tmp)       #do the sbox subtitution
                tmp=self.permute(tmp, P)            #permute
                tmp=self.XOR(left, tmp)             #xor against the left
                left=right                          #swap sides
                right=tmp                           #now save the processed stuff in the right
            swapandinv=self.permute(right+left,InvP)#32 bit swap and inverse permutation
            output+=swapandinv                      #append this block to the output
        processed=bitarray_to_str(output)           #convert to string before returning
        return processed


    def permute(self, bits, table):
        # Use table to permute the bits
        ### YOUR CODE HERE ###
        return [bits[loc-1] for loc in table]       #returns a permutation of bits using table

    def sbox_substition(self, bits):                #weird choice of names...but ok..
        # Apply sbox subsitution on the bits
        ### YOUR CODE HERE ###
        substitution = list()                       #place to store the substition
        blocks = splitby(bits, 6)                   #get blocks of 6 bits
        for i in range(len(blocks)):                #process each block
            block = blocks[i]                       #single block
            row = int(str(block[0])+str(block[5]),2)#first and last is the row
            column = int(''.join([str(bit) for bit in block[1:][:-1]]),2) #middle gives the column
            sval = SBOX[i][row][column]             #get the substitute value
            newbits = bits_to_str(sval, 4)          #new bits to insert
            temp=list()                             #place to store some bits
            for bit in newbits:                     #get all of the newbits
                temp.append(int(bit))               #make ints and put them in the list
            substitution += temp                    #append it
        return substitution                         #return it

    def encrypt(self, key, plaintext):
        # Calls the performrounds function.
        ### YOUR CODE HERE ###
        self.password = key                         #assign the key to the object 
        self.plaintext = plaintext                  #assign the text
        self.createKeys()                           #create the keylist
        return self.performRounds(self.plaintext)   #do it..

    def decrypt(self, key, ciphertext):
        # Calls the performrounds function.
        ### YOUR CODE HERE ###
        self.password = key                         #assign the key to the object
        self.createKeys()                           #create the keylist
        self.keylist.reverse()                      #reverse the keylist for decryption
        return self.performRounds(ciphertext)       #do it..


if __name__ == '__main__':
    key = "blahblah"
    plaintext= "Hi world"
    des = DES()
    ciphertext = des.encrypt(key,plaintext)
    text = des.decrypt(key,ciphertext)
    print(ciphertext)
    print(text)
