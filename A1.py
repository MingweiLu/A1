# A1.py
# Mingwei Lu - Frequency
# Kiana Liu - Find key given length
# Zihan Su - Decryption and Encryption

import binascii

mapTable = [[0x2, 0x3, 0x1, 0x0, 0x8, 0x9, 0xb, 0xa, 0xe, 0xf, 0xd, 0xc, 0x4, 0x5, 0x7, 0x6 ],
    [0x9, 0xb, 0xa, 0xe, 0xf, 0xd, 0xc, 0x4, 0x5, 0x7, 0x6, 0x2, 0x3, 0x1, 0x0, 0x8 ],
    [0xb, 0xa, 0xe, 0xf, 0xd, 0xc, 0x4, 0x5, 0x7, 0x6, 0x2, 0x3, 0x1, 0x0, 0x8, 0x9 ],
    [0x8, 0x9, 0xb, 0xa, 0xe, 0xf, 0xd, 0xc, 0x4, 0x5, 0x7, 0x6, 0x2, 0x3, 0x1, 0x0 ],
    [0xe, 0xf, 0xd, 0xc, 0x4, 0x5, 0x7, 0x6, 0x2, 0x3, 0x1, 0x0, 0x8, 0x9, 0xb, 0xa ],
    [0xf, 0xd, 0xc, 0x4, 0x5, 0x7, 0x6, 0x2, 0x3, 0x1, 0x0, 0x8, 0x9, 0xb, 0xa, 0xe ],
    [0xd, 0xc, 0x4, 0x5, 0x7, 0x6, 0x2, 0x3, 0x1, 0x0, 0x8, 0x9, 0xb, 0xa, 0xe, 0xf ],
    [0xc, 0x4, 0x5, 0x7, 0x6, 0x2, 0x3, 0x1, 0x0, 0x8, 0x9, 0xb, 0xa, 0xe, 0xf, 0xd ],
    [0xa, 0xe, 0xf, 0xd, 0xc, 0x4, 0x5, 0x7, 0x6, 0x2, 0x3, 0x1, 0x0, 0x8, 0x9, 0xb ],
    [0x5, 0x7, 0x6, 0x2, 0x3, 0x1, 0x0, 0x8, 0x9, 0xb, 0xa, 0xe, 0xf, 0xd, 0xc, 0x4 ],
    [0x7, 0x6, 0x2, 0x3, 0x1, 0x0, 0x8, 0x9, 0xb, 0xa, 0xe, 0xf, 0xd, 0xc, 0x4, 0x5 ],
    [0x6, 0x2, 0x3, 0x1, 0x0, 0x8, 0x9, 0xb, 0xa, 0xe, 0xf, 0xd, 0xc, 0x4, 0x5, 0x7 ],
    [0x4, 0x5, 0x7, 0x6, 0x2, 0x3, 0x1, 0x0, 0x8, 0x9, 0xb, 0xa, 0xe, 0xf, 0xd, 0xc ],
    [0x3, 0x1, 0x0, 0x8, 0x9, 0xb, 0xa, 0xe, 0xf, 0xd, 0xc, 0x4, 0x5, 0x7, 0x6, 0x2 ],
    [0x1, 0x0, 0x8, 0x9, 0xb, 0xa, 0xe, 0xf, 0xd, 0xc, 0x4, 0x5, 0x7, 0x6, 0x2, 0x3 ],
    [0x0, 0x8, 0x9, 0xb, 0xa, 0xe, 0xf, 0xd, 0xc, 0x4, 0x5, 0x7, 0x6, 0x2, 0x3, 0x1 ]
]


def getColumn(mapTable, col):
    # https://stackoverflow.com/questions/903853/how-do-you-extract-a-column-from-a-multi-dimensional-array
    return [hex(row[col]) for row in mapTable]

def getRow(mapTable, row):
    return [hex(letter) for letter in mapTable[row]]

# restriction: row number 0-7
def validatePh(validRowList):
    for i in range(8, 17):
        if i in validRowList:
            validRowList.remove(i)

# restriction: col number 2-7
def validateKh(validColList):
    for i in range(2):
        if i in validColList:
            validColList.remove(i)

    for i in range(8, 17):
        if i in validColList:
            validColList.remove(i)

def getCoordinateHigh(mapTable, hvalue):
    result = []
    for i in range(len(mapTable)):
        for j in range(len(mapTable)):
            if hex(mapTable[i][j]) == hvalue and 0<=i<=7 and 2<=j<=7: #check restrictions
                result.append([i,j])
    return result

def getCoordinateLow(mapTable, lvalue):
    result = []
    for i in range(len(mapTable)):
        for j in range(len(mapTable)):
            if hex(mapTable[i][j]) == lvalue: #check restrictions
                result.append([i,j])
    return result

# https://www.geeksforgeeks.org/python-intersection-two-lists/
def intersection(lst1, lst2):
    lst3 = [value for value in lst1 if value in lst2]
    return lst3
    


def keyFinder(keyLength, cipherText):
    # Creating lists for letters with the same xMod(len(keyLength))
    modDic = {}
    for i in range(len(cipherText)):
        x = i % keyLength
        if x not in  modDic:
            modDic[x] = []
        # https://stackoverflow.com/questions/606191/convert-bytes-to-a-string
        modDic[x].append(cipherText[i].decode("utf-8") )
    # After this loop, each dic[x] should contain letters index%keyLength = x
    print("mod: ", modDic[0])

    key = []
    for index, wordList in modDic.items():
        validKeyLetter = []
        counter = 0
        for letter in wordList:
            ch = hex(int("0x"+letter[0],16))
            cl = hex(int("0x"+letter[1],16))

            hList = getCoordinateHigh(mapTable, ch) #(ph,kh)
            #print("hList: ",hList)
            lList = getCoordinateLow(mapTable, cl) #(pl,kl)
            #print("lList: ",lList)

            #allPosP = [(x[0],y[0]) for x in hList for y in lList]
            allPosKey = [(x[1],y[1]) for x in hList for y in lList]
            #print("K: ", allPosKey)

            
            if counter == 0:
                validKeyLetter = allPosKey
            else:
                #if len(intersection(validKeyLetter,allPosKey)) == 0:
                    #print(validKeyLetter)
                    #print(ch, cl)
                validKeyLetter = intersection(validKeyLetter,allPosKey)
                #print(allPosKey)
                #print("HI:",index,  validKeyLetter)
            counter += 1
        print("Valid: ", validKeyLetter)



    # validColListKh = []
    # validColListKl = []
    # validRowListPh = []
    # for index, wordList in modDic.items():
    #     isValidColKh = True
    #     isValidColKl = True
    #     isValidRowPh = True
    #     for col in range(len(mapTable)):
    #         colList = getColumn(mapTable, col)
    #         rowList = getRow(mapTable, col)
    #         print("Row List: ", rowList)
    #         for letter in wordList:
    #             # Trying to split letter into 2 bytes
    #             # https://stackoverflow.com/questions/8088375/how-do-i-convert-a-single-character-into-its-hex-ascii-value-in-python/8088383
    #             ch = hex(int("0x"+letter[0],16))
    #             cl = hex(int("0x"+letter[1],16))
    #             print("index:", index, "ch: ", ch, "cl: ", cl)
    #             #print(colList)
    #             # mapTable[][col] doesn't contain letter --> invalid
    #             if ch not in colList:
    #                 isValidColKh = False
    #             if ch not in rowList:
    #                 isValidRowPh = False

    #             if cl not in colList:
    #                 isValidColKl = False
    #         if isValidColKh:
    #             # col is valid so far
    #             # note: if index is not 0 but col is valid, it means that this col does not fit bucket 0, hence invalid 
    #             if index == 0:
    #                 validColListKh.append(col)
    #         else:
    #             if col in validColListKh:
    #                 validColListKh.remove(col)
            
    #         if isValidRowPh:
    #             # col is valid so far
    #             # note: if index is not 0 but col is valid, it means that this col does not fit bucket 0, hence invalid 
    #             if index == 0:
    #                 validRowListPh.append(col)
    #                 print("Success")
    #         else:
    #             if col in validRowListPh:
    #                 validRowListPh.remove(col)
    #                 print("removed")
    #         validatePh(validRowListPh) 
    #         validateKh(validColListKh)
    # print("validColListKh: ", validColListKh)
    # print("validRowListPh: ", validRowListPh)
    

# https://stackoverflow.com/questions/3964245/convert-file-to-hex-string-python           
def convertBinaryFilesToHex():
    filename = 'ciphertext1'
    with open(filename, 'rb') as f:
        content = f.read()
    return binascii.hexlify(content)

def main():
    # f = open("ciphertext1", "rb")
    # keyFinder(7, f.read())
    cipher = convertBinaryFilesToHex()
    #print(cipher)
    # https://stackoverflow.com/questions/20024490/how-to-split-a-byte-string-into-separate-bytes-in-python
    hexlist = [cipher[i:i+2] for i in range(0, len(cipher), 2)]
    #print(hexlist)
    keyFinder(7, hexlist)


if __name__ == "__main__":
    main()
