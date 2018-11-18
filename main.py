from Crypto.Cipher import AES
key = b'0123456789012345'
inputString = raw_input("Input string to be encrypted:")
cipher = AES.new(key, AES.MODE_ECB)
message = [inputString[i:i+16] for i in range(0, len(inputString), 16)]
encryption = []
for input in message:
    temp = cipher.encrypt(input)
    encryption.append(temp)
    print temp
decryption = []
for encrypt in encryption:
    temp = cipher.decrypt(encrypt)
    decryption.append(temp)
    print temp
