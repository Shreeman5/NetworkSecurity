from socket import *
from OpenSSL import crypto
from Crypto.PublicKey import RSA
import uuid
from Crypto.Cipher import PKCS1_OAEP
import ast
import hashlib
from Crypto.Cipher import AES


def create_certificate_and_RSA_key_pair():
    # Generate RSA key pair to sign the certificate with
    RSA_key_pair = crypto.PKey()
    RSA_key_pair.generate_key(crypto.TYPE_RSA, 2048)
    
    # Self-signed certificate X509
    certificate = crypto.X509()
    # get issuer of the certificate
    certificate.get_issuer().commonName = "Bob" 
    # mainly here so that there is no certificate loading error on Alice's end
    certificate.gmtime_adj_notBefore(0)
    certificate.gmtime_adj_notAfter(50)
    # set public key of certificate to the RSA public key
    certificate.set_pubkey(RSA_key_pair) 
    # sign the certificate using the RSA key pair and the integrity protection algorithm
    certificate.sign(RSA_key_pair, "sha256") 
    
    return certificate, RSA_key_pair
    

# Compute Hash of K, first_message_from_alice, message_2 and "CLIENT"/"CORRUPT"
# If "CORRUPT", exit handhsake.
# If "CLIENT", proceed with hanshake.
def compute_hash_of_received_stuff_and_verify_alice(K, first_message_from_alice, message_2, alice_hash):
    
    keyed_hash_function = hashlib.sha1()
    keyed_hash_function.update(K.encode())
    keyed_hash_function.update(first_message_from_alice)
    keyed_hash_function.update(message_2)
    keyed_hash_function.update("CLIENT".encode())
    
    print('1: Bob will find the keyed hash function, which is a digest of K, message 1, message 2 and "CLIENT"/"CORRUPT"')
    print('2: Bob just generated K, he knows message 1 and message 2 and he can generate a string "CLIENT"/"CORRUPT"')
    print('3: Bob will know do a hash on his end by using K, message 1, message 2 and "CLIENT"/"CORRUPT"')
    print('4: If the hash that Bob generated matches the hash that Alice sent, Alice has been fully authenticated to Bob')
    print()
    if alice_hash.decode('utf8') == keyed_hash_function.hexdigest():
        print("Since the hashes match, this is Alice. Alice has been fully authenticated to Bob.")
        print()
        return "SERVER"
    else:
        print('Since the hashes do not match, this is not Alice. OR, Alice sent a "CORRUPT" string. Exit handshake.')
        exit()
    


def main():
    # Waiting for  Alice, once she arrives, start the program.
    port_server = 8000
    socket_bob = socket(AF_INET, SOCK_STREAM)
    socket_bob.bind(("", port_server))
    socket_bob.listen(1)
    number = 1

    while 1:
        # Connection with Alice and receiving the first message.
        connection_socket, addr = socket_bob.accept()
        first_message_from_alice = connection_socket.recv(1024)
        print('Bob has received the first message from Alice, which contains a certificate signed by the public key of Alice(K_a),'
              ' supported encryption algorithm which is AES, supported integrity protection algorithm which is sha256,'
              ' and R_Alice')
        
        # decoding the first message from Alice
        # converting the certificate in bytes to the actual certificate
        certificate_from_Alice = crypto.load_certificate(crypto.FILETYPE_PEM, first_message_from_alice[0:-18])
        # Verifying whether this is Alice. If not, exit.
        if certificate_from_Alice.get_issuer().commonName == "Alice":
            print("By checking the certificate and who it is signed by, Bob determines that this is Alice")
        else:
            print("By checking the certificate and who it is signed by, Bob determines that this is not Alice")
            exit()
        # If it is Alice, decoding her encryption algorithm
        encryption_chosen_by_Alice = first_message_from_alice[-18:-14].decode('utf8')
        print('Bob decodes the supported encryption algorithm(non-negotiable) to be:', encryption_chosen_by_Alice)
        # If it is Alice, decoding her integrity protection algorithm
        integrity_protection_chosen_by_Alice = first_message_from_alice[-14:-8].decode('utf8')
        print('Bob decodes the supported integrity protection algorithm(non-negotiable) to be:',integrity_protection_chosen_by_Alice)
        # If it is Alice, decoding her nonce aka R_Alice
        R_Alice = first_message_from_alice[-8:].decode('utf8')
        print('Bob decodes R_Alice to be:', R_Alice)
        # Getting Alice's public key from the certificate.
        alice_public_key = certificate_from_Alice.get_pubkey()
        public_key_of_Alice = RSA.importKey(crypto.dump_publickey(crypto.FILETYPE_PEM, alice_public_key))
        print('K_a:', public_key_of_Alice)
        # Generate R_Bob
        nonce = uuid.uuid4().hex
        rb = nonce[:8]
        print('R_Bob generated by Bob: ', rb)
        # print(type(rb))
        # print(rb)
        R_Bob = rb.encode()
        # Encrypt R_bob with Alice's public key
        encryptor = PKCS1_OAEP.new(public_key_of_Alice)
        Ka_Rb = encryptor.encrypt(R_Bob)
        print('Using the certificate, Bob finds the public key of Alice and uses that to encrypt R_Bob')
        # certificate and RSA_key_pair of Bob
        certificate, RSA_key_pair = create_certificate_and_RSA_key_pair()
        # convert certificate to bytes
        byte_certificate = crypto.dump_certificate(crypto.FILETYPE_PEM, certificate)
        # send first message to Alice
        message_2 = byte_certificate + Ka_Rb
        print('Bob has sent the second message to Alice, which contains a certificate signed by the public key of Bob(K_b),'
              'and K_a{R_Bob}')
        connection_socket.send(message_2)
        print()
        
        # Second message from Alice
        second_message_from_alice = connection_socket.recv(1024)
        print('Bob has received the third message from Alice, which contains K_b{S} and the combined hash'
              ' of K, message 1, message 2 and "CLIENT" or "CORRUPT"')
        # Find encrypted KB_S
        KB_S = second_message_from_alice[:256]
        # Find bob's private key
        bob_private_key = RSA.importKey(crypto.dump_privatekey(crypto.FILETYPE_PEM, RSA_key_pair))
        # Decrypt S using bob's private key and then, decode it.
        decryptor = PKCS1_OAEP.new(bob_private_key)
        S = decryptor.decrypt(ast.literal_eval(str(KB_S))).decode('utf8')
        print('Bob decrypts S, using his private key, to be:', S)
        K_hex = hex(int(R_Alice, 16) ^ int(rb, 16) ^ int(S, 16))
        K = K_hex[2:]
        print('Bob computes the Master Secret K(S xor R_Alice xor R_Bob) to be:', K)
        print()
        
        # If Alice is who she claims to be, Bob will generate a hash on his end replacing "CLIENT" with "SERVER". Otherwise, the program will end.
        alice_verified_string = compute_hash_of_received_stuff_and_verify_alice(K, first_message_from_alice, message_2, second_message_from_alice[256:])
        # Compute Hash of K, message_1, message_from_Bob and "SERVER"
        keyed_hash_function = hashlib.sha1()
        keyed_hash_function.update(K.encode())
        keyed_hash_function.update(first_message_from_alice)
        keyed_hash_function.update(message_2)
        keyed_hash_function.update(alice_verified_string.encode())
        message_4 = keyed_hash_function.hexdigest().encode()
        # send second message to Alice
        print('Bob has sent the fourth message to Alice, which contains the combined hash'
              ' of K, message 1, message 2 and "SERVER"')
        print()
        connection_socket.send(message_4)
        
        # Since the hashes match, Bob will generate 4 keys, 2 for encryption and 2 for integrity protection
        # One write encryption key and one read encryption key
        # One write integrity protection key and one read integrity protection key
        # The keys will come from a hash of K, R_alice and R_bob
        four_keys_total = hashlib.sha256()
        four_keys_total.update(K.encode())
        four_keys_total.update(R_Alice.encode())
        four_keys_total.update(R_Bob)
        print('Using the hash(K, R_Alice, R_Bob), four keys are produced by Bob.')
        # Now, using sha256, a 64 bit hexdigest is produced. 
        key_digest = four_keys_total.hexdigest()
        # 0-15 bits will go to key_encryption_read
        key_encryption_read = key_digest[0:16]
        # 16-31 bits will go to key_encryption_write
        key_encryption_write = key_digest[16:32]
        # 32-47 bits will go to key_integrity_protection_read
        key_integrity_protection_read = key_digest[32:48]
        # 48-63 bits will go to key_integrity_protection_write
        key_integrity_protection_write = key_digest[48:64]
        print('Key encryption write: ', key_encryption_write)
        print('Key encryption read: ', key_encryption_read)
        print('Key integrity protection write: ', key_integrity_protection_write)
        print('Key integrity protection_read: ', key_integrity_protection_read)
        print()
        print('SSL Handhsake is complete')
        print()
        
        
        # Read the file random_words.txt as binary
        # Maximum block size allowed on SSL transfer is 16KB
        print('Bob will send a 64KB file to Alice now, over the SSL connection.')
        print()
        input_file = open("bob_random_words.txt", "rb")
        data = input_file.read()
        input_file.close()
        number_of_blocks = int(len(data) / 16384)
        blocks = []
        for i in range(number_of_blocks):
            start = i * 16384
            end = (i+1) * 16384
            blocks.append(data[start:end])
        
        # starting block has seq = 0, with every loop, seq increases by 1
        seq = 0
        # RH which contains record type, SSL version and length of block
        record_header = "DataSSL316384"
        # final message to be sent to Alice
        final_message = b""
        # for each 16 KB block in the txt file, do HMAC and then encryption
        for block in blocks:
            # do HMAC of key_integrity_protection_write, seq, rh and 16 KB data block using SHA-256
            m1 = hashlib.sha256()   
            m1.update(key_integrity_protection_write.encode())
            m1.update(str(seq).encode())
            m1.update(record_header.encode())
            m1.update(block)
            hmac = m1.hexdigest()
            print('Using SHA-256 integrity protection, like Alice requested, here is the HMAC'
                  ' of Key integrity protection_write, SEQ=', seq, ' RH and block(aka a 4th of the data, 16KB):', hmac)
            
            # find out how much padding is required
            cumulative = block + hmac.encode()
            padding_number = 16 - (len(cumulative) % 16)
            padding = ('x'*padding_number).encode()
            cumulative += padding
            
            # encrypt block, hmac and padding using AES
            iv = b'0101010101010101'
            block_to_be_encrypted = cumulative
            cipher = AES.new(key_encryption_write.encode("utf8"), AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(block_to_be_encrypted)
            print('Then, Bob encrypts the block(aka a 4th of the data, 16 KB), HMAC and padding using AES by using his encryption_write key, like Alice requested.'
                  'For space purposes, the ciphertext will not be printed in the terminal.')
            print()
            # append record header and encrypted block(no sequence number thougg) to the final message
            final_message += record_header.encode()+ciphertext
            
            # seq increases by 1
            seq += 1
        
        print('After the 4 encrypted blocks have been appended together into one message, Bob will send that encrypted message(aka the file) to Alice.')
        # send final message, which is the encrypted and integrity protected file to Alice
        connection_socket.send(final_message)
        
        # mainly here because even after everything is done, Bob's socket does not close and Bob's terminal is on an infinite loop.
        # band-aid fix to the solution using a variable declared at the start.
        if number == 1:
            exit()
        
        connection_socket.close()


main()
