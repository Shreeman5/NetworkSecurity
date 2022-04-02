from socket import *
from OpenSSL import crypto
import uuid
from Crypto.PublicKey import RSA
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
    certificate.get_issuer().commonName = "Alice" 
    # mainly here so that there is no certificate loading error on Bob's end
    certificate.gmtime_adj_notBefore(0)
    certificate.gmtime_adj_notAfter(50)
    # set public key of certificate to the RSA public key
    certificate.set_pubkey(RSA_key_pair) 
    # sign the certificate using the RSA key pair and the integrity protection algorithm
    certificate.sign(RSA_key_pair, "sha256") 
    
    return certificate, RSA_key_pair


def compare_hashes(hmac, x, RH, Decrypted_info, key_integrity_protection_read):
    # do HMAC of key_integrity_protection_read, seq, rh and 16 KB data block using SHA-256
    m1 = hashlib.sha256()   
    m1.update(key_integrity_protection_read.encode())
    m1.update(str(x).encode())
    m1.update(RH)
    m1.update(Decrypted_info)
    computed_hmac = m1.hexdigest()
    
    print('Using SHA-256 integrity protection, here is the HMAC, that Alice generates,'
          ' of Key integrity protection_read, SEQ=', x, ' RH and block(aka a 4th of the data, 16KB):', computed_hmac.encode())
    print('This is the hmac that Bob sent for the corresponding block: ', hmac)
    
    # If the hashes match, return 1 to the caller function. After the 4 blocks are verified using Alice's integrity_protection read key, 
    # it is safe to write the decrypted blocks into a file.
    if hmac == computed_hmac.encode():
        print('Block ', x, ' is verified.')
        return 1
    else:
        return 0
    
    

def decrypt_and_decode_the_file_from_Bob(data_file_from_bob, key_encryption_read, key_integrity_protection_read):
    iv = b'0101010101010101'
    comparison = b''
    hash_block_counter = 0
    # Run the loop 4 times, each time target 16 KB of data.
    for x in range(4):
        i = 16477 * x
        j = 16477 * (x+1)
        # Extract RH header. There are 4 of these.
        RH = data_file_from_bob[i:i+13]
        # Extract the encrypted info from Bob. This should contain the 16 KB block, hmac and padding
        Encrypted_info = data_file_from_bob[i+13:j]
        # Create an AES cipher to decrypt the encrypted stuff
        cipher = AES.new(key_encryption_read.encode("utf8"), AES.MODE_CBC, iv)
        Decrypted_info = cipher.decrypt(Encrypted_info)
        print('Alice decrypts block ', x, ' of 3 using AES, by using her encryption_read key. For space purposes the decrypted block(16 KB of letters) will not be displayed here.')
        # Add the decrypted stuff to a byte variable
        comparison += Decrypted_info[0:16384]
        # Check whether hashes are correct. 
        hmac = Decrypted_info[16384:16448]
        hash_block_counter += compare_hashes(hmac, x, RH, Decrypted_info[0:16384], key_integrity_protection_read)
        print()
    
    # If all the 4 hashes are correct, send the aggregate byte variable 'comparison' to be written to a file.
    if hash_block_counter == 4:
        return comparison
    else:
        return 0
        
# Compute Hash of K, first_message_from_alice, message_2 and "SERVER"
# If "SERVER", proceed with hanshake.
def compute_hash_of_received_stuff_and_verify_bob(K, message_1, first_message_from_bob, bob_hash):
    keyed_hash_function = hashlib.sha1()
    keyed_hash_function.update(K.encode())
    keyed_hash_function.update(message_1)
    keyed_hash_function.update(first_message_from_bob)
    keyed_hash_function.update("SERVER".encode())
    
    print('1: Alice will find the keyed hash function, which is a digest of K, message 1, message 2 and "SERVER"')
    print('2: ALice just generated K, she knows message 1 and message 2 and she can generate a string "SERVER"')
    print('3: Alice will know do a hash on her end by using K, message 1, message 2 and "SERVER"')
    print('4: If the hash that Alice generated matches the hash that Bob sent, Bob has been fully authenticated to Alice')
    print()
    if bob_hash.decode('utf8') == keyed_hash_function.hexdigest():
        print("Since the hashes match, this is Bob. Bob has been fully authenticated to Alice.")
        print()
    else:
        print("Since the hashes do not match, this is not Bob. Alice has been fully authenticated to Bob.")
        exit()

def main():
    # Connection with Bob
    mode = 'good' # either good or corrupt
    name_server_1 = 'localhost'
    port_server_1 = 8000
    alice_socket = socket(AF_INET, SOCK_STREAM)
    alice_socket.connect((name_server_1, port_server_1))

    # First message to Bob
    # encryption and integrity protection
    encryption = "AES"
    integrity_protection = "sha256"
    # certificate and RSA_key_pair of Alice
    certificate, RSA_key_pair = create_certificate_and_RSA_key_pair()
    # print("PuPr ket for Alice", RSA_key_pair)
    # convert certificate to bytes
    byte_certificate = crypto.dump_certificate(crypto.FILETYPE_PEM, certificate)
    # Generate R_Alice
    nonce = uuid.uuid4().hex
    R_Alice = nonce[:8]
    print('R_Alice generated by Alice: ', R_Alice)
    # Send first message to Bob in bytes
    message_1 = byte_certificate + encryption.encode() + integrity_protection.encode() + R_Alice.encode()
    print('Alice has sent the first message to Bob, which contains a certificate signed by the public key of Alice(K_a),'
          ' supported encryption algorithm which is AES, supported integrity protection algorithm which is SHA-256,'
          ' and R_Alice')
    alice_socket.send(message_1)
    print()
    
    # Receive first message from Bob
    first_message_from_bob = alice_socket.recv(2048)
    print('Alice has received the second message from Bob, which contains a certificate signed by the public key of Bob(K_b),'
          'and K_a{R_Bob}')
    # Verifying whether this is Alice. If not, exit.
    certificate_from_Bob = crypto.load_certificate(crypto.FILETYPE_PEM, first_message_from_bob[0:932])
    if certificate_from_Bob.get_issuer().commonName == "Bob":
        print("By checking the certificate and who it is signed by, Alice determines that this is Bob")
    else:
        print("By checking the certificate and who it is signed by, Alice determines that this is not Bob")
        exit()
    # Find encrypted Ka_rb
    Ka_Rb = first_message_from_bob[932:]
    # Find alice's private key
    alice_private_key = RSA.importKey(crypto.dump_privatekey(crypto.FILETYPE_PEM, RSA_key_pair))
    # Decrypt Rb using alice's private key and then, decode it.
    decryptor = PKCS1_OAEP.new(alice_private_key)
    R_Bob = decryptor.decrypt(ast.literal_eval(str(Ka_Rb))).decode('utf8')
    print('Alice decrypts R_Bob using her private key, which turns out to be:', R_Bob)
    # Getting Bob's public key from the certificate.
    bob_public_key = certificate_from_Bob.get_pubkey()
    public_key_of_Bob = RSA.importKey(crypto.dump_publickey(crypto.FILETYPE_PEM, bob_public_key))
    print('K_b:', public_key_of_Bob)
    # Generate S
    nonce_1 = uuid.uuid4().hex
    small_s = nonce_1[:8]
    print('Alice generates a random number called S, which is:', small_s)
    S = small_s.encode()
    # Encrypt S with Bob's public key
    encryptor = PKCS1_OAEP.new(public_key_of_Bob)
    Kb_S = encryptor.encrypt(S)
    # Generate Master secret K
    K_hex = hex(int(R_Alice, 16) ^ int(R_Bob, 16) ^ int(small_s, 16))
    K = K_hex[2:]
    print('Alice computes the Master Secret K(S xor R_Alice xor R_Bob) to be:', K)
    # Compute Hash of K, message_1, message_from_Bob and "CLIENT" or "CORRUPT"
    keyed_hash_function = hashlib.sha1()
    keyed_hash_function.update(K.encode())
    keyed_hash_function.update(message_1)
    keyed_hash_function.update(first_message_from_bob)
    if mode == 'good':
        keyed_hash_function.update("CLIENT".encode())
    elif mode == 'corrupt':
        keyed_hash_function.update("CORRUPT".encode())
    # send Kb_S and keyed hash function to Bob
    message_3 = Kb_S + keyed_hash_function.hexdigest().encode()
    print('Alice has sent the third message to Bob, which contains K_b{S} and the combined hash'
          ' of K, message 1, message 2 and "CLIENT"or"CORRUPT"')
    alice_socket.send(message_3)
    print()
    
    print('Alice should receive the fourth message from Bob, which contains the combined hash'
          ' of K, message 1, message 2 and "SERVER"')
    # Receive second message from Bob
    second_message_from_bob = alice_socket.recv(2048)
    if second_message_from_bob == b'':
        print('Bob did not send anything, which means Alice made a mistake in the handshake process by using the string "CORRUPT". Exit handshake.')
        exit()
    # If Bob is who he claims to be, using the hashes, handhsake is done. Otherwise, the program will end.
    compute_hash_of_received_stuff_and_verify_bob(K, message_1, first_message_from_bob, second_message_from_bob)
    # Since the hashes match, Alice will generate 4 keys, 2 for encryption and 2 for integrity protection
    # One write encryption key and one read encryption key
    # One write integrity protection key and one read integrity protection key
    # The keys will come from a hash of K, R_alice and R_bob
    four_keys_total = hashlib.sha256()
    four_keys_total.update(K.encode())
    four_keys_total.update(R_Alice.encode())
    four_keys_total.update(R_Bob.encode())
    print('Using the hash(K, R_Alice, R_Bob), four keys are produced by Alice.')
    # Now, using sha256, a 64 bit hexdigest is produced. 
    key_digest = four_keys_total.hexdigest()
    # 0-15 bits will go to key_encryption_write
    key_encryption_write = key_digest[0:16]
    # 16-31 bits will go to key_encryption_read
    key_encryption_read = key_digest[16:32]
    # 32-47 bits will go to key_integrity_protection_write
    key_integrity_protection_write = key_digest[32:48]
    # 48-63 bits will go to key_integrity_protection_read
    key_integrity_protection_read = key_digest[48:64]
    print('Key encryption write: ', key_encryption_write)
    print('Key encryption read: ', key_encryption_read)
    print('Key integrity protection write: ', key_integrity_protection_write)
    print('Key integrity protection read: ', key_integrity_protection_read)
    print()
    print('SSL Handhsake is complete')
    print()
    
    # Needed because only 2048 bits are sent at a time
    data_file_from_bob = b''
    while True:
        data_chunk_from_bob = alice_socket.recv(2048)
        if data_chunk_from_bob == b'':
            break
        data_file_from_bob += data_chunk_from_bob
    print('Alice has received the encrypted message(aka the file) from Bob.')
    print()
    
    # decrypt and decode the file from Bob
    comparison = decrypt_and_decode_the_file_from_Bob(data_file_from_bob, key_encryption_read, key_integrity_protection_read).decode('utf8')
    
    if comparison == 0:
        # If 3 or less of the hashes were verified, do not write output to file.
        print('Some or maybe all of the hashes were not verified. Do not write output to file.')
        exit()
    else:    
        print('All of the hashes were verified. Write output to file.')
        # write Alice's decrypted info to a file. Check her output and what Bob sent by writing command:
        # FC alice_decrypted_Random_words.txt bob_random_words.txt
        # on the terminal
        text_file = open("alice_decrypted_random_words.txt", "w")
        text_file.write(comparison)
        text_file.close()
    
    

main()
