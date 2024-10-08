import hashlib,binascii
from Crypto.Cipher import AES
from Crypto.Protocol import KDF
from argparse import ArgumentParser
import sys



# Constants
AES256_CONSTANT = [0x6B,0x65,0x72,0x62,0x65,0x72,0x6F,0x73,0x7B,0x9B,0x5B,0x2B,0x93,0x13,0x2B,0x93,0x5C,0x9B,0xDC,0xDA,0xD9,0x5C,0x98,0x99,0xC4,0xCA,0xE4,0xDE,0xE6,0xD6,0xCA,0xE4]
AES128_CONSTANT = AES256_CONSTANT[:16]
IV = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]
ITERATION = 4096 # Active Directory default



def parse_arguments():
  parser = ArgumentParser()
  parser.add_argument("-p","--password",dest="password",help="Password String")
  parser.add_argument("-d","--domain",dest="domain",help="Set the domain FQDN")
  parser.add_argument("-u","--user",dest="user",help="sAMAccountName - this is case sensitive for AD user accounts")
  parser.add_argument("-l","--host",action='store_true',help="Target is a computer account")
  parser.add_argument("-ntlm",action='store_true',help="NTLM Password Hash")
  parser.add_argument("-aes128",action='store_true',help="AES128 Password Hash")
  parser.add_argument("-aes256",action='store_true',help="AES256 Password Hash")
     

  return parser.parse_args()

# Calculate NTLM password from a string
def do_ntlm(password):
  pwhash = hashlib.new('md4', password.encode('utf-16le')).digest()
  return binascii.hexlify(pwhash).decode()


def do_aes_256(aes_256_pbkdf2):
  cipher = AES.new(aes_256_pbkdf2, AES.MODE_CBC, bytes(IV))
  key_1 = cipher.encrypt(bytes(AES256_CONSTANT))

  cipher = AES.new(aes_256_pbkdf2, AES.MODE_CBC, bytes(IV))
  key_2 = cipher.encrypt(bytearray(key_1))

  aes_256_raw = key_1[:16] + key_2[:16]
  return aes_256_raw.hex().upper()


def do_aes_128(aes_128_pbkdf2):
  cipher = AES.new(aes_128_pbkdf2, AES.MODE_CBC, bytes(IV))
  aes_128_raw = cipher.encrypt(bytes(AES128_CONSTANT))
  return aes_128_raw.hex().upper()



def main():
  args = parse_arguments()
  domain = None
  host = None
  password = None
  user = None
  salt = None
  
  if args.domain:
    domain = args.domain.upper()
  
  if args.user:
    user = args.user
      
  if args.host:
    if args.user:
      host = args.user.replace("$","")
    else:
      print("Missing User, specify with -u <username>")
    
  if args.password:
    password = args.password

  
  
  if args.ntlm:
    if password:
      pwhash = hashlib.new('md4', args.password.encode('utf-16le')).digest()
      print("[+] NTLM: ",binascii.hexlify(pwhash).decode())
    else:
      print("Missing Password value!")
    
  if args.aes256:
    # Check required values
    if not domain:
      print("[!] Missing Domain. Specify with -d <domain>")
      sys.exit(1)
    if not password:
      print("[!] Missing Password. Specify with -p <password>")
      sys.exit(1)
    if not user:
      print("[!] Missing Username. Specify with -u <username>")
      sys.exit(1)      
    
    # Calculate SALT
    if args.host:
      host = args.user.replace('$', '')
      salt = f'{domain}host{host.lower()}.{domain.lower()}'
    else:
      salt = f'{domain}{args.user}'
  
    # Calculkate password bytes
    try:
      password_bytes = unhexlify(args.password).decode('utf-16-le', 'replace').encode('utf-8', 'replace')
    except:
      password_bytes = args.password.encode('utf-8')    
  
    salt_bytes = salt.encode('utf-8')      
    aes_256_pbkdf2 = KDF.PBKDF2(password_bytes, salt_bytes, 32, ITERATION)
    aes_256_key = do_aes_256(aes_256_pbkdf2)
    print(f'[+] AES256 Key: {aes_256_key}')
  
  if args.aes128:
     # Check required values
    if not domain:
      print("[!] Missing Domain. Specify with -d <domain>")
      sys.exit(1)
    if not password:
      print("[!] Missing Password. Specify with -p <password>")
      sys.exit(1)
    if not user:
      print("[!] Missing Username. Specify with -u <username>")
      sys.exit(1)      
    
    # Calculate SALT
    if args.host:
      host = args.user.replace('$', '')
      salt = f'{domain}host{host.lower()}.{domain.lower()}'
    else:
      salt = f'{domain}{args.user}'
  
    # Calculkate password bytes
    try:
      password_bytes = unhexlify(args.password).decode('utf-16-le', 'replace').encode('utf-8', 'replace')
    except:
      password_bytes = args.password.encode('utf-8')    
  
    salt_bytes = salt.encode('utf-8')      
    aes_256_pbkdf2 = KDF.PBKDF2(password_bytes, salt_bytes, 32, ITERATION)
    aes_128_pbkdf2 = aes_256_pbkdf2[:16]
    aes_128_key = do_aes_128(aes_128_pbkdf2)
    print(f'[+] AES128 Key: {aes_128_key}')
    
  
  
    
main()
