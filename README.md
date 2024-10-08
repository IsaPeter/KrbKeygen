# KrbKeygen

Python script to calculate Active Directory Kerberos keys (NTLM, AES128, AES256).

The source code based on the following repositiries: 
- https://github.com/Tw1sm/aesKrbKeyGen
- https://gist.github.com/Kevin-Robertson/9e0f8bfdbf4c1e694e6ff4197f0a4372


## Examples

**Calculate NTLM hash for a given password**

```bash
└─$ python3 krbkeygen.py -ntlm -p horse                                                              
[+] NTLM:  739120ebc4dd940310bc4bb5c9d37021
```

**Calculate AES256 hash for a AD user account**

```bash
└─$ python3 krbkeygen.py -aes256 -p horse -d essos.local -u khal.drogo
[+] AES256 Key: 2EF916A78335B11DA896216AD6A4F3B1FD6276938D14070444900A75E5BF7EB4
```

**Calculate AES128 hash for a AD user account**

```bash
└─$ python3 krbkeygen.py -aes128 -p horse -d essos.local -u khal.drogo
[+] AES128 Key: 7D76DA251DF8D5CEC9BF3732E1F6C1AC
```

**Calculate AES128 Key for a AD computer account**

```bash
└─$ python3 krbkeygen.py -aes128 -p SecretPassword -d domain.local -u windowsdc1$ -l   
[+] AES128 Key: 27220D9A02A83E86192670946FD0EA44
```


**Help menu**

```bash
└─$ python3 krbkeygen.py --help                                       
usage: krbkeygen.py [-h] [-p PASSWORD] [-d DOMAIN] [-u USER] [-l] [-ntlm] [-aes128] [-aes256]

options:
  -h, --help            show this help message and exit
  -p PASSWORD, --password PASSWORD
                        Password String
  -d DOMAIN, --domain DOMAIN
                        Set the domain FQDN
  -u USER, --user USER  sAMAccountName - this is case sensitive for AD user accounts
  -l, --host            Target is a computer account
  -ntlm                 NTLM Password Hash
  -aes128               AES128 Password Hash
  -aes256               AES256 Password Hash
```

