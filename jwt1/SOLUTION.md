# Intended solution

1. Copy the token's payload in cyberchef, from base64, and copy the decoded payload
2. Paste the decoded payload and change it to:

```
{
    "loggedin": true,
    "username": "santiago"
}
```

3. Encode the payload to base64
4. Change the claims section of the JWT with the encoded payload
5. Delete the signature from the JWT but keep the last dot
5. Refresh the page