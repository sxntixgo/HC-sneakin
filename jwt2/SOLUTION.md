# Intended solution

1. Copy the token in cyberchef, select JWT Verify, and copy the decoded payload
2. Change JWT Verify to JWT Sign, select "None" as the signing algorithm
3. Paste the payload and change it to:

```
{
    "loggedin": true,
    "username": "santiago"
}
```

4. Copy the output and update your cookie
5. Refresh the page

Alternatively, you can solve this using the extension JSON Web Token Attacker from Burp Suite with the attack Signature Exclusion.