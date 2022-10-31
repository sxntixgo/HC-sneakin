# Intended solution

1. Copy the hash from the browser's cookies and save it in a file
2. Use hashcat to recover the key

```
hashcat -m 16500 --show -a 0 ~/Downloads/jwt.txt ~/Downloads/rockyou.txt 
```

3. Use https://jwt.io/ to modify the claims and sign the toke with the recovered key
4. Paste the new cookie
5. Refresh the browser