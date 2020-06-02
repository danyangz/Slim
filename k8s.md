## How to use Slim in Kubernetes?
We use the Antrea CNI(https://github.com/vmware-tanzu/antrea) as an exmaple.

### Step 0: Prerequisites
Deploy a kubernetes cluster.

Create the Antrea CNI and check its running state.
```
root@k8s-master:/usr/local/kubernetes/antrea# wget https://raw.githubusercontent.com/vmware-tanzu/antrea/master/build/yamls/antrea.yml

root@k8s-master:/usr/local/kubernetes/antrea# kubectl apply -f antrea.yml

root@k8s-master:/usr/local/kubernetes/antrea# kubectl get pod -A | grep antrea
kube-system   antrea-agent-7t4j2                      2/2     Running   0          27h
kube-system   antrea-agent-9h77v                      2/2     Running   0          27h
kube-system   antrea-agent-p5w28                      2/2     Running   0          27h
kube-system   antrea-controller-6847d9964c-9qnnz      1/1     Running   0          27h
```

Clone the Slim's code and compile it at every k8s node's `/root/slim` path. 

### Step 1: Create ubuntu containers in Pod
Add the following content into `deployment_ubuntu.yaml`. 
```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ubuntu-deployment
spec:
  selector:
    matchLabels:
      app: ubuntu-deployment
  replicas: 3
  template:
    metadata:
      labels:
        app: ubuntu-deployment
    spec:
      containers:
      - name: ubuntu
        image: ubuntu-net:v1
        command: [ "/bin/sh", "-ce", "tail -f /dev/null" ]
        ports:
        - containerPort: 80
        - containerPort: 5001
        volumeMounts:
        - mountPath: /slim
          name: slim-volume
      volumes:
      - name: slim-volume
        hostPath:
          path: /root/slim
```
Since default ubuntu image does not include iperf and network tools, we use `ubuntu-net:v1`, which is made in advance and include iperf and network tools. You can replace `ubuntu-net:v1` with your customized image.

Then, create these containers in Pod.
```
root@k8s-master:/usr/local/kubernetes# kubectl create -f deployment_ubuntu.yaml
```

## Step 2: Access a node machine and the corresponding container
Assuming we can see that a container IP in k8s-node-01 is 10.244.1.21, and a container IP in k8s-node-02 is 10.244.2.15
```
root@k8s-master:/usr/local/kubernetes/cprtest# kubectl get pod -o wide | grep ubuntu
ubuntu-deployment-5b86c44b94-b6ng8   1/1     Running   0          28h   10.244.2.14   k8s-node-02   <none>           <none>
ubuntu-deployment-5b86c44b94-rrdhk   1/1     Running   0          28h   10.244.2.15   k8s-node-02   <none>           <none>
ubuntu-deployment-5b86c44b94-vqxwf   1/1     Running   1          28h   10.244.1.21   k8s-node-01   <none>           <none>
```
Start SlimRouter on k8s-node-01 machine (IP: 10.0.0.6).
```
root@k8s-node-01:~/slim# cd /root/slim/router/
root@k8s-node-01:~/slim/router# ./router 10.0.0.6
[INFO] SlimRouter Starting...
[DEBUG] Accepting new clients...
```
In a new terminal,
```
root@k8s-master:~# kubectl exec -it ubuntu-deployment-5b86c44b94-vqxwf -- /bin/bash
root@ubuntu-deployment-5b86c44b94-vqxwf:/# LD_PRELOAD=/slim/socket/SlimSocket.so iperf -s
WARNING: VNET_PREFIX is not set. Using 0.0.0.0/0.
All connections are treated as virtual network connections.
```
If it works, we can see following messages on above k8s-node-01 machine.
```
[TRACE] New client with sock 4.
[TRACE] result of pthread_create --> 0
[TRACE] Start to handle the request from client sock 4.
[TRACE] Start to read from sock 4
[TRACE] Get request cmd 0
[DEBUG] SOCKET_SOCKET
[TRACE] write rsp 4 bytes to sock 4
[TRACE] New client with sock 5.
[TRACE] result of pthread_create --> 0
[TRACE] Start to handle the request from client sock 5.
[TRACE] Start to read from sock 5
[TRACE] Get request cmd 1
[DEBUG] SOCKET_BIND
[TRACE] write rsp 4 bytes to sock 5
```

# Step 3: Access another node machine and corresponding container
Start SlimRouter on k8s-node-01 machine (IP: 10.0.0.62).
```
root@k8s-node-02:~# cd /root/slim/router/
root@k8s-node-02:~/slim/router# ./router 10.0.0.62
[INFO] SlimRouter Starting...
[DEBUG] Accepting new clients...
```
In a new terminal,
```
root@k8s-master:~# kubectl exec -it ubuntu-deployment-5b86c44b94-rrdhk -- /bin/bash
root@ubuntu-deployment-5b86c44b94-rrdhk:/# LD_PRELOAD=/slim/socket/SlimSocket.so iperf -c 10.244.1.21 -i 2
```

Slim can also support multiple containers in different nodes or Pods.
