# Slim: OS Kernel Support for a Low-Overhead Container Overlay Network

Slim is a low-overhead container overlay networking solution. Unlike traditional container overlay networks that rely on packet encapsulation (e.g., VXLAN), Slim virtualizes the network at a per-connection level, significantly improving throughput, latency, and CPU utilization.

Slim has two modes: secure mode and non-secure mode. Non-secure mode does not require kernel modifications and is easy to deploy. However, non-secure mode should be used only when a container is trusted because the container gets access to its host network. Secure mode addresses this security issue via a Linux kernel module.

Our NSDI 2019 paper (https://danyangzhuo.com/papers/NSDI19-Slim.pdf) describes the technical details of Slim.

## Requirement

We have tested on:
* Ubuntu 16.04
* Docker
* Weave Overlay Network

We have tested the following applications:
* Memcached
* Nginx
* Postgres
* Apache Kafka

## How to use this code?
Here is an example to configure a cluster of two machines to use Slim in the non-secure mode. Let's assume machine A has IP address of IP1 and machine B has IP2.

### Step 0: Clone the repo, build from source
On machine A and B:
```bash
git clone https://github.com/danyangz/slim
pushd slim/socket
make
popd
pushd slim/router
make
popd
```

### Step 0: Secure mode (optional)
To use the secure mode, first compile and insert the kernel module on machine A and B:
```bash
git clone https://github.com/danyangz/slim
pushd slim/kern_module
make
sudo insmod slim_kern.ko 
popd
```
Uncomment the first lines in router/router.cpp and socket/socket.c. Then, compile the secure mode of SlimRouter and SlimSocket:
```bash
pushd slim/socket
make
popd
pushd slim/router
make
popd
```

### Step 1: Start the weave network
On machine A:
```bash
weave launch
```
On machine B:
```bash
weave launch <IP1>
```

### Step 2: Start the containers
Let's start a container on each machine. Here we simply use standard ubuntu 16.04 image to instantiate containers. We name the container on machine A as c1 and the container on machine B as c2.

On machine A:
```bash
eval $(weave env)
docker run --name c1 -v slim/:/slim/ -ti ubuntu:16.04
```
On machine B:
```bash
eval $(weave env)
docker run --name c2 -v slim/:/slim/ -ti ubuntu:16.04
```

### Step 3: Start SlimRouter
On machine A:
```bash
cd slim/router
./router <IP1>
```
On machine B:
```bash
cd slim/router
./router <IP2>
```

### Step 4: Speed test
Let's use iperf to test the network speed.

Inside the shell of container c1 on machine A:
```bash
apt update
apt install iperf
LD_PRELOAD=/slim/socket/SlimSocket.so VNET_PREFIX=10.32.0.0/12 iperf -s
```
Inside the shell of container c2 on machine B:
```bash
apt update
apt install iperf
LD_PRELOAD=/slim/socket/SlimSocket.so VNET_PREFIX=10.32.0.0/12 iperf -c c1
```


## How to use Slim in Kubernetes?
Slim can also be used in Kubernetes. It makes the container communication performance in different nodes reach the upper bound of across-nodes communication.

We select the Antrea CNI(https://github.com/vmware-tanzu/antrea), which works acquiescently at overlay (VXLAN) network mode.

### Step 0: Prerequisites
Make sure that the Kubernetes cluster already deploys successfully.

Then create the Antrea CNI and check it Running state. (If you already start other CNI, stop it.)
```
root@k8s-master:/usr/local/kubernetes/antrea# wget https://raw.githubusercontent.com/vmware-tanzu/antrea/master/build/yamls/antrea.yml

root@k8s-master:/usr/local/kubernetes/antrea# kubectl apply -f antrea.yml

root@k8s-master:/usr/local/kubernetes/antrea# kubectl get pod -A | grep antrea
kube-system   antrea-agent-7t4j2                      2/2     Running   0          27h
kube-system   antrea-agent-9h77v                      2/2     Running   0          27h
kube-system   antrea-agent-p5w28                      2/2     Running   0          27h
kube-system   antrea-controller-6847d9964c-9qnnz      1/1     Running   0          27h
```

In addition, git clone Slim code and compile it as above(Step 0: Clone the repo, build from source) at every k8s node machine `/root/slim` path. 

### Step 1: Create ubuntu containers in Pod
Add following contents into `deployment_ubuntu.yaml`. 
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
Since default ubuntu image does not include iperf and network tools, we use `ubuntu-net:v1`, which is made in advance and include iperf and network tools. You can replace `ubuntu-net:v1` with yourself ubuntu image.

Then, create these ubuntu containers in Pod.
```
root@k8s-master:/usr/local/kubernetes# kubectl create -f deployment_ubuntu.yaml
```

## Step 2: Access a node machine and corresponding container
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
Keep the above terminal running and open a new terminal.
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
Keep the above terminal running.

# Step 3: Access another node machine and corresponding container
Start SlimRouter on k8s-node-01 machine (IP: 10.0.0.62).
```
root@k8s-node-02:~# cd /root/slim/router/
root@k8s-node-02:~/slim/router# ./router 10.0.0.62
[INFO] SlimRouter Starting...
[DEBUG] Accepting new clients...
```
Keep the above terminal running and open a new terminal.
```
root@k8s-master:~# kubectl exec -it ubuntu-deployment-5b86c44b94-rrdhk -- /bin/bash
root@ubuntu-deployment-5b86c44b94-rrdhk:/# LD_PRELOAD=/slim/socket/SlimSocket.so iperf -c 10.244.1.21 -i 2
```

Finally, you can see the iperf TCP communication results. The bandwidth between two containers in Pods reaches approximately the maximum bandwidth between two machines.

Slim can also support multiple containers in different nodes or Pods, only need to start more SlimRouter in nodes and iperf servers in containers. The method is similar to the above.
