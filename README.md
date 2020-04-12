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