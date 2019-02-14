# Slim: OS Kernel Support for a Low-Overhead Container Overlay Network

Slim is a low-overhead container overlay networking solution. Unlike traditional container overlay networks that rely on packet encapsulation (e.g., VXLAN), Slim virtualizes the network at a per-connection level, significantly improving throughput, latency, and CPU utilization.

Slim has two modes: secure mode and non-secure mode. Non-secure mode does not require kernel modifications and is easy to deploy. However, non-secure mode should be used only when a container is trusted because the container gets access to its host network. Secure mode addresses this security issue via a Linux kernel module.

Our detailed paper will appear at NSDI 2019 (https://www.usenix.org/conference/nsdi19/technical-sessions).

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
