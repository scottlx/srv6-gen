## srv6 packet generator

Generate icmp request packet tunneled by srv6.

### Pre-request (libpcap devel)
centos
```shell
yum install libpcap-devel
```
ubuntu
```shell
sudo apt-get install libpcap-dev
```

### Run
```shell
   vim pkt-gen.json
   go run main.go pkt-gen.json
```

### Apn6 support
Implement apn6 header described below

[Application-aware Networking (APN) Framework (ietf.org)](https://www.ietf.org/archive/id/draft-li-apn-framework-06.html#name-introduction-2)
