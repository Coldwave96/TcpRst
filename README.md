# TcpRst

![](https://img.shields.io/badge/Python-3-brightgreen)
![](https://img.shields.io/badge/Platform-Linux-blue)

## Introduction

💪💪 基于RAW_SOCKET + TCP Reset实现的TCP旁路阻断。

## Usage

⚠️⚠️ 需要以root权限运行!!!

```bash
git clone https://github.com/Coldwave96/TcpRst.git
cd TcpRst
sudo python3 reset.py iface ip1 ip2 ...
# eg. sudo python3 reset.py eno1 192.168.0.2 182.168.0.3
```

## Attention

* 需要该网卡能够监控到阻断ip的数据流，比如同网段下

* 如果需要跨网段阻断，在网络可达的情况下，可尝试开启网卡混杂模式

## Addition

💎💎 linux开启和关闭网卡混杂模式命令：

```bash
ifconfig eth1 promisc  # 设置混杂模式
ifconfig eth1 -promisc # 取消混杂模式
```
