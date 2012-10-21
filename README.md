EAP-attack-utils
================

针对校园网EAP协议的简单攻击工具。

依赖
------------

* Linux
* Python2


使用
----

### 基本结构

``` bash
$ tree
.
├── LICENSE
├── README.md
├── eappacket.py               # EAP协议基础包
├── maccollector.py            # 局域网MAC搜集脚本
├── sendeapfailure.py          # EAP-Failure包发送器
└── sendeaplogoff.py           # EAP-Logoff包发送器
```

见[「基于以太网的802.1x认证安全分析」](http://blog.lovemaple.info/blog/2012/08/13/802-dot-1x-over-ethernet-security-analysis/)

Todo
----
* 消息轰炸器
* EAP定制版协议的黑盒测试工具
