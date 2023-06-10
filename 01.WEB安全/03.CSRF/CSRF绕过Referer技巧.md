## 前言

防止CSRF漏洞常用的方法一般有2个，那就是验证referer和增加token；

由于校验referer一般是通过正则表达式来进行匹配，开发人员可能存在疏忽，导致了被绕过的可能（正常情况下验证referer是不能绕过的）

## 绕过

### 空referer

**和标题一样，测试时就是给数据包中的referer置空即可**，有些网站可能没有考虑到referer为空的情况或者业务需要referer为空的情况从而导致了绕过

如果要实际利用，那么可以使用以下的一些方法：

-  form表单页面加上如下内容：  
```html
  <meta name="referrer" content="never" >
```

-  a标签的一个属性ref  
```html
<a href="xxx" ref="noreferrer">TEST</a>
```

-  利用其他的协议，比如`data:`、`file:`等  
```html
  <iframe src="data:text/html;base64,PGZvcm0gbWV0aG9kPXBvc3QgYWN0aW9uPWh0dHA6Ly9hLmIuY29tL2Q+PGlucHV0IHR5cGU9dGV4dCBuYW1lPSdpZCcgdmFsdWU9JzEyMycvPjwvZm9ybT48c2NyaXB0PmRvY3VtZW50LmZvcm1zWzBdLnN1Ym1pdCgpOzwvc2NyaXB0Pg==">
```

-  如果目标是http的站点，那么将poc放到https的站点上，从https的站点跳转到http的站点，也是不带有referer的 

### 关键词绕过

查看是否必须存在指定的关键词，如必须存在`abc.com`，那么我们只需要使用`xxx.com/poc.html?abc.com`即可绕过（`?`也可以换成其他的一些符号，只要不影响html解析就行，比如`#`）

### 指定域绕过

相比上一个更难，比如referer必须在域`abc.com`下，这种情况也有一些方法：

1. 使用`@`，比如`abc.com@xxx.com/poc.html`
2. 看看子域名有不有发布文章的功能的地方，比如存在一个子域名`forum.abc.com`可以发布文章，那么把poc发布到这个域名下诱导其他人访问也是可以的
3. 如果是GET型CSRF，思路和第二条也差不多，只是要简单很多，找个能从网站内访问POC的点即可，比如网站头像处设置成CSRF的POC
4. 找一个任意URL跳转的漏洞来结合
5. 结合XSS

## 总结

绕过方法总体来说有2种

- 第一种就是空referer
- 第二种就是和任意URL跳转一样的绕法
