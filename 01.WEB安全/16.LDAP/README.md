## LDAP 注入

### 简介

**LDAP(Lightweight Directory Access Protocol)**：轻量级目录访问协议，是一种在线目录访问协议。LDAP主要用于目录中资源的搜索和查询，是X.500的一种简便的实现，是运行于TCP/IP之上的协议，端口号为：**389**， 加密**636**（SSL）

| 属性                     | 解释                                                         |
| ------------------------ | ------------------------------------------------------------ |
| dn（Distinguished Name） | 一条记录的位置 ，描述如下<br/>cn=user,ou=marketing,ou=pepple,dc=mydomain,dc=org |
| dc(domain compoent)      | 一条记录所属区域 域名部分                                    |
| ou (Organization Unit)   | 一条记录所属组织                                             |
| cn/uid（Common Name）    | 一条记录的名字/ID                                            |
| Entry                    | 条目记录数                                                   |

### 原理

攻击者将特制的数据输入到LDAP查询或过滤器中，模拟正常LDAP查询操作，但当查询完成时，攻击者恶意数据被LDAP服务显示出来，从而导致安全问题的发生

LDAP注入本质就是在OpenLDAP实施中，由于一个括号内代表一个过滤器，第二个过滤器会被忽略，只有第一个会被执行。当查询语句带有逻辑操作符时，可以通过注入恶意的LDAP语句去达到不同的目的

### 基本的LDAP语法

- = 等于
- & 逻辑和
-  | 逻辑或
-  ! 逻辑不 
- \* 通配符

逻辑操作符(AND、OR、NOT)和关系操作符(=、>=、<=、~=)

除使用逻辑操作符外，RFC4256还允许使用下面的单独符号作为两个特殊常量：

```
(&)     ->Absolute TRUE
(|)     ->Absolute FALSE
```

对象定义：

```
objectclass: top
objectclass: person
```

对象类定义：

```
objectclass: person
objectclasses=( 2.5.6.6 NAME 'person' DESC 'Defines entries that generically represent people.' SUP 'top' STRUCTURAL MUST ( cn $ sn ) MAY ( userPassword $ telephoneNumber $ seeAlso $ description )
```

 属性定义：

```
attributetypes=( 2.5.4.4 NAME ( 'sn' 'surName' ) DESC 'This is the X.500 surname attribute, which contains the family name of a person.' SUP 2.5.4.41 EQUALITY 2.5.13.2 ORDERING 2.5.13.3 SUBSTR 2.5.13.4 USAGE userApplications )
```

搜索语法：

主要根据属性和值进行搜索

```
attribute operator value	
```

### LDAP查询语句

一个圆括号内的判断语句又称为一个过滤器filter。

**默认情况下，LDAP的DN和所有属性都不区分大小写**

```
( "&" or "|" (filter1) (filter2) (filter3) ...) ("!" (filter))
```

### LDAP注入

#### 无逻辑操作符的注入

后端代码如果是这样写的：

```php
(attribute=$input)
```

构造输入语句：

```php
$input=value)(injected_filter
```

完整的语句就成下面这样了：

```php
(attribute=value)(injected_filter)
```

由于一个括号内代表一个过滤器，在OpenLDAP实施中，第二个过滤器会被忽略，只有第一个会被执行。而在ADAM中，有两个过滤器的查询是不被允许的。因而这类情况仅对于OpenLDAP有一定的影响。

例如我们要想查询一个字段是否存在某值时，可以用`$input=x*`进行推移，利用页面响应不同判断`x*`是否查询成功

#### 带有逻辑操作符的注入

```php
(|(attribute=$input)(second_filter))
(&(attribute=$input)(second_filter))
```

此时带有逻辑操作符的括号相当于一个过滤器。此时形如value)(injected_filter)的注入会变成如下过滤器结构

```php
(&(attribute=value)(injected_filter))(second_filter)
```

虽然过滤器语法上并不正确，OpenLDAP还是会从左到右进行处理，忽略第一个过滤器闭合后的任何字符。一些LDAP客户端Web组成会忽略第二个过滤器，将ADAM和OpenLDAP发送给第一个完成的过滤器，因而存在注入。

### 案例分享

#### 万能用户名案例

验证登陆的查询语句是这样:

```php
(&(USER=$username)(PASSWORD=$pwd))
```

输入`$username = admin)(&)(`使查询语句变为

```php
(&(USER=admin)(&))((PASSWORD=$pwd))
```

即可让后面的password过滤器失效，执行第一个过滤器而返回true，达到万能密码的效果

#### 权限提升案例

现假设下面的查询会向用户列举出所有可见的低安全等级文档

```php
(&(directory=document)(security_level=low))
```

这里第一个参数`document`是用户入口，`low`是第二个参数的值。如果攻击者想列举出所有可见的高安全等级的文档，他可以利用如下的注入：

```php
document)(security_level=*))(&(directory=documents
```

生成的过滤器为：

```php
(&(directory=documents)(security_level=*))(&(direcroty=documents)(security_level=low))
```

LDAP服务器仅会处理第一个过滤器而忽略第二个，因而只有下面的查询会被处理：`(&(directory=documents)(security_level=*))`，而`(&(direcroty=documents)(security_level=low))`则会被忽略。结果就是，所有安全等级的可用文档都会列举给攻击者，尽管他没有权限看它们。

## 参考链接

https://www.cnblogs.com/endust/p/11811477.html

