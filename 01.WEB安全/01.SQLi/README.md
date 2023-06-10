## 定义
SQL注入即是指web应用程序对用户输入数据的合法性没有判断或过滤不严，攻击者可以在web应用程序中事先定义好的查询语句的结尾上添加额外的SQL语句，在管理员不知情的情况下实现非法操作，以此来实现欺骗数据库服务器执行未授权的任意查询，从而进一步得到相应的数据信息。
## 什么是SQL注入
简单的来说，SQL注入是开发者没有对用户的输入数据进行严格的限制/转义，致使用户在输入一些特定的字符时，在与后端设定的sql语句进行拼接时产生了歧义，使得用户可以控制该条sql语句与数据库进行通信。

简单举个例子
```php
<?php
$conn = mysqli_connect($servername, $username, $password, $dbname);
if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}
$username = @$_POST['username'];
$password = @$_POST['password'];
$sql = "select * from users where username = '$username' and password='$password';";
$rs = mysqli_query($conn,$sql);
if($rs->fetch_row()){
    echo "success";
}else{
    echo "fail";
}
?>
```
上述代码模拟web应用程序进行登录操作。若登录成功，则返回success，失败则返回fail
正常用户登录，sql语句如下：
```sql
select * from users where username = '$username' and password='$password'
```
其中，变量$username 与变量$password为用户可以控制的内容，正常情况下，用户所输入的内容在sql语义上都将作为字符串，被赋值给字段来当做整条select查询语句的筛选条件。
若用户输入的$username为admin'-- ，$password为123。那么拼接到sql语句中将得到如下结果
```sql
select * from users where username = 'admin'-- ' and password='123'
```
这里的`-- ` 是单行注释符，可以将`'admin'` 后面的内容给注释掉，让此条sql语句的语义发生变化，就算用户输入错误的密码，也可以完成登录操作，这就是我们常说的万能密码之一。
## 常见数据库
数据库包括关系型数据库和非关系型数据库，这两类数据库最主要的区别如下表所示

|  | 关系型数据库 | 非关系型数据库 |
| --- | --- | --- |
| 特性 |1. 采用了关系模型来组织数据的数据库<br />2. 事务的一致性<br />3.关系模型指的就是二维表格模型，而一个关系型数据库就是由二维表及其之间的联系所组成的一个数据组织<br />|使用键值对存储数据；<br />分布式；<br />一般不支持ACID特性；<br />非关系型数据库严格上不是一种数据库，应该是一种数据结构化存储方法的集合|
| 优点 |1.容易理解：二维表结构是非常贴近逻辑世界一个概念，关系模型相对网状、层次等其他模型来说更容易理解；<br />2.使用方便：通用的SQL语言使得操作关系型数据库非常方便；<br />3.易于维护：丰富的完整性(实体完整性、参照完整性和用户定义的完整性)大大减低了数据冗余和数据不一致的概率；<br />4.支持SQL，可用于复杂的查询|1.无需经过sql层的解析，读写性能很高；<br />2.无需经过sql层的解析，读写性能很高；<br />3.基于键值对，数据没有耦合性，容易扩展；<br />4.存储数据的格式：nosql的存储格式是key,value形式、文档形式、图片形式等等，文档形式、图片形式等等，而关系型数据库则只支持基础类型|
| 缺点 |1.为了维护一致性所付出的巨大代价就是其读写性能比较差；<br />2.固定的表结构；<br />3.高并发读写需求；<br />4.海量数据的高效率读写；|1.不提供sql支持，学习和使用成本较高；<br />2.无事务处理，附加功能bi和报表等支持也不好|
常见的关系型数据库和非关系型数据库有如下几种，我们主要讨论关系型数据库的注入问题，非关系型数据库暂不讨论

### 关系型数据库

1. mysql
2. Oracle
3. postgresql
4. mssql
5. DB2
### 非关系型数据库

1. MongoDB
2. Redis
3. influxdb
4. 。。。
## 渗透的时候，如何判断数据库？

| 方法           | 数据库                                                       |
| -------------- | ------------------------------------------------------------ |
| 常用搭配       | asp => mssql / access<br />.net => mssql<br />php => mysql,postgresql<br />java => mysql,oracle |
| 默认端口       | oracle => 1521<br />mssql => 1433<br />mysql => 3306<br />postgresql => 5432 |
| 数据库特有函数 | pg_sleep() => postgresql<br />benchmark() => mysql<br />waitfor delay => mssql<br />DBMS_PIPE.RECEIVE_MESSAGE() => oracle<br />... |
| 特殊符号       | ; => 字句查询标识符，postgresql，mssql 默认可堆叠查询;<br />\# =>Mysql 注释符 |
| 特定表名       | information_schema => mssql,postgresql,mysql<br />pg_tables => postgresql<br />sysobjects => mssql<br />all_tables,user_tables => oracle |
| 报错banner信息 | ...                                                          |
