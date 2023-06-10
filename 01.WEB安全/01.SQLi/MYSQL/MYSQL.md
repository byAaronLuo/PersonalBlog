## MySQL 简介
MySQL 是一个关系型数据库管理系统，由瑞典 MySQL AB 公司开发，目前属于 Oracle 公司。MySQL 是一种关联数据库管理系统，关联数据库将数据保存在不同的表中，而不是将所有数据放在一个大仓库内，这样就增加了速度并提高了灵活性。

- MySQL 是开源的，目前隶属于 Oracle 旗下产品。
- MySQL 支持大型的数据库。可以处理拥有上千万条记录的大型数据库。
- MySQL 使用标准的 SQL 数据语言形式。
- MySQL 可以运行于多个系统上，并且支持多种语言。这些编程语言包括 C、C++、Python、Java、Perl、PHP、Eiffel、Ruby 和 Tcl 等。
- MySQL 对PHP有很好的支持，PHP 是目前最流行的 Web 开发语言。
- MySQL 支持大型数据库，支持 5000 万条记录的数据仓库，32 位系统表文件最大可支持 4GB，64 位系统支持最大的表文件为8TB。
- MySQL 是可以定制的，采用了 GPL 协议，你可以修改源码来开发自己的 MySQL 系统。



## 版本区别
这里只讨论大版本的区别

| 版本 | 区别 |
| --- | --- |
| 5.0 以下 | 单用户模式，无information_schema库，需要猜解注入 |
| 5.0及5.0以上 | 多用户模式，存在information_schema库，其包含了MySQL的所有表，视图等 |

## SQL基本语法
在MySQL数据库中，常见对数据进行处理的操作有：增，删，改，查，对应的SQL语句以及操作内容分别是：

- 增 ，增加数据，通常在SQL语句中，其简单结构通常可以表示为：



```sql
INSERT INTO table_name ( field1, field2,...fieldN ) VALUES ( value1, value2,...valueN );
```

- 删，删除数据，通常在SQL语句中，其简单结构通常可以表示为：



```sql
DELETE FROM table_name [WHERE Clause]
```

- 改，更新数据，通常在SQL语句中，其简单结构通常可以表示为：



```sql
UPDATE table_name SET field1=new-value1, field2=new-value2 [WHERE Clause]
```

- 查，查询数据，通常在SQL语句中，其简单结构可以表示为：



```sql
SELECT column_name,column_name FROM table_name [WHERE Clause] [LIMIT N][ OFFSET M]
```
## 参考链接
[https://xz.aliyun.com/t/7169#](https://xz.aliyun.com/t/7169#)

[https://blog.sari3l.com/posts/9622f295/](https://blog.sari3l.com/posts/9622f295/)

[https://www.sqlsec.com/2020/05/sqlilabs.html#toc-heading-114](https://www.sqlsec.com/2020/05/sqlilabs.html#toc-heading-114)

