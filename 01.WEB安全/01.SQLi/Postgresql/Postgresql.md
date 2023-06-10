## 简介
PostgreSQL 是一个免费的对象-关系数据库服务器(ORDBMS)，在灵活的BSD许可证下发行。
PostgreSQL 开发者把它念作 post-gress-Q-L。
PostgreSQL 的 Slogan 是 "世界上最先进的开源关系型数据库"。
## 特征
| 特征 | 描述 |
| --- | --- |
| **函数** | 通过函数，可以在数据库服务器端执行指令程序 |
| **索引** | 用户可以自定义索引方法，或使用内置的 B 树，哈希表与 GiST 索引 |
| **触发器** | 触发器是由SQL语句查询所触发的事件。如：一个INSERT语句可能触发一个检查数据完整性的触发器。触发器通常由INSERT或UPDATE语句触发。 多版本并发控制：PostgreSQL使用多版本并发控制（MVCC，Multiversion concurrency control）系统进行并发控制，该系统向每个用户提供了一个数据库的"快照"，用户在事务内所作的每个修改，对于其他的用户都不可见，直到该事务成功提交 |
| **规则** | 规则（RULE）允许一个查询能被重写，通常用来实现对视图（VIEW）的操作，如插入（INSERT）、更新（UPDATE）、删除（DELETE） |
| **数据类型** | 包括文本、任意精度的数值数组、JSON 数据、枚举类型、XML 数据等 |
| **全文检索** | 通过 Tsearch2 或 OpenFTS，8.3版本中内嵌 Tsearch2。 |
| **NoSQL** | JSON，JSONB，XML，HStore 原生支持，至 NoSQL 数据库的外部数据包装器 |
| **数据仓库** | 能平滑迁移至同属 PostgreSQL 生态的 GreenPlum，DeepGreen，HAWK 等，使用 FDW 进行 ETL |

## schema(模式)
一个PostgreSQL数据库集群包含一个或多个已命名数据库。用户和用户组在整个集群范围内是共享的，但是其它数据并不共享。任何与服务器连接的客户都只能访问那个在连接请求里声明的数据库。
注意: 集群中的用户并不一定要有访问集群内所有数据库的权限。共享用户名的意思是不能有重名用户。假定同一个集群里有两个数据库和一个joe用户，系统可以配置成只允许joe 访问其中的一个数据库。
一个数据库包含一个或多个已命名的模式，模式又包含表。模式还可以包含其它对象，包括数据类型、函数、操作符等。同一个对象名可以在不同的模式里使用而不会导致冲突；比如，schema1和myschema都可以包含一个名为mytable的表。和数据库不同，模式不是严格分离的：只要有权限，一个用户可以访问他所连接的数据库中的任意模式中的对象。
我们需要模式的原因有好多：

- 允许多个用户使用一个数据库而不会干扰其它用户。
- 把数据库对象组织成逻辑组，让它们更便于管理。
- 第三方的应用可以放在不同的模式中，这样它们就不会和其它对象的名字冲突。

模式类似于操作系统层次的目录，只不过模式不能嵌套。
**默认的schema是public模式**
```sql
--简单版目录结构
postgres
--public(schema)
----table_name_1
----table_name_2
--myschema(schema)
----table_name_1
----table_name_2
--schema...
----table_name_1
----table_name_2
```
## SQL
```shell
postgres=# \help SELECT
Command:     SELECT
Description: retrieve rows from a table or view
Syntax:
[ WITH [ RECURSIVE ] with_query [, ...] ]
SELECT [ ALL | DISTINCT [ ON ( expression [, ...] ) ] ]
    [ * | expression [ [ AS ] output_name ] [, ...] ]
    [ FROM from_item [, ...] ]
    [ WHERE condition ]
    [ GROUP BY grouping_element [, ...] ]
    [ HAVING condition [, ...] ]
    [ WINDOW window_name AS ( window_definition ) [, ...] ]
    [ { UNION | INTERSECT | EXCEPT } [ ALL | DISTINCT ] select ]
    [ ORDER BY expression [ ASC | DESC | USING operator ] [ NULLS { FIRST | LAST } ] [, ...] ]
    [ LIMIT { count | ALL } ]
    [ OFFSET start [ ROW | ROWS ] ]
    [ FETCH { FIRST | NEXT } [ count ] { ROW | ROWS } ONLY ]
    [ FOR { UPDATE | NO KEY UPDATE | SHARE | KEY SHARE } [ OF table_name [, ...] ] [ NOWAIT | SKIP LOCKED ] [...] ]

from_item 可以是以下选项之一：

    [ ONLY ] table_name [ * ] [ [ AS ] alias [ ( column_alias [, ...] ) ] ]
```
## 一些小tips

- postgresql 默认用户是postgres，密码为空，可直接连接数据库，利用CVE-2019-9193触发命令执行
- postgresql 默认支持多语句查询，可以使用堆叠查询读写文件，执行命令
- postgresql 快速判断的方法有：pg_sleep()函数，pg_tables，pg_database等等
- postgresql 注入一般只能在同库中查询，可以跨schema，但是不能跨库查询



## 参考链接
[https://xz.aliyun.com/t/8621](https://xz.aliyun.com/t/8621)

[https://blog.csdn.net/m0_48520508/article/details/108509371](https://blog.csdn.net/m0_48520508/article/details/108509371)

[https://www.runoob.com/postgresql/postgresql-tutorial.html](https://www.runoob.com/postgresql/postgresql-tutorial.html)

[https://blog.csdn.net/wjzholmes/article/details/105651159](https://blog.csdn.net/wjzholmes/article/details/105651159)

