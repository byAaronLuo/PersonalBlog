## 符号
### 注释符
| **注释符** | **释义** |
| --- | --- |
| -- | SQL注释风格 |
| ;%00 | 空字节 |
| /* | C注释风格 |

### 常用运算符
| **运算符** | **释义** |
| --- | --- |
| + | 加法运算 |
| - | 减法运算 |
| * | 乘法运算 |
| / | 除法运算 |
| % | 取模运算 |
| & | 位与逻辑运算 |
| &#124; | 位或逻辑运算 |
| ... | ... |

### 常见全局变量
| **变量** | **释义** |
| --- | --- |
| @@VERSION | SQL Server 版本 |
| @@SEVERNAME | 运行SQL Server 的本地服务器名称 |

## 函数
### 系统函数信息
| **函数** | **释义** |
| --- | --- |
| DB_NAME() | 获取当前数据库名 |
| USER_NAME() / USER | 获取用户在数据库中的名字 |
| is_srvrolemember('sysadmin')<br />is_srvrolemember('db_owner')<br />is_srvrolemember('public') |判断当前用户权限|

### 进制转换
| 函数 | 释义 |
| --- | --- |
| ASCII(str) | 返回字符表达式最左端字符的ASCII 码值 |
| CHAR(str) | 将ASCII 码转换为字符 |
| cast(16 as VARBINARY(50)) | 将16转换为16进制 |
| CONVERT(VARBINARY(50),16) | 将16转换为16进制 |
| master.dbo.fn_varbintohexstr(16)  | 将16转换为16进制 |
| STR(n) | 将数值型数据转为字符型数据 |

### 字符串操作函数
| 函数 | 释义 |
| --- | --- |
| SUBSTRING (`<expression>`， `<starting_ position>`，` length`) | 返回从字符串左边第starting_ position 个字符起length个字符的部分。 |
| LEFT (<character_expression>， <integer_expression>) | 返回character_expression 左起 integer_expression 个字符。 |
| RIGHT (<character_expression>， <integer_expression>) | 返回character_expression 右起 integer_expression 个字符 |
| QUOTENAME (<’character_expression’>[， quote_ character])  | 返回被特定字符括起来的字符串。 |
| REPLICATE (character_expression,integer_expression)  | 返回一个重复character_expression 指定次数的字符串。 |
| REVERSE (<character_expression>)  | 将指定的字符串的字符排列顺序颠倒 |
| REPLACE (<string_expression1>， <string_expression2>， <string_expression3>) | 用string_expression3 替换在string_expression1 中的子串string_expression2。 |
| SPACE (<integer_expression>)  | 返回一个有指定长度的空白字符串。 |
| STUFF (`<character_expression1>`，` <start_ position>`， `<length>`，`<character_expression2>`) | 用另一子串替换字符串指定位置、长度的子串。 |
| LEFT (<character_expression>， <integer_expression>) | 返回character_expression 左起 integer_expression 个字符。 |
| RIGHT (<character_expression>， <integer_expression>) | 返回character_expression 右起 integer_expression 个字符。 |
| CHARINDEX (`<’substring_expression’>`， `<expression>`) | 返回字符串中某个指定的子串出现的开始位置<br />其中substring _expression 是所要查找的字符表达式，expression 可为字符串也可为列名表达式。如果没有发现子串，则返回0 值。<br />此函数不能用于TEXT 和IMAGE 数据类型。 |
| PATINDEX (`<’%substring _expression%’>`， `<column_ name>`) | 其中子串表达式前后必须有百分号“%”否则返回值为0。<br />返回字符串中某个指定的子串出现的开始位置。<br />与CHARINDEX 函数不同的是，PATINDEX函数的子串中可以使用通配符，且此函数可用于CHAR、 VARCHAR 和TEXT 数据类型。 |
| CONCAT | 连接字符串函数，MSSQL 2012+ 支持 |

### 其他函数/语句
| 函数/语句 | 释义 |
| --- | --- |
| IF...ELSE... | 条件语句 |
| case when exp then state1 ELSE state2 end | 条件语句 |
| WAITFOR DELAY '0:0:n' | 延迟n s |
| LEN(str) | 计算字符串长度 |
| LOWER(str) | 将字符串的大写字母全部转成小写 |
| UPPER(str) | 将字符串的小写字母全部转成大写 |
| LTRIM() | 字符串头部的空格去掉 |
| RTRIM()  | 把字符串尾部的空格去掉 |

## 常见SQL语句
### 获取数据库权限
```sql
select is_srvrolemember('sysadmin')
select is_srvrolemember('db_owner')
select is_srvrolemember('public')
```
### 获取系统相关信息
```sql
-- 获取版本
select @@version;
-- 获取用户名
select user;
-- 获取服务器主机名
select @@servername;
```
### 获取数据库
```sql
-- 当前数据库
select db_name();
-- 其他数据库,n为number类型
select db_name(n);
-- 所有数据库
select name from master..sysdatabases;
```
### 获取表
```sql
select name from test..sysobjects where xtype = 'u'
-- 或者
-- 每个库都有information_schema，可以不用加test，也支持跨库查，需要注意这样查询出来使用视图的
select table_name from test.information_schema.tables
-- 从当前库获取表，去除视图
select table_name from information_schema.tables where table_type not in ('view');
```
### 获取字段
```sql
select name from test..syscolumns where id = (select id from test..sysobjects where name = 'users')
-- 或者
select column_name from test.information_schema.columns where table_name = 'users';
--或者，以下不支持跨库查询
select top 1 col_name(object_id('users'),1) from sysobjects;
-- i 为第几个字段，int型
select top 1 col_name(object_id('users'),i) from sysobjects;
```
### 获取值
```sql
select username, password from users;
```
