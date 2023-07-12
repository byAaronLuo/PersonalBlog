## 常用符号
| 符号 | 释义 |
| :-: | :-: |
| -- | 单行注释符 |
| /**/ | 多行注释符 |
| &#124;&#124; | 用于字符拼接 |
| null | 表示空字符串 |
| dual | 虚拟表，在进行select操作必带 |

## 常用函数
### 字符函数
| 函数 | 释义 |
| :-: | --- |
| ascii | select ascii('a') from dual 结果97 |
| chr | select chr(97) from dual 结果'a' |
| upper | SELECT Upper ('abcde') FROM dual  结果：ABCDE |
| lower | SELECT lower('ABCDE') FROM dual 结果：abcde |
| initcap | SELECT Initcap ('AAA') FROM dual 结果：Aaa<br />SELECT Initcap ('aaa') FROM dual 结果：Aaa |
| concat | SELECT Concat ('a', 'b') FROM dual 结果：ab<br />Select 'a' &#124;&#124; 'b' from dual 结果：ab |
| substr | Select substr('abcde',0,3) from dual 结果：abc |
| length | Select length('abcde') from dual 结果：5 |
| replace | Select replace('abcde','a','A') from dual 结果：Abcde |
| instr | Select instr('Hello World','W') from dual 结果：8<br />Select instr('Hello World','w') from dual 结果：0<br />如果在第一个参数中存在第二个参数，则返回第一个遇到的匹配参数的位置，该方法区分大小写 |
| trim | select trim(' Mr Smith ') from dual 结果：Mr Smith |
| lpad | select lpad('Smith',10,'*') from dual 结果：*****Smith |
| rpad | select rpad('Smith',10,'*') from dual 结果：Smith***** |

### 数学函数
| 函数 | 释义 |
| --- | --- |
| round | select round(412,-2) from dual;  结果：400<br />向上取整运算，第二个参数指定了取小数点后的几位，如果是5则进一。 |
| Mod | select Mod(198,2) from dual 结果：0<br />取模运算 |
| ABS | select abs(-2) from dual 结果： 2 |
| Trunc | select trunc(412.13,2) from dual   结果：412.13<br />select trunc(412.53) from dual     结果：412<br />向下取整运算，第二个参数指定了取小数点后的几位 |

### 转换函数
| 函数 | 释义 |
| --- | --- |
| to_char | select to_char(1) from dual 结果：'1' |
| to_number | select to_number('1') from dual 结果：1 |
| to_date | select to_date('2021-1-1','yyyy-MM-dd') from dual 结果：01-JAN-21 |

### 其他函数/表达式
| 函数 | 释义 |
| --- | --- |
| NVL | select nvl('string',0) from dual 结果：string<br />select nvl('',0) from dual 结果：0<br />从两个表达式返回一个非 null 值 |
| NULLIF | select nullif('abc','abc') from dual 结果：空<br />select nullif('abc','abcd') from dual 结果：abc<br />如果两个指定的表达式相等，则返回空值，否则返回第一个表达式 |
| NVL2 | select nvl2('a','b','c') from dual 结果：b<br />select nvl2('','b','c') from dual 结果：c<br />如果第一个参数不为空，则返回第二个参数；否则，返回第三个参数 |
| decode | select decode('1','1',1,2) from dual; 结果：1<br />第一个参数是否等于第二个参数，如果等于，则返回第三个参数，否则返回第四个参数，可用于行转列 |
| DBMS_PIPE.RECEIVE_MESSAGE | select dbms_pipe.receive_message('o',10)from dual; 结果：1<br />时间注入函数，两个参数，从指定管道获取消息,timeout 为 integer的可选输入参数，用来指定等待时间 |
| case...when...then..else...end | select case when 1=1 then 1 else 2 end from dual 结果：1 |

## 语句归类
### 获取数据库版本
```sql
SELECT banner FROM v$version WHERE banner LIKE 'Oracle%';
SELECT version FROM v$instance;
```
### 获取操作系统版本
```sql
SELECT banner FROM v$version where banner like 'TNS%'
```
### 获取当前用户权限的所有数据库
```sql
SELECT DISTINCT owner FROM all_tables;
```
### 获取当前数据库
这里需要说明一下，由于Oracle 中使用 Schema 的概念将每个用户的数据进行分离，Schema 其实类似于命名空间（Namespace），默认情况下，Schema 的名称同用户名称相同，其实在这里用这种方法去查所谓的当前数据库，但是在`all_tables`里其实都没有，使用SQLMAP跑出来的库也没有，所以当前数据库使用`select user from dual`
```sql
SELECT global_name FROM global_name;
SELECT name FROM v$database;
SELECT instance_name FROM v$instance;
SELECT SYS.DATABASE_NAME FROM DUAL;
```
### 获取用户信息
```sql
-- 当前数据库用户
SELECT user FROM dual;
-- 所有数据库用户
SELECT username FROM all_users ORDER BY username;
-- 当前用户权限
SELECT * FROM session_privs;
-- 用户角色
SELECT GRANTEE, GRANTED_ROLE FROM DBA_ROLE_PRIVS;
```
### 获取当前数据库中的表名
```sql
-- 以SYSTEM 为例子
-- 所有用户的表
select distinct table_name from all_tables where owner = 'SYSTEM'
-- 当前用户的表，这里会有很多不需要的数据，其实不建议使用
select table_name from user_tables;
-- 包括系统表，需要高权限
select table_name from dba_tables where owner = 'SYSTEM'; 
```
### 获取当前数据库下某表的所有列名
```sql
select column_name from all_tab_columns where table_name ='USERS_KVHXKJ'
```
### 查询值
```sql
select USERNAME_ETSGGX,PASSWORD_OEDQBQ from USERS_KVHXKJ
```
### 子查询，分页实现limit
```sql
-- 这里以获取当前用户权限所拥有的数据库
-- 以下是实现limit 1,1
select owner from (select t.owner,rownum as no from (select distinct owner from all_tables)t) where no = 1
-- 实现多个 使用between and
select owner from (select t.owner,rownum as no from (select distinct owner from all_tables)t) where no between 1 and 10
```
