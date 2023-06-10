## 常用符号
### 注释符
| **注释符** | **说明** |
| --- | --- |
| #
url编码:%23 | 单行注释
在URL中#表示锚点，也就是hash路由，带上#不会请求后端路由，而是刷新前端路由 |
| -- x | 单行注释
x为任意字符，这里表示有一个空格 |
| /**/  | 多行(内联)注释 |

### 常用运算符
| **运算符** | **说明** |
| --- | --- |
| && | 同 and |
| &#124;&#124; | 同 or |
| ! | 同 not |
| ^ | 异或，同xor |
| \\ | 转义符 |
| ~ | 一元比特反转 |
| + | 加，可替代空格 |

### 常见全局变量
| **变量** | **说明** |
| --- | --- |
| @@VERSION | 返回版本信息 |
| @@GLOBAL.VERSION | 同@@VERSION |
| @@HOSTNAME | 返回安装的计算机名称 |
| @@BASEDIR | 返回MYSQL绝对路径 |

## 常用函数
### 系统函数信息
| **函数** | **说明** |
| --- | --- |
| USER() | 获取当前操作句柄的用户名，同SESSION_USER()、CURRENT_USER()，有时也用SYSTEM_USER()。 |
| DATABASE() | 获取当前选择的数据库名，同SCHEMA() |
| VERSION() | 获取当前版本信息。 |

### 进制转换
| **函数** | **说明** |
| --- | --- |
| ORD(str) | 返回字符串第一个字符的ASCII值。 |
| OCT(N) | 以字符串形式返回 N 的八进制数，N 是一个BIGINT 型数值，作用相当于`CONV(N,10,8)`。 |
| HEX(N_S) | 参数为字符串时，返回 N_or_S 的16进制字符串形式，为数字时，返回其16进制数形式。 |
| UNHEX(str) | HEX(str) 的逆向函数。将参数中的每一对16进制数字都转换为10进制数字，然后再转换成 ASCII 码所对应的字符。 |
| BIN(N) | 返回十进制数值 N 的二进制数值的字符串表现形式。 |
| ASCII(str) | 同`ORD(string)`。 |
| CONV(N,from_base,to_base) | 将数值型参数 N 由初始进制 from_base 转换为目标进制 `to_base` 的形式并返回。 |
| CHAR(N,... [USING charset_name]) | 将每一个参数 N 都解释为整数，返回由这些整数在 ASCII 码中所对应字符所组成的字符串。 |

### 字符串截取/拼接
| **函数** | **说明** |
| --- | --- |
| SUBSTR(str,N_start,N_length) | 对指定字符串进行截取，为SUBSTRING的简单版。 |
| SUBSTRING() | 多种格式SUBSTRING(str,pos)、
SUBSTRING(str FROM pos)、SUBSTRING(str,pos,len)、
SUBSTRING(str FROM pos FOR len)。 |
| RIGHT(str,len) | 对指定字符串从最右边截取指定长度。 |
| LEFT(str,len) | 对指定字符串从最左边截取指定长度。 |
| RPAD(str,len,padstr) | 在 str 右方补齐 len 位的字符串 padstr，返回新字符串。如果 str 长度大于 len，则返回值的长度将缩减到 len 所指定的长度。 |
| LPAD(str,len,padstr) | 与RPAD相似，在str左边补齐。 |
| MID(str,pos,len) | 同于 SUBSTRING(str,pos,len)。 |
| INSERT(str,pos,len,newstr) | 在原始字符串 str 中，将自左数第 pos 位开始，长度为 len 个字符的字符串替换为新字符串 newstr，然后返回经过替换后的字符串。INSERT(str,len,1,0x0)可当做截取函数。 |
| CONCAT(str1,str2...) | 函数用于将多个字符串合并为一个字符串 |
| GROUP_CONCAT(...) | 返回一个字符串结果，该结果由分组中的值连接组合而成。 |
| MAKE_SET(bits,str1,str2,...) | 根据参数1，返回所输入其他的参数值。可用作布尔盲注，如：EXP(MAKE_SET((LENGTH(DATABASE())>8)+1,'1','710'))。 |

### 其他常见函数
| **函数/语句** | **说明** |
| --- | --- |
| IF(exp,state1,state2) | 条件语句，exp为true，执行state1，否则执行state2 |
| CASE...WHEN exp THEN state1 ELSE state2 END | 同IF |
| SLEEP(N) | 休眠N秒 |
| BENCHMARK(count,exp)：  | 执行表达式exp，count次（消耗CPU） |
| LENGTH(str) | 返回字符串的长度。 |
| PI() | 返回π的具体数值。 |
| REGEXP "statement" | 正则匹配数据，返回值为布尔值。 |
| LIKE "statement" | 匹配数据，%代表任意内容。返回值为布尔值。 |
| RLIKE "statement" | 与regexp相同。 |
| LOCATE(substr,str,[pos]) | 返回子字符串第一次出现的位置。 |
| POSITION(substr IN str) | 等同于 LOCATE()。 |
| LOWER(str) | 将字符串的大写字母全部转成小写。同：LCASE(str)。 |
| UPPER(str) | 将字符串的小写字母全部转成大写。同：UCASE(str)。 |
| ELT(N,str1,str2,str3,...) | 与MAKE_SET(bit,str1,str2...)类似，根据N返回参数值。 |
| NULLIF(expr1,expr2) | 若expr1与expr2相同，则返回expr1，否则返回NULL。 |
| CHARSET(str) | 返回字符串使用的字符集。 |
| DECODE(crypt_str,pass_str) | 使用 pass_str 作为密码，解密加密字符串 crypt_str。加密函数：ENCODE(str,pass_str)。 |

## 常用语句
### 获取数据库版本
```sql
select version();
```
### 获取当前用户
```sql
select user()
```
### 获取所有数据库
```sql
select schema_name from information_schema.schemata;
```
### 获取当前数据库
```sql
select database()
```
### 获取用户
```sql
desc mysql.user
select * from mysql.user 
```
### 获取当前数据库的表名
```sql
select table_name from information_schema.tables where table_schema = database()
```
### 获取当前数据库的某表的列名
```sql
select column_name from information_schema.columns where table_name = 'users'
```
### 获取当前数据库某表的值
```sql
select id ,username,password from users;
```
