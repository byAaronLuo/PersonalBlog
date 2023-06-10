## 常见符号
### 注释符
| **符号** | **说明** |
| --- | --- |
| -- | 单行注释
x为任意字符，这里表示有一个空格 |
| /**/ | 多行(内联)注释 |
| &#124;&#124; | 字符串拼接 |
| ::text | 类型转换为text |

## 常见函数/表达式
### 字符串函数
| 函数 | 描述 |
| --- | --- |
| string 丨丨 string | 字串连接
'Post' 丨丨 'greSQL' => PostgreSQL |
| bit_length(string) | 字串里二进制位的个数
bit_length('jose') => 32 |
| char_length(string) | 字串中的字符个数
char_length('jose') => 4 |
| convert(string using conversion_name) | 使用指定的转换名字改变编码。
convert('PostgreSQL' using iso_8859_1_to_utf8) =>'PostgreSQL' |
| lower(string) | 把字串转化为小写 |
| octet_length(string) | 字串中的字节数
octet_length('jose') => 4 |
| overlay(string placing string from int [for int]) | 替换子字串
overlay('Txxxxas' placing 'hom' from 2 for 4) => Thomas |
| position(substring in string) | 返回指定的子字串的位置
position('om' in 'Thomas') =>3 |
| substring(string [from int] [for int]) | 抽取子字串 |
| substring(string from pattern) | 抽取匹配 POSIX 正则表达式的子字串 |
| substring(string from pattern for escape) | 抽取匹配SQL正则表达式的子字串 |
| trim([leading丨trailing 丨 both] [characters] from string) | 从字串string的开头/结尾/两边/ 删除只包含characters(默认是一个空白)的最长的字串 |
| upper(string) | 把字串转化为大写。 |
| ascii(text) | 参数第一个字符的ASCII码 |
| btrim(string text [, characters text]) | 从string开头和结尾删除只包含在characters里(默认是空白)的字符的最长字串 |
| chr(int) | 给出ASCII码的字符 |
| convert(string text, [src_encoding name,] dest_encoding name) | 把字串转换为dest_encoding |
| initcap(text) | 把每个单词的第一个字母转为大写，其它的保留小写。单词是一系列字母数字组成的字符，用非字母数字分隔。 |
| length(string text) | string中字符的数目 |
| lpad(string text, length int [, fill text]) | 通过填充字符fill(默认为空白)，把string填充为长度length。 如果string已经比length长则将其截断(在右边)。 |
| ltrim(string text [, characters text]) | 从字串string的开头删除只包含characters(默认是一个空白)的最长的字串。 |
| md5(string text) | 计算给出string的MD5散列，以十六进制返回结果。 |
| repeat(string text, number int) | 重复string number次。
repeat('Pg', 4) => PgPgPgPg |
| replace(string text, from text, to text) | 把字串string里出现地所有子字串from替换成子字串to。 |
| rpad(string text, length int [, fill text]) | 通过填充字符fill(默认为空白)，把string填充为长度length。如果string已经比length长则将其截断。 |
| rtrim(string text [, character text]) | 从字串string的结尾删除只包含character(默认是个空白)的最长的字 |
| split_part(string text, delimiter text, field int) | 根据delimiter分隔string返回生成的第field个子字串(1 Base)。
split_part('abc~@~def~@~ghi', '~@~', 2) => def |
| strpos(string, substring) | 声明的子字串的位置。
strpos('high','ig') => 2  |
| substr(string, from [, count]) | 抽取子字串。 |
| to_hex(number int/bigint) | 把number转换成其对应地十六进制表现形式。 |
| translate(string text, from text, to text) | 把在string中包含的任何匹配from中的字符的字符转化为对应的在to中的字符。
translate('12345', '14', 'ax') => a23x5
 |

### 转换函数
| **函数** | **描述** |
| --- | --- |
| to_char(timestamp, text) | 将时间戳转换为字符串 |
| to_char(interval, text) | 将时间间隔转换为字符串 |
| to_char(int, text) | 整型转换为字符串 |
| to_char(double precision, text) | 双精度转换为字符串 |
| to_char(numeric, text) | 数字转换为字符串 |
| to_date(text, text) | 字符串转换为日期 |
| to_number(text, text) | 转换字符串为数字 |
| to_timestamp(text, text) | 转换为指定的时间格式 time zone convert string to time stamp |
| to_timestamp(double precision) | 把UNIX纪元转换成时间戳 |

### 其他函数/表达式
| **表达式** | **说明** |
| --- | --- |
| case...when(expr) then result1 else result2 end | 同if 表达式 |

## 语句归类
### 获取数据库版本
```sql
select version()
```
### 获取当前用户
```sql
select user;
```
### 获取所有的数据库
```sql
select datname from pg_database;
```
### 获取当前数据库
```sql
select current_database();
```
### 获取当前数据库所有schema
```sql
select schemaname from pg_tables
```
### 获取当前schema的表名
```sql
select tablename from pg_tables where schemaname = 'public'
-- 或者从该库的information_schema.tables获取
select table_name from information_schema.tables where table_schema='public'
```
### 获取当前表的列名
```sql
SELECT attname FROM pg_namespace,pg_type,pg_attribute b JOIN pg_class a ON a.oid=b.attrelid WHERE a.relnamespace=pg_namespace.oid AND pg_type.oid=b.atttypid AND attnum>0 AND a.relname='products' AND nspname='public';
select column_name from information_schema.columns where table_name = 'products';
```
### 获取当前表的值
```sql
select name from products
```
