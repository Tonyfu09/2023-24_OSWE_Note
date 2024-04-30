<!--
# Disclaimer
All Resources below is only for education purpose for everyone who wanted to learn OSWE.
!-->

# 2023-24_OSWE Preparation
The Summary here only forcus on web vulnerabilit and how we could get the initial shell from those web vulnerability. Embark on a comprehensive exploration of various web application vulnerabilities, deeply into understanding the OWASP Top 10.

## Course could helps 
1. Hands on exprience on web vulnerability https://pentesterlab.com/ , White Exercises in https://pentesterlab.com/badges/whitebadge<br>
2. Code logic knowledge https://www.codecademy.com/ <br>

## OSWEer's Advice
- https://z-r0crypt.github.io/blog/2020/01/22/oswe/awae-preparation/ <br>
- https://sarthaksaini.com/about-me.html <br>
- https://charchitverma100.medium.com/an-honest-oswe-2023-review-my-journey-preparation-and-exam-67d0adcbcde4

# OSWE prepare OSWAP Top 10 Related Topic

## XSS to RCE
XSS Vulnerability Payload List - https://github.com/payloadbox/xss-payload-list <br>
good to pratice - https://pentesterlab.com/exercises/xss_and_mysql_file/course <br>

## Bypassing File Upload Restrictions

## Authentication Bypass

OSWAP [Sample](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema) also provides different way of Authentication Bypass.


## JavaScript Injection

- ### Prototype Pollution
Prototype pollution often happen when an attacker inject javascript code. The attacker is attempting to control the default values of an object's properties. <br>
Example from snyk - https://learn.snyk.io/lesson/prototype-pollution/ <br>

## PHP Type Juggling
Simplify PHP Type Juggling - https://secops.group/php-type-juggling-simplified/

## XML External Entity (XXE) Attack
XXE Attack is the vulnerability that allows an attacker to interfere with an application's processing of XML data. The impact is for the attack to view files on the application server filesystem.  <br>
OSWAP Description - https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing  <br>
PortSwigger about blind XXE vulnerbilities - https://portswigger.net/web-security/xxe/blind  <br>

## Server Side Request Forgery (SSRF)
SSRF is the type which the attack forcus the server send the web request the attack wants. Different types could refer https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery. 

## Server Side Template Injection (SSTI)

## NodeJS

## SQLi
SQL injection (SQLi) is a major web application vulnerability class prevalent in many web applications. <br>
1. Error-Based SQL Injections
- In-band SQL Injection technique that relies on error messages thrown by the database server to obtain information about the structure of the database.
- 
2. Union-Based SQL Injections
- The UNION operator is used to combine the result-set of two or more SELECT statements which return as part of the HTTP response.
- 
3. Blind Boolean-based SQL Injections:
- Blind SQL (Structured Query Language) injection is a type of SQL Injection attack that asks the database true or false questions and determines the answer based on the applications response. 
- https://owasp.org/www-community/attacks/Blind_SQL_Injection

Skill set for encoding and decoding also would be helpful for bypass the payload into the sql injection.

- ### SQL injection Explain and sample testing <br>
https://www.sqlinjection.net/detection/ <br>
https://portswigger.net/web-security/sql-injection <br>

## Serialization and Deserialization
Serialization, as defined by Microsoft, is the conversion of an object's state into a format suitable for persistence or transportation. You can find more about this definition on Microsoft's website. Deserialization, on the other hand, involves reconstructing an object from its serialized form to restore its original state.

For a practical example of deserializing objects, you can refer to the following link: [Newtonsoft's documentation on deserializing objects](https://www.newtonsoft.com/json/help/html/deserializeobject.htm). Additionally, there's a helpful sample code in C# available online, which you can access through this link: [Sample code on GitLab](https://gitlab.com/-/snippets/2496138).

Insecure deserialization could allow an attacker to control the serialized object, enabling the injection of malicious code into the victim's system, thus bypassing file upload security measures. The vulnerability is further detailed as mentioned on [OWASP Top 10 - Insecure Deserialization](https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization)

## Resource
Hacktrick https://book.hacktricks.xyz/pentesting-web/sql-injection <br>
PostgreSQL Dollar quoted string constants https://www.postgresqltutorial.com/postgresql-plpgsql/dollar-quoted-string-constants/

# The Box have been pwanded 

From OSWE Like Box https://docs.google.com/spreadsheets/u/1/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview

# HTB
|BoxName|TechForBox|OS|
|---|---|---|
|Vault|Not Yet|Linux|
|Popcorn|Not Yet|Linux|
|Celestial|Not Yet|Linux|
|Blocky|Not Yet|Linux|
|Falafel|Not Yet|Linux|
|Zipper|Not Yet|Linux|
|Unattended|Not Yet|Linux|
|Help|Not Yet|Linux|
|Mango|Not Yet|Linux|
|Schooled|Not Yet|Linux|
|Sink|Not Yet|Linux|
|Monitors|Not Yet|Linux|
|Magic|Not Yet|Linux|
|Unobtainium|Not Yet|Linux|
|Crossfit|Not Yet|Linux|
|Crossfit2|Not Yet|Linux|
|Stacked|Not Yet|Linux|
|Fingerprint|Not Yet|Linux|
|JSON|Not Yet|Windows|

# Vulnhub (only for web vulnerility leads to RCE)
|BoxName|TechForBox|OS|
|---|---|---|
|Silky-CTF|Commands Injection|Linux|
|bwapp|OWASP Top 10 Box|Linux|
|Homeless|Arbitrary file upload to LFI, code analysis to observe md5 collisions|Linux|
|Seattle|Not Yet|Linux|
|Ted 1|Not Yet|Linux|
|Raven 2|Not Yet|Linux|
|Potato|Not Yet|Linux|
|Secure Code 1|Not Yet|Linux|
|Pipe|Not Yet|Linux|

# Payload Cheetsheet
Command injection https://github.com/payloadbox/command-injection-payload-list <br>
XSS Playload https://github.com/payloadbox/xss-payload-list  <br>
SQL injection Payload https://github.com/payloadbox/sql-injection-payload-list <br>
Payload All the Thing https://swisskyrepo.github.io/PayloadsAllTheThingsWeb/SQL%20Injection/ <br>
Markdown Cheatsheet https://github.com/lifeparticle/Markdown-Cheatsheet <br>

# Formatting syntax for Github 
https://medium.com/analytics-vidhya/writing-github-readme-e593f278a796 <br>
https://docs.github.com/en/get-started/writing-on-github/getting-started-with-writing-and-formatting-on-github/basic-writing-and-formatting-syntax <br>

# Tools
MD5 Collisions - https://github.com/cbornstein/pymd5-collisions <br>
dnspy - .NET Debugger - https://github.com/dnSpy/dnSpy/releases <br>
pgAdmin - https://www.pgadmin.org/ Front end for PostgreSQL <br>
XSS Playload - https://github.com/payloadbox/xss-payload-list <br>
SSRF Map - https://github.com/swisskyrepo/SSRFmap
