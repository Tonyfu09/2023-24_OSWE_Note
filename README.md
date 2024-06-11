<!--
# Disclaimer
All Resources below is only for education purpose for everyone who wanted to learn OSWE.
!-->

# 2023-24_OSWE Preparation
The Summary here only forcus on web vulnerabilit and how we could get the initial shell from those web vulnerability. Embark on a comprehensive exploration of various web application vulnerabilities, deeply into understanding the OWASP Top 10.

## Course could helps 
1. Hands on exprience on web vulnerability [PentesterLab](https://pentesterlab.com/) , [White Badge Exercises](https://pentesterlab.com/badges/whitebadge) <br>
2. Code logic knowledge [Codecademy](https://www.codecademy.com/) <br>
3. Pentest Course [Pentester Academy](https://www.pentesteracademy.com/) <br>

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

OSWAP [Sample](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema) also provides different way of Authentication Bypass. In order to preform authentication bypass, we will require to modify the value of parameter or logicially to make the application trust you are authenticated.

- ### Bypass regular login
As mentioned by [Hacktricks](https://book.hacktricks.xyz/pentesting-web/login-bypass), one common approach involves leveraging various techniques to attempt to bypass login pages. <br> 

Question could ask
- 1. The user ID you could?
- 2. How the user obtain the password via signup
- 3. How the user while they forgot password
- 4. How the user password save to database
- 5. How to explore table scheme outsite
- 6. What is the authentication method for user?
- 7. what is the sql query can get the passowrd
- 8. Try to figure it out the important element to cract the token

Login page Check list also avaliable (https://github.com/Mehdi0x90/Web_Hacking/blob/main/Login%20Bypass.md)

- ### PHP Type Juggling
PHP does not require explicit type definition in variable declaration. In this case, the type of a variable is determined by the value it stores. [Definition from PHP](https://www.php.net/manual/en/language.types.type-juggling.php) 

PHP Loose comparisons will lead to vulnerability to return the result that didn't expect [PHP Loose comparisons](https://www.php.net/manual/en/types.comparisons.php)

Simplify PHP Type Juggling - https://secops.group/php-type-juggling-simplified/

- ### SQL Injection
The Union keyword to retrieve data from other tables within the database for sql injection. - [PortSwigger](https://portswigger.net/web-security/sql-injection/union-attacks) <br>
more caution about the collation https://dev.mysql.com/doc/refman/8.0/en/charset-collate.html

## JavaScript Injection

- ### Prototype Pollution
Prototype pollution often happen when an attacker inject javascript code. The attacker is attempting to control the default values of an object's properties. <br>
Example from snyk - https://learn.snyk.io/lesson/prototype-pollution/ <br>

## XML External Entity (XXE) Attack

XXE (XML External Entity) Attack is a vulnerability that allows an attacker to interfere with an application's processing of XML data. The impact can range from the attacker viewing files on the application server filesystem to more severe consequences like remote code execution.  <br>

### Resources:
- [OWASP Description](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
- [PortSwigger on Blind XXE Vulnerabilities](https://portswigger.net/web-security/xxe/blind)

## XML Entities

XML documents can define entities which can be referenced within the document. There are three types of XML entities:

1. **Internal Entities**: Defined within the XML document.
2. **External Entities**: Referenced from an external source.
3. **Parameter Entities**: Used within DTDs (Document Type Definitions).

DTDs define the structure, legal elements, and attributes of an XML document.

## Steps to Exploit XXE Vulnerability
- Search that if the application accept to receive the XML parsing in some of field.
- Enumerate the directory
- Read the sensitive file
- Write the file in the target library 

Detailed Sample and explaination [w3s XML DTD](https://www.w3schools.com/xml/xml_dtd.asp)

Attack vector 
- XXE vulnerability lead to attack retrieve sensitive file from server
- XXE vulnerability to call the other vulnerability function

## Server Side Request Forgery (SSRF)
SSRF is the type which the attack forcus the server send the web request the attack wants. Different types could refer https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery. 

## Server Side Template Injection (SSTI)
Server Side Template Injection is focus on the template injection that is execute on web server.

1. [First Jinja template ](https://realpython.com/primer-on-jinja-templating/) is good for understand if you are first time have exprience with Jinja. Two step involves 1. Load a template and 2. Render the template
2. Detailed explanation of [SSTI](https://portswigger.net/research/server-side-template-injection)
3. Inject payload to easy define if the server getting template expressions, such as {{7*7}}, ${7*7}

[Jinja Template Design Document](https://jinja.palletsprojects.com/en/3.1.x/templates/)

- ### Example - Twig from [OWASP](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection)
There is a function execute by server into the PHP code snippet and could be vulnerable.

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

## NodeJS

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

# Tools (Not Allow use Automatic Tools in Exam)
MD5 Collisions - https://github.com/cbornstein/pymd5-collisions <br>
dnspy - .NET Debugger - https://github.com/dnSpy/dnSpy/releases <br>
pgAdmin - https://www.pgadmin.org/ Front end for PostgreSQL <br>
XSS Playload - https://github.com/payloadbox/xss-payload-list <br>
SSRF Map - https://github.com/swisskyrepo/SSRFmap
Remote Debugger for (vs-2019) - https://github.com/MicrosoftDocs/visualstudio-docs/blob/main/docs/python/includes/vs-2019/remote-debugging-python-code.md
