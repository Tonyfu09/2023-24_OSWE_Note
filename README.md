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
1. z-r0crypt's Blog
https://z-r0crypt.github.io/blog/2020/01/22/oswe/awae-preparation/ <br>
2. Sarthak Saini's Personal Experience
https://sarthaksaini.com/about-me.html <br>
3. Charchit Verma's Review
https://charchitverma100.medium.com/an-honest-oswe-2023-review-my-journey-preparation-and-exam-67d0adcbcde4

# OSWE prepare OSWAP Top 10 Related Topic

## Cross Site Scripting (XSS)

XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user. 

1. DOM-based XSS <br>
The Document Object Model (DOM) is structured as a tree of objects, typically manipulated using JavaScript to render HTML in a browser. If an attacker can modify a JavaScript function, a DOM-based XSS (Cross-Site Scripting) vulnerability could allow them to control DOM elements. <br>

The Document Object Model tree is illustrate on w3schools: <br>
![image](https://github.com/Tonyfu09/2023-24_OSWE_Note/assets/39818274/88ee655c-5504-4e6d-b921-8296defd30cf)

- Adversary passes parameter to a sink that supports dynamic code execution to hijack other account
- 

2. Reflected DOM-based XSS <br>
An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will cause JavaScript code supplied by the attacker to execute within the user's browser in the context of that user's session with the application.

- Server-Site proccess data from the request, an attacker take advantage of it.
- An Attack analyst what the plug in that running on the web apps.

3. Stored DOM-based XSS <br>
An attacker able to send the request to the target server and store it in the server, then use it in a later stage.

- Server-Site proccess data from the request, an attacker take advantage to stores it, and then includes the data in a later response.Stored XSS is also sometimes referred to as Persistent or Type-II XSS.

As three of XSS above coud happening at the same attack period. Further reading could be the Client XSS and Server XSS from [Types of XSS](https://owasp.org/www-community/Types_of_Cross-Site_Scripting) also helps clear things.

### XSS to RCE
XSS Vulnerability Payload List - https://github.com/payloadbox/xss-payload-list <br>
good to pratice - https://pentesterlab.com/exercises/xss_and_mysql_file/course <br>

### Cross-Origin Resource Sharing (CORS)
Cross-Origin Resource Sharing (CORS) is a mechanism that allows an application to load scripts or other resources from different domains, schemes, or ports.

Key header to describe CORS as follows:
   - CORS HTTP REQUEST HEADERS
     - [ ] Origin, define where to send the request
     - Access-Control-Request-Headers
     - Access-Control-Request-Method

   - CORS HTTP RESPONSE HEADERS
     - [ ] Access-Control-Allow-Origin, there are three types of value respectivetly *, <origin>, null as defined in mozilla https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
     - Access-Control-Allow-Credentials
     - Access-Control-Allow-Headers
     - Access-Control-Allow-Methods
     - Access-Control-Expose-Headers
     - Access-Control-Max-Age
     - Timing-Allow-Origin

### SameSite Attribute
The SameSite attribute lets servers specify whether/when cookies are sent with cross-site requests from [Using HTTP cookies in Mozilla](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies)

## Authentication Bypass

OSWAP [WSTG - Latest Sample](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema) also provides different way of Authentication Bypass. In order to preform authentication bypass, we will require to modify the value of parameter or logicially to make the application trust you are authenticated.

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

## JavaScript Injection

- ### Prototype Pollution
Prototype pollution often happen when an attacker inject javascript code. The attacker is attempting to control the default values of an object's properties. <br>
Example from snyk - https://learn.snyk.io/lesson/prototype-pollution/ <br>

#### Function constructor decribe as [Javascript function constructor](https://www.geeksforgeeks.org/prototype-in-javascript/) 
<code>
function Person(name, job, yearOfBirth){   
    this.name= name;
    this.job= job;
    this.yearOfBirth= yearOfBirth;
}
</code>

Indepe explaination from Hacktrike about how Prototype pollution is working [Hacktricks Prototype Pollution](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution)

#### Prototype pollution sinks <br>
- Descripte that some javascript function or DOM element that you're able to access via prototype pollution which enable for adversary execute arbitary JavaScript or system commands. <br>

#### Prototype pollution gadgets <br>
- According the description from [Prototype pollution](https://portswigger.net/web-security/prototype-pollution), the prototype pollution gadgets is more about the process turming the prototype pollution vulnerability into an actual exploit. That's means the vulnerability is criticial. <br>

#### Step to identifies <br>
1. Discover any functions that allow the addition of arbitrary properties to global object prototypes, which can then be inherited by user-defined objects. <br>
2. Add arbitrary properties to prototype objects. <br>
3. Reveal and test whether it is possible to control and pollute the objects. <br>
4. Verify the value change after the pollution, does the program crash or the value of the key is actually got changed?

## XML External Entity (XXE) Attack

XXE (XML External Entity) Attack is a vulnerability that allows an attacker to interfere with an application's processing of XML data. The impact can range from the attacker viewing files on the application server filesystem to more severe consequences like remote code execution.  <br>

### Resources:
- [OWASP Description](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
- [PortSwigger on Blind XXE Vulnerabilities](https://portswigger.net/web-security/xxe/blind)

#### XML Entities

XML documents can define entities which can be referenced within the document. There are three types of XML entities:

1. **Internal Entities**: Defined within the XML document.
2. **External Entities**: Referenced from an external source.
3. **Parameter Entities**: Used within DTDs (Document Type Definitions).

DTDs define the structure, legal elements, and attributes of an XML document.

#### Steps to Exploit XXE Vulnerability
- Search that if the application accept to receive the XML parsing in some of field.
- Enumerate the directory
- Read the sensitive file
- Write the file in the target library 
- Generally, the XML file would not execute directly

Detailed Sample and explaination [w3s XML DTD](https://www.w3schools.com/xml/xml_dtd.asp)

Attack vector 
- XXE vulnerability lead to attack retrieve sensitive file from server
- XXE vulnerability to call the other vulnerability function

## Server Side Request Forgery (SSRF)
SSRF is the type which the attack forcus the server send the web request the attack wants. Different types could refer https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery. 

- Identify the SSRF exist in the application
1. Send the different version and different method of the api endpoints could gathering some vulnerability, also if it could gain more internal information to create map for the attacker.
2. Identify the SSRF vulnerability to determine if there have been any unexpected commands run on the server side to make an request.

- Exfiltration
1. Set up a web server in your environment to gather data sent from the victim.
2. Analyze the data and parameters received from the victim.

- Remote Code Execution
1. Code analyst to discover vulnerability services

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
1. Discover escape string 

- ### SQL Injection
The Union keyword to retrieve data from other tables within the database for sql injection. - [PortSwigger](https://portswigger.net/web-security/sql-injection/union-attacks) <br>
more caution about the collation https://dev.mysql.com/doc/refman/8.0/en/charset-collate.html

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
|Vault|WebApp Enumeration, Bypass,  |Linux|
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
