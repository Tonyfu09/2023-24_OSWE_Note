<!--
# Disclaimer
All Resources below is only for education purpose for everyone who wanted to learn OSWE.
!-->

# 2023-24_OSWE Preparation
The Summary here only forcus on web vulnerabilit and how we could get the initial shell from those web vulnerability. Embark on a comprehensive exploration of various web application vulnerabilities, deeply into understanding the OWASP Top 10.

## Course could helps 
1. Hands on exprience on web vulnerability https://pentesterlab.com/ <br>
2. Code logic knowledge https://www.codecademy.com/

## OSWEer's Advice
- https://z-r0crypt.github.io/blog/2020/01/22/oswe/awae-preparation/ <br>
- https://sarthaksaini.com/about-me.html <br>

# OSWE prepare OSWAP Top 10 Related Topic

## XSS to RCE
XSS Vulnerability Payload List - https://github.com/payloadbox/xss-payload-list <br>
good to pratice - https://pentesterlab.com/exercises/xss_and_mysql_file/course <br>

## Bypassing File Upload Restrictions

## Authentication Bypass to RCE

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
SQL injection (SQLi) is a major web application vulnerability class prevalent in many web applications. 

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

<!-- 
# OSWE Like Topic

1. Source Code Audit
2.  (Archived)ATutor Authentication Bypass and RCE
	1. test
	2. test
3.  (Archived)ATutor LMS Type Juggling Vulnerability
	1. PHP Strict compasion and loose compasion
	2. 
	3. 
4.  ManageEngine Applications Manager AMUserResourcesSyncServlet SQL Injection RCE
	1. test
	2. test
	3. Stacked Queries https://www.sqlinjection.net/stacked-queries/
5.  Bassmaster NodeJS Arbitrary JavaScript Injection Vulnerability
	1. Regular expression - https://regex101.com/
        2. Regular expression explain - https://hackmd.io/@Heidi-Liu/regex#Why-we-need-Regular-Expression
	2. JavaScript RegExp Reference - https://www.w3schools.com/jsref/jsref_obj_regexp.asp
        3. (execute a shell) hex-encode our forward slashes and bypass the restrictions of the regex parsing
6.  DotNetNuke Cookie Deserialization RCE
	1. C# Serialize and Deserialize https://blog.miniasp.com/post/2008/03/19/How-to-serialize-and-deserialize-using-C-NET
        2. .NET Documentation https://learn.microsoft.com/en-us/dotnet/?view=net-8.0
	3. Generating payloads that exploit unsafe .NET object deserializationhttps://github.com/pwntester/ysoserial.net
7.  ERPNext Authentication Bypass and Server Side Template Injection
	1. SQL Injection - utf8mb4_general_ci - https://dev.mysql.com/doc/refman/8.0/en/charset-unicode-sets.html
	2. Frappe Framework - https://frappeframework.com/docs/v15/user/en/tutorial/create-a-doctype
 	3. 
  	4. 
   	5. 
8.  openCRX Authentication Bypass and Remote Code Execution
	1. Java application analysis, tree -L 3
	2. XXE (XML External Entity) vulnerability
 	3. XXE Attack submitted - <!DOCTYPE reset [ <!ENTITY qaz SYSTEM "/etc/passwd"> ]> <reset>&qaz;</reset>
 	4. JAVA RCE - create a feature void, create a procedure and call that feature.
9.  openITCOCKPIT XSS and OS Command Injection - Blackbox
	1. XSS - The Browser Exploitation Framework (BeEF)
	2. DOM - HTML elements via the getElementByID and getElementsByTagName methods.
	3. Websocket - How to obtain a url and key from websocket server 
 	4. OS Command injection combining a fuzzing skill
  	5. 
10.  Concord Authentication Bypass to RCE
Reference : https://fetch.spec.whatwg.org/#cors-request
	1. CORS, Access-Control-Allow-Origin have three values *, null and origin. https://fetch.spec.whatwg.org/#cors-request
	2. SameSite Attribute, [http-response] Set-Cookie: session=ABCDEFGHIJKLMNO; Path=/; Max-Age=0; SameSite=Lax; *three of attribute: Strict, None, and Lax. Understanding the relationship between SOP, CORS, and the SameSite attribute is critical in understanding how and when an application might be vulnerable to CSRF.
 	3. CORS exploits are similar to reflected Cross-Site Scripting (XSS) in that we must send a link to an already-authenticated user in order to exploit something of value
  	4. Liquibase.xml, Liquibase is an open-source database schema change management solution which enables you to manage revisions of your database changes easily.
11.  Server-Side Request Forgery
	1. Directus v9.0.0 rc34
	2. API gateways for microservices
 	3. API Discovery via Verb Tampering, the way to retrieve api with error code 204,401,403,404
  	4. Server-Side Request Forgery (SSRF) occurs when an attacker can force an application or server to request data or a resource. 
  	5. Blind SSRF vulnerability when the request got 403 forbiddenm but the server have 200 return data but actually does not return the result of the forged request. 
  	6. Blind SSRF vulnerability cannot access the results of SSRF
  	7. Error messages to determine if we've requested a valid resource
  	8. Headless Chrome - A headless browser is a browser without a graphical user interface. Instead of controlling the browser’s actions via its graphical user interface (GUI), headless browsers are controlled using the command line.
  	9. 
12.  Guacamole Lite Prototype Pollution	
	1. Object Prototype - https://developer.mozilla.org/en-US/docs/Learn/JavaScript/Objects/Object_prototypes. The respectivitly would be the object class prototype, student prototype and s object directly.
	2. Module with EJS, Handlebars.
 	3. Testing the template enginee with the function you found in the code.
  > ejs  = require("ejs")
...
> ejs.render("Hello, <%= foo %>", {"foo":"world"})
'Hello, world'

> {}.__proto__.outputFunctionName = "x = 1; console.log('haxhaxhax') ; y"
"x = 1; console.log('haxhaxhax') ; y"

> ejs.render("Hello, <%= foo %>", {"foo":"world"})
haxhaxhax
'Hello, world'

  	4. EJS case, Prototype Pollution Exploitation - Application and Library dependent. Try to find if that possible to set isAdmin to true in the Object prototype. <br>
 	5. Handlebars - To build a Handlebars proof of concept, we are going use techniques that were discovered by security researcher Beomjin Lee.
   	6. Handlebars Abstract Syntax Tree (AST) - the syntax return data from Handlebars.
	7. Prototype extends the DOM - http://prototypejs.org/learn/extensions
  	8. eval() is a function property of the global object. The argument of the eval() function is a string.
	9. Remote debuggering to caught the throw exception on javascript
	10. 

13.  Dolibarr Eval Filter Bypass RCE
	1. eval() function in (JavaScript, PHP, and Python). Any time an application passes improperly sanitized user input into eval(), it is an example of client-side eval injection. This attack is essentially the same as client-side cross-site scripting (XSS).
 	2. identify sink https://en.wikipedia.org/wiki/Sink_(computing)
  	3. Bypass Security Filter to Trigger Eval - using regular expression to search the different value pass to the function in each parameter.(dol_eval\(\$[\w\[\]']+,\s\d,\s\d,\s'(?!1|2)'\))
   	4. "extends CommonObject" in code-server's search bar can get other classes inherit from CommonObject.
    	5. Filter Bypass Revisted - Review other ways to bypass blocklist validation controls.
    	6. reflection -> to a way to modify an application programmatically at run-time. Example like (new ReflectionFunction(urldecode('%65%78%65%63')))->invoke('whoami');
    	7. PHP includes many string functions that we could use in our payload to bypass the blocklist. We could use string functions to construct "exec" in a variety of ways.
    	8. a. (new ReflectionFunction(str_replace("z", "e","zxzc")))->invoke('hostname'); b. (new ReflectionFunction(implode("x", array("e","ec"))))->invoke('hostname'); c. (new ReflectionFunction(strip_tags("ex<a>ec")))->invoke('hostname'); 
 
14.  (Archived)Atmail Mail Server Appliance: from XSS to RCE archived
	1. test
	2. test
!-->

<!--
# Post OSWE

## API Security
<!-- Task list -->

<!--
Resources
https://erev0s.com/blog/vampi-vulnerable-api-security-testing/

- [x] GraphQLmap
- [ ] B
- [ ] C
- [ ] 
!-->
