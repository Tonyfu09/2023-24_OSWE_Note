<!--
# Disclaimer
All Resources below is only for education purpose for everyone who wanted to learn OSWE.
!-->

# 2023-24_OSWE Preparation
The Summary here only forcus on web vulnerability and how we could discover the initial shell from those web vulnerability. Embark on a comprehensive exploration of various web application vulnerabilities, deeply into understanding the OWASP Top 10.


## Course Outline: Preparing for Web Vulnerability Pentesting and OSWE
1. Hands on exprience on web vulnerability [PentesterLab](https://pentesterlab.com/) , [White Badge Exercises](https://pentesterlab.com/badges/whitebadge) <br>
2. Code logic knowledge [Codecademy](https://www.codecademy.com/) <br>
3. Pentest Course [Pentester Academy](https://www.pentesteracademy.com/) <br>
4. WSTG from OWASP https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/ <br>
5. OWASP top 10 Explaination [Portswigger](https://portswigger.net/) <br>


## OSWEer's Preparation Advice
1. z-r0crypt's Blog
https://z-r0crypt.github.io/blog/2020/01/22/oswe/awae-preparation/ <br>
2. Sarthak Saini's Personal Experience
https://sarthaksaini.com/about-me.html <br>
3. Charchit Verma's Review
https://charchitverma100.medium.com/an-honest-oswe-2023-review-my-journey-preparation-and-exam-67d0adcbcde4
4. Hakansonay's exprience
https://hakansonay.medium.com/the-oswe-review-and-exam-preparation-guide-e37886046b23
5. Snoopysecurity's OSWE-Prep https://github.com/snoopysecurity/OSWE-Prep


# OSWE prepare OSWAP Top 10 Related Topic


## Cross Site Scripting (XSS), A03:2021-Injection
XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user. 

### 1. DOM-based XSS <br>
- The Document Object Model (DOM) is structured as a tree of objects, typically manipulated using JavaScript to render HTML in a browser. If an attacker can modify a JavaScript function, a DOM-based XSS (Cross-Site Scripting) vulnerability could allow them to control DOM elements. <br>

- The Document Object Model tree is illustrate on w3schools: <br>
![image](https://github.com/Tonyfu09/2023-24_OSWE_Note/assets/39818274/88ee655c-5504-4e6d-b921-8296defd30cf)

- Adversary passes parameter to a sink that supports dynamic code execution to hijack other account.
- Be aware of the HTML function that can send dynamic content or to load a script on the web page.

### 2. Reflected DOM-based XSS <br>
An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will cause JavaScript code supplied by the attacker to execute within the user's browser in the context of that user's session with the application.

- Server-Site proccess data from the request, an attacker take advantage of it.
- An Attack analyst what the plug in that running on the web apps.

### 3. Stored DOM-based XSS <br>
An adversary able to send the request to the target server and store it in the server, then use it in a later stage.

- Server-Site proccess data from the request, an adversary take advantage to stores it, and then includes the data in a later response.Stored XSS is also sometimes referred to as Persistent or Type-II XSS.

As three of XSS above coud happening at the same attack period. Further reading could be the Client XSS and Server XSS from [Types of XSS](https://owasp.org/www-community/Types_of_Cross-Site_Scripting) also helps clear things.

### XSS to RCE
XSS Vulnerability Payload List - https://github.com/payloadbox/xss-payload-list <br>
good to pratice - https://pentesterlab.com/exercises/xss_and_mysql_file/course <br>

### Same-Origin Policy (SOP)
Same-Origin Policy to prevent one origin from accessing resources on a different origin. Same origin policy could as https://123.com/readme and https://123.com/upgrade. But different schema like https://123.com/userID.json or differnet domain like https://abc.123.com/upgrade.
Testing method by reviewing the attribute of response. Access-Control-Allow-Origin, Access-Control-Allow-Methods, Access-Control-Allow-Headers, Access-Control-Expose-Headers.

### Cross-Origin Resource Sharing (CORS)
Cross-Origin Resource Sharing (CORS) is a mechanism that allows an application to load scripts or other resources from different domains, schemes, or ports. As the SOP will be commonly apply on the site, the CORS is a good way to release the permissive for other origin to access reasources.

### SameSite Attribute
The SameSite attribute lets servers specify whether/when cookies are sent in Set-Cookie headers with cross-site requests from [Using HTTP cookies in Mozilla](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies)

SameSite restriction levels as below: <br>
- Strict, If a cookie is set with the SameSite=Strict attribute, browsers will not send it in any cross-site requests.
- None, Means disables SameSite restrictions.
- Lax, The browsers will send the cookie in cross-site request, but only in a few scenarios as the request uses the GET, HEAD or OPTIONS methond and the request resulted from a top-level navigation by the user.

### CSRF Token
CSRF token generated by the application, the token is a unique, only visible between the client and the application. The CSRF token is use for exchange the further request.

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

### Other XSS preparation
- Create a website, Practice write a script to create a website for scraping sensitive information


## OS Command Injection
OS command injection is a vulnerability that allows an Adversary to execute arbitrary commands on the server side or sending the arbitary commands to the targer by someway.


## Authentication Bypass, A07:2021 – Identification and Authentication Failures
Authentication bypass is a method that circumvents the authentication process in a way not intended by the web application. This vulnerability allows an unauthenticated user to access the application's functions, extract sensitive information, and even gain unauthorized access to the application.

OSWAP [WSTG - Latest Sample](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema) also provides different way of Authentication Bypass. In order to preform authentication bypass, we will require to modify the value of parameter or logicially to make the application trust you are authenticated.

### Bypass regular login
As mentioned by [Hacktricks](https://book.hacktricks.xyz/pentesting-web/login-bypass), one common approach involves leveraging various techniques to attempt to bypass login pages. <br> 

Here are some questions might consider:
- 1. What is the user ID you are using?
- 2. How does the user obtain their password during signup?
- 3. What steps does the user take if they forget their password?
- 4. How is the user's password saved in the database?
- 5. How can we explore the table schema externally?
- 6. What authentication method is used for users?
- 7. What SQL query can be used to retrieve the password?
- 8. What are the key elements needed to crack the token?
- 9. How can we gather more information from the logging system?
Login page Check list also avaliable on (https://github.com/Mehdi0x90/Web_Hacking/blob/main/Login%20Bypass.md)

### Code Review
Review all the functions in the source code. Break them down one by one to check if any function might have vulnerabilities that could lead to authentication bypass.

### Code Review - Filter Bypass with Authentication bypass

- An event sink is a class or function designed to receive incoming events from another object or function. This is commonly implemented in C++ as callbacks. Other object-oriented languages, such as Java and C#, have built-in support for sinks by allowing events to be fired to delegate functions.
- Guard, In computer programming, a guard is a Boolean expression that must evaluate to true if the execution of the program is to continue in the branch in question. [Guard](https://en.wikipedia.org/wiki/Guard_(computer_science))
- WAF Ruleset review if there have any request blocking happening in white box attack. 

Step 1 - Damager function, such as a PHP application, we could start by searching for functions like exec(), passthru(), system(), or shell_exec(), eval() https://www.php.net/manual/en/function.eval.php
Step 2 - Input Validation, understand what is the filtering
Step 3 - Come with some of escape payload, and test in the application

Some of function as below,
strpos, the function is use for checking the variable of the first position, https://www.php.net/manual/en/function.strpos.php
implode, join array elements with a string, https://www.php.net/manual/en/function.implode.php


### PHP Type Juggling
PHP does not require explicit type definition in variable declaration. In this case, the type of a variable is determined by the value it stores. [Definition from PHP](https://www.php.net/manual/en/language.types.type-juggling.php) 

PHP Loose comparisons will lead to vulnerability to return the result that didn't expect [PHP Loose comparisons](https://www.php.net/manual/en/types.comparisons.php)

Simplify PHP Type Juggling - https://secops.group/php-type-juggling-simplified/


## JavaScript Injection

### Prototype Pollution
Prototype pollution often happen when an attacker inject javascript code. The attacker is attempting to control the default values of an object's properties. <br>
- Example from snyk - https://learn.snyk.io/lesson/prototype-pollution/ <br>
- Explaination from Hacktrike about how Prototype pollution is working [Hacktricks Prototype Pollution](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution)

Another key point is the prototype chain. JavaScript implements inheritance through objects, where each object has a prototype. JavaScript uses this prototype chain to create a layered structure for inheritance such as keyname.__proto__.__proto__.__proto__ , enabling objects to inherit properties and methods from other objects. For more details [mdn web docs - Prototype Chain](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Inheritance_and_the_prototype_chain)

#### Function constructor decribe as [Javascript function constructor](https://www.geeksforgeeks.org/prototype-in-javascript/) 
1. Create a function constructor<br>
<code>
function Person(name, job, yearOfBirth){   
    this.name= name;
    this.job= job;
    this.yearOfBirth= yearOfBirth;
}
</code><br>

2. calculateAge() method gets added to the Prototype property
Person.prototype.calculateAge = function () {
    console.log('The current age is: ' + (2019 - this.yearOfBirth));
}<br>

3. Create a object person
let Person1 = new Person('Jenni', 'clerk', 1986);
console.log(Person1)
Person1.calculateAge();
Therefore, the prototype property (calculateAge) allows other objects (such as Person) to inherit all the properties and methods of the constructor function.

#### Prototype pollution sinks <br>
- Descripte that some javascript function or DOM element that you're able to access via prototype pollution which enable for adversary execute arbitary JavaScript or system commands. <br>

#### Prototype pollution gadgets <br>
- According the description from [Prototype pollution](https://portswigger.net/web-security/prototype-pollution), the prototype pollution gadgets is more about the process turming the prototype pollution vulnerability into an actual exploit. That's means the vulnerability is criticial. <br>

#### Step to identifies <br>
1. Discover any functions that allow the addition of arbitrary properties to global object prototypes, which can then be inherited by user-defined objects. <br>
2. Discover there have any dependencies. <br>
3. Add arbitrary properties to prototype objects. <br>
4. Reveal and test whether it is possible to control and pollute the objects. <br>
5. Verify the value change after the pollution, does the program crash after the value of the key is actually got changed? <br>


## XML External Entity (XXE) Attack, A05:2021-Security Misconfiguration

XXE (XML External Entity) Attack is a vulnerability that allows an attacker to interfere with an application's processing of XML data. The impact can range from the attacker viewing files on the application server filesystem to more severe consequences like remote code execution.  <br>

### Resources:
- [OWASP Description](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
- [PortSwigger on Blind XXE Vulnerabilities](https://portswigger.net/web-security/xxe/blind)

#### XML Entities

XML documents can define entities which can be referenced within the document. There are three types of XML entities:
1. **Internal Entities**: Defined within the XML document.
2. **External Entities**: Referenced from an external source.
3. **Parameter Entities**: Used within DTDs (Document Type Definitions). DTDs define the structure, legal elements, and attributes of an XML document.

#### Steps to Exploit XXE Vulnerability
- Check if the application allows XML parsing in specific fields.
- Enumerate directories for potential vulnerabilities.
- Access sensitive files.
- Write files into the target directory/library (e.g., "kal").
- Typically, XML files are not executed directly, but can still be leveraged in attacks like XXE (XML External Entity).

Detailed Sample and explaination [w3s XML DTD](https://www.w3schools.com/xml/xml_dtd.asp)

- ### Attack vector 
1. An XXE vulnerability was exploited to retrieve sensitive files from the server.
2. The XXE vulnerability was leveraged to trigger another vulnerability's function.


## Server Side Request Forgery (SSRF), A10:2021-Server-Side Request Forgery
SSRF is the type which the attack forcus the server send the web request that the adversary wants. Different types could refer [HackTricks - SSRF](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery). 

- Identify the SSRF exist in the application
1. Send the different api version and different method of the api endpoints could gathering some vulnerability, also if it could gain more internal information to create map for the attacker.
2. Identify the SSRF vulnerability to determine if there have been any unexpected commands run on the server side to make an request.
3. Application flow that requires the server to call external web services.
4. Code analyst to discover vulnerability services

- Verify SSRF vulnerability
1. Set up a web server in your environment to gather data sent from the victim.
2. Analyze the data and parameters received from the victim.
3. Defind the format of payload


## Server Side Template Injection (SSTI), A03:2021-Injection
Server-Side Template Injection (SSTI) occurs when an adversary is able to inject malicious code into a template that is processed on the web server. The initial step in exploiting SSTI often involves identifying the templating engine used by the web application, which can provide insight into potential vulnerabilities. <br>

- ### SSTI references are provided below.
1. [First Jinja template ](https://realpython.com/primer-on-jinja-templating/) is good for understand if you are first time have exprience with Jinja. Two step involves 1. Load a template and 2. Render the template
2. Detailed explanation of [SSTI from portswigger](https://portswigger.net/research/server-side-template-injection)
3. Inject payload to easy define if the server getting template expressions, such as {{7*7}}, ${7*7}
4. [Jinja Template Design Document](https://jinja.palletsprojects.com/en/3.1.x/templates/)

- ### Example - Twig from [OWASP](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection)
There is a function execute by server into the PHP code snippet and could be vulnerable.

- ### Payload
The list of SSTI vulnerabilities you'd want to examine includes both filter bypass techniques and associated payloads. [Swisskyrepo - SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md)


## SQL injection, A03:2021-Injection
SQL injection (SQLi) is a major web application vulnerability class prevalent in many web applications. <br>
<br>
1. Error-Based SQL Injection
- An Error-Based SQL Injection technique relies on error messages returned by the database server to obtain information about the structure of the database. Therefore, we can test a condition and analyze the returned error to determine whether there is a difference in the application's HTTP response.
2. In-band SQL Injection
- Also known as classic SQL injection, this technique allows the adversary to retrieve data using the same communication channel used to send the malicious query.
- An example of In-band SQL injection is when the adversary modifies a query to retrieve all the data within a table.
3. Union-Based SQL Injection
- The UNION operator is used to combine the result-set of two or more SELECT statements which return as part of the HTTP response or simply explain is retrieveing the data from other table.
- The UNION keyword to retrieve data from other tables within the database for sql injection. - [PortSwigger](https://portswigger.net/web-security/sql-injection/union-attacks) <br>
more caution about the collation https://dev.mysql.com/doc/refman/8.0/en/charset-collate.html
4. Blind Boolean-based SQL Injection
- Blind SQL (Structured Query Language) injection is a type of SQL Injection attack that asks the database true or false questions and determines the answer based on the applications response. 
- Content-based, Time-based and Remote Database Fingerprinting - https://owasp.org/www-community/attacks/Blind_SQL_Injection
5. Time-based SQL Injection
- In a Time-Based SQL Injection, the adversary introduces a delay in the response to validate the presence of a SQL injection vulnerability. This technique does not rely on retrieving data directly but on observing the time delay in the server's response to determine whether the injection was successful.
6. Stack Query

### Skill set in encoding and decoding can be useful for bypassing filters in SQL injection attacks.
1. Discover escape characters or sequences.
2. URL-encode the string and add it into the URL as a query parameter.

### Code Analysis on SQL Injection
1. Review the code to check if any user controller variables can potentially affect SQL injection
2. Potential function, Potential function, Potential function!!! Be aware the functional that calling behind.
3. The logic of sanitize the input value
4. Build your own script to exploit SQL injection vulnerabilities.

### User Defined Function
1. [](https://book.hacktricks.xyz/pentesting-web/sql-injection/mssql-injection#mssql-user-defined-function-sqlhttp)

### SQL injection Explanation and Sample Testing <br>
SQL Injection Detection - https://www.sqlinjection.net/detection/ <br>
Portswigger SQL Injection - https://portswigger.net/web-security/sql-injection <br>
SQL injection Cheat Sheet - https://portswigger.net/web-security/sql-injection/cheat-sheet <br>
Hacktrick https://book.hacktricks.xyz/pentesting-web/sql-injection <br>
PostgreSQL Dollar quoted string constants https://www.postgresqltutorial.com/postgresql-plpgsql/dollar-quoted-string-constants/ <br>
SQL Injection Explain https://www.invicti.com/learn/in-band-sql-injection/ <br>


## Serialization and Deserialization
Serialization, as defined by Microsoft, is the conversion of an object's state into a format suitable for persistence or transportation. You can find more about this definition on Microsoft's website. Deserialization, on the other hand, involves reconstructing an object from its serialized form to restore its original state.

For a practical example of deserializing objects, you can refer to the following link: [Newtonsoft's documentation on deserializing objects](https://www.newtonsoft.com/json/help/html/deserializeobject.htm). Additionally, there's a helpful sample code in C# available online, which you can access through this link: [Sample code on GitLab](https://gitlab.com/-/snippets/2496138).

Insecure deserialization could allow an attacker to control the serialized object, enabling the injection of malicious code into the victim's system, thus bypassing file upload security measures. The vulnerability is further detailed as mentioned on [OWASP Top 10 - Insecure Deserialization](https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization)

### Java Serialization and Deserialization
Serialization in Java allows you to convert an object into a stream of bytes, which can then be saved to a file, sent over a network, or otherwise transferred. This is done using the Serializable interface from the java.io package. To make an object serializable, the class must implement the Serializable interface.
- Here is an example that demonstrates how to serialize and deserialize a Person object:
```
import java.io.Serializable;

public static class Person implements Serializable {
    public String name = null;
    public int age = 0;
    public String address = null;
    public String phoneNumber = null;
    public String email = null;
    public String gender = null;
    public String nationality = null;
    public boolean isEmployed = false;
    public double salary = 0.0;
}
```

Deserialization is the process of converting a stream of bytes back into a Java object. It reverses the process of serialization, which is the conversion of an object into a byte stream. Deserialization restores the object's state, allowing it to be used in its original form after being transmitted or stored.
- Potentiall deserialization/serialization  during the process then discover vulnerabilities in code search. The deserialization is the process covert the file into a byte stream to recreate the actual Java object in memory
```
import java.io.*;

public class DeserializePerson {

    public static void main(String[] args) {
        // File that contains the serialized object
        String filename = "person.ser";

        // Deserialize the object
        try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(filename))) {
            // Read the object from the file
            Person person = (Person) in.readObject();

            // Display the deserialized object
            System.out.println("Deserialized Person:");
            System.out.println("Name: " + person.name);
            System.out.println("Age: " + person.age);
            System.out.println("Address: " + person.address);
            System.out.println("Phone: " + person.phoneNumber);
            System.out.println("Email: " + person.email);
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
}
```

### .NET Framework Class For Serialization
More serializes and deserializes objects to and from Microsoft XML documents, Example as follows code for create a class with purchase order, then read and write the purchase order. [Microsoft - XmlSerializer](https://learn.microsoft.com/en-us/dotnet/api/system.xml.serialization.xmlserializer?view=net-8.0)

Example of .NET framwork show to how the leverage the gadget wraps and create an object that you can use as binding source. That means this class allow the adversary to wrap the usefal object to obtain RCE [HackTricks - .NET deserialization](https://book.hacktricks.xyz/pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net)  

As the resources of gadget that could possible use for exploit, generating payloads that exploit unsafe .NET object deserialization. [ysoserial - .NET Payloads](https://github.com/pwntester/ysoserial.net)

### PHP deserialization



## Unrestriced File Bypass

- File Extension. Typically, the application will only permit users to upload files with specific extensions that the application owner has designated.

- ### Step to think more about the file extension
Step 1 - How the code logic for the user upload their file
Step 2 - Does the filter applied?

- ### Resource
Hactrick https://book.hacktricks.xyz/pentesting-web/file-upload 


# The Box have been pwanded 
From OSWE Like Box https://docs.google.com/spreadsheets/u/1/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview

# HTB
|BoxName|TechForBox|OS|
|---|---|---|
|Vault|WebApp Enumeration, File Bypass, Tunneling, Decryption |Linux|
|Popcorn|WebApp Enumeration, File Bypass |Linux|
|Celestial|Deserialization, NodeJS - Source code Review |Linux|
|Blocky|WebApp Enumeration, Java - Decompile |Linux|
|Falafel|PHP & MYSQL - SQL Injection |Linux|
|Zipper|API Vulnerability, Python Script for Exploitation |Linux|
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
|Arkham|Java Deserialization |Windows|

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
Java Deserialization https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet <br>
PHP WebShell https://github.com/JohnTroony/php-webshells/tree/master <br>

# Formatting syntax for Github 
https://medium.com/analytics-vidhya/writing-github-readme-e593f278a796 <br>
https://docs.github.com/en/get-started/writing-on-github/getting-started-with-writing-and-formatting-on-github/basic-writing-and-formatting-syntax <br>

# Tools (Automatic Tools are Not Allowed During the OSWE Exam)
MD5 Collisions - https://github.com/cbornstein/pymd5-collisions <br>
dnspy - .NET Debugger - https://github.com/dnSpy/dnSpy/releases <br>
JD-GUI - https://java-decompiler.github.io/ <br>
pgAdmin - https://www.pgadmin.org/ Front end for PostgreSQL <br>
XSS Playload - https://github.com/payloadbox/xss-payload-list <br>
SSRF Map - https://github.com/swisskyrepo/SSRFmap
Remote Debugger for (vs-2019) - https://github.com/MicrosoftDocs/visualstudio-docs/blob/main/docs/python/includes/vs-2019/remote-debugging-python-code.md
