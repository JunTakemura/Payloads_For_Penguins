# Methodology for BSCP Style Web App Pentesting
For those who can't afford burp pro or cheapskates thogh you can't take an actual exam without pro. Note that this NOT a general pentesting methodology. For example in this workflow SQLi only appears in the stage 2 `get admin` but in reality it of course can be used for getting a normal user account.

## Flow

For now I mainly focus on how to **identify** vulnerabilities rather than exploit them.

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
    


#### Fuzz

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



#### Http request smuggling

#### Bypass auth

#### Brute forcing

### Get admin

#### CSRF

#### SQLi

#### CORS

#### JWT

#### Business logic

#### Broken access control

### Read secret files

#### OS command injections

#### XXE

#### LFI

#### File uploading

#### SSRF

#### SSTI

#### Insecure deserialization


## References
[PortSwigger Academy Labs](https://portswigger.net/web-security/all-labs)  
[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master)  
[Burp Suite Certified Practitioner Exam Study by botesjuan](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/blob/main/README.md)  
