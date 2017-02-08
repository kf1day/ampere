# Ampere 
A small tool to protect Asterisk installations against scanning and bruteforcing.


## Synopsis
Application subscribes Asterisk's Management Interface (AMI) security events.
There is a table of penalties for each host.
In case of any suspicious activity the penalty raises, increment depends on the status of event.
Legal event (such as successful auth) removes penalties.
If penalties are too high, host is blocking in configured chain via `iptables` syscall.
Each violator is stored in SQLite database.
Chain is flushing on application start, then saved rules are applying back again.


## Dependencies:
- libpcre3
- libsqlite3
- iptables


## Building
`make` - build unstripped executable

`make debug` - build unstripped executable with extra "debug" output (such as parsed config variables, recived messages, etc)

`make nice` - build stripped executable with optimization "-O3" flag


## Installation
* Put `ampere.cfg` into `/etc/ampere/`
* Put executable anywhere you want, e.g. `/usr/lib/ampere/`

The tool is not acting like a natural UNIX daemon (for now) and should be started via SystemD / SysV init script.

#### Example of *ampere.service* for systemd:
```
[Unit]
Description=Ampere 
After=asterisk.service
Requires=asterisk.service

[Service]
Type=simple
TimeoutSec=120

SyslogIdentifier=ampere

ExecStart=/usr/lib/ampere/ampere

[Install]
WantedBy=multi-user.target
```


## Configuring
The main task of Ampere is control firewall rules in specified chain.
When application starts, chain should exist and jumping to a chain also should be configured.
Last rule is always `RETURN`.

#### Example of *iptables -S* output:
```
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-N ampere-firewall
-A INPUT -i eth0 -p udp -m udp --dport 5060 -j ampere-firewall
-A INPUT -i eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i eth0 -j DROP
```

Application reads config from `/etc/ampere/ampere.cfg`, options are:

`host` - AMI interface address (default: 127.0.0.1). Due to `iptables` executes locally, it makes sense to only use loopback addresses

`port` - AMI interface port (default: 5038)

`user` - AMI interface login (default: ampere)

`pass` - AMI interface secret (default: ampere)

`loyalty` - Multiplier for fines upper limit (default: 3). In most cases than mean number of allowed authentication attempts.

`chain` - name of chain in firewall table (default: ampere).

#### Example of ampere.cfg:
```
pass = 123
loyalty = 4
chain = ampere-firewall
```

AMI also should be configured for accept connections and sent security events

#### Example of asterisk's "manager.conf"
```
[general]
enabled = yes
webenabled = no
port = 5038
bindaddr = 127.0.0.1

[ampere]
secret = 123
read = security
write = no
```

Then reload asterisk:
`asterisk -x "manager reload"`


## Prerequisites
Ampere was tested and successfuly used:
* Asterisk 13.13 (production/dedicated)
* OS Debian 8.6 with kernel 3.16.0-4-amd64
* gcc version 4.9.2

