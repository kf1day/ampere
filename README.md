# Ampere
An active network filter for Asterisk PBX


## Synopsis
The application subscribes to Asterisk's Management Interface (AMI) security events. There is a table of penalties for each host. In case of any suspicious activity, the penalty raises, increment depends on event status. Legal event (such as successful auth) removes penalties. If the penalties are too high, host blocked in configured chain via `iptables` syscall. Each violator is stored in internal database. The chain is flushed once application starts, and previously stored rules applies back again.


## Dependencies:
* Asterisk 12 or above
* Berkeley v5.x Database Libraries
* libpcre3
* iptables


## Building
`make` - build stripped executable\
`make dev` - build unstripped executable with debug symbols and some extra verbosity (such as parsed config variables, recived messages, etc)


## Installation
* Put `ampere.cfg` into `/etc/ampere/`
* Put executable anywhere you want, e.g. `/usr/lib/ampere/`

Ampere is not acting like a natural UNIX daemon (for now) and should be forked via SystemD / SysV init script.

#### Example of *ampere.service* for systemd:
```
[Unit]
Description=Ampere
After=asterisk.service
Wants=asterisk.service

[Service]
Type=simple
TimeoutSec=120

SyslogIdentifier=ampere

ExecStart=/usr/lib/ampere/ampere -o /var/log/ampere.log

[Install]
WantedBy=multi-user.target
```


## Configuring

### Firewall
When the application starts, chain should exist; jumping into a chain should be configured.

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



### Config file
By default, the application reads config from `/etc/ampere/ampere.cfg`.
This can be overriden by setting `-c /path/to/ampere.cfg` argument\
The options are:\
`host` - AMI interface address (default: 127.0.0.1). Due to `iptables` executes locally, it makes sense to only use loopback addresses \
`port` - AMI interface port (default: 5038)\
`user` - AMI interface login (default: ampere)\
`pass` - AMI interface secret (default: ampere)\
`loyalty` - Multiplier for penalties upper limit (default: 3). In most cases than mean number of allowed authentication attempts.\
`chain` - name of chain in firewall table (default: ampere).\
`trust` - network address(/mask) of trusted host or network (default: 0.0.0.0/32 - consider any host is untrusted).

#### Example of *ampere.cfg*:
```
pass = 123
loyalty = 4
chain = ampere-firewall
trust = 192.168.0.0/22
```

### Database
Ampere creates an internal BerkleyDB database file at compile-time configured path. Directory should exist.


### Logging
Ampere prints data to stdout/stderr. In a case of systemd daemonising, this output grabs by syslog. Setting `-o /path/to/ampere.log` argument makes the application to write its own log.


### Asterisk Management Interface
AMI also should be configured to accept connections and send security- and system-level events. Sending only those messages for which the application waits can be the useful. It can be done by specifying some `eventfilter` directives.

#### Example of asterisk's *manager.conf*
```
[general]
enabled = yes
webenabled = no
port = 5038
bindaddr = 127.0.0.1

[ampere]
secret = 123
read = security,system
write = no
eventfilter = Event: ChallengeResponseFailed
eventfilter = Event: ChallengeSent
eventfilter = Event: FailedACL
eventfilter = Event: InvalidPassword
eventfilter = Event: Shutdown
eventfilter = Event: SuccessfulAuth
```

Then reload asterisk:
`asterisk -x "manager reload"`


## Stability
Ampere has tested and successfuly applied to production.
Prerequisites are:
* Asterisk 12.8.2 and 13.13.1
* OS Debian 8 with kernel 3.16.0-4-amd64
* GCC version 4.9.2
