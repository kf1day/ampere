#ampere
####A small daemon to process Asterisk's Management Interface security events

Dependencies:
- libpcre3

example of asterisk's "manager.conf"

```
[general]
enabled = yes
webenabled = no
port = 5038
bindaddr = 0.0.0.0

[ampere]
secret = 123
read = security
write = no
```

The tool is not acting like a natural daemon (for now) and should be started via SystemD / SysV init script

