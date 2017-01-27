#ampere
####A small daemon to process Asterisk's Management Interface security events

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
