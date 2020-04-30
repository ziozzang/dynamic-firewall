# dynamic-firewall
Dynamic Firewall with whitelist/blacklist based HTTP/HTTPS proxy firewall.
Fully supported FQDN firewall http/https also dns.


* **working in progress.**

# Author
Jioh L. Jung <ziozzang@gmail.com>


# What is this?
* This is Proxy Server with FQDN(Exact matching, Substring matching, wildcard matching...) whitelisting policy.
* You can use this proxy as dynamic firewalls. and it can proxing
* no need to setup Root-Certification. it's not required certification. it can only check SNI field on HTTPS/TLS packet and Host Header on HTTP packet.
* This server also act as DNS Server Proxy. but current support only A record.
* You can set allow/passing or deny/blocking on real-time with HTTP API.

# How to Use.
* use docker image.

# SetUp/Configuration
* All configuration is using env parameters.

# API
## Security Token
* if you want to use passphase token, set 'secret' field.
* warning: only works with PUT, DELETE, POST. not GET.

* Example
```
# Using cURL
curl -XPUT 0.0.0.0:5555/ipaddr -d 'addr=127.0.0.0/24&secret=ASDF'  -v
```

## Allow Client IP List
* This policy has no weight of IP network items.

### Get All List
* Simple Usage


* Example
```
# Using cURL
curl -XGET 0.0.0.0:5555/ipaddr -v
```

### Put Allow IP Network
* warning: IP network format is like '10.2.3.0/24'. it must not have ip address. for example, '10.2.3.1/24' is bad case.

* URL: /ipaddr
* Params
** addr: IP Network

* Example
```
# Using cURL
curl -XPUT 0.0.0.0:5555/ipaddr -d 'addr=127.0.0.0/24'  -v
```

### Delete Allow IP Network

* URL: /ipaddr
* Params
** addr: IP Network

* Example
```
# Using cURL
curl -XDELETE 0.0.0.0:5555/ipaddr -d 'addr=127.0.0.0/24'  -v

```

### Simple Allow from all.

* Example
```
# Using cURL
curl -XDELETE 0.0.0.0:5555/ipaddr -d 'addr=0.0.0.0/0'  -v
```


## Allow/Deny Target Hosts

### Get All Allow/Deny List

* Example
```
# Using cURL(GET)
curl -XGET 0.0.0.0:5555/rules -v

# with cURL (POST)
curl -XPOST 0.0.0.0:5555/rules -d 'secret=ASDF'  -v
```
### Put Allow/Deny Host

* id: processing sequence: 1->higher number..
* type
 * 0 - allow passthru
 * 1 - deny or drop
 * 2 - deny but upstream

* Example
```
# Using cURL
curl -XPUT 0.0.0.0:5555/rule -d 'id=1&domain=google.com&type=0&regex=false'  -v
curl -XPUT 0.0.0.0:5555/rule -d 'id=2&domain=github.com&type=0&regex=false'  -v

# Allow All host
curl -XPUT 0.0.0.0:5555/rule -d 'id=60000&domain=.*&type=0&regex=true'  -v
```


### Delete from allow list

* URL: /rule
* Params
** id: id

* Example
```
# Using cURL
curl -XDELETE 0.0.0.0:5555/rule -D 'id=1'  -v
```

### Simple Allow from all.

* Example
```
# Using cURL
curl -XPUT 0.0.0.0:5555/rule -d 'id=60000&domain=.*&type=0&regex=true'  -v
```


# Testing
Tested Python 3.7
