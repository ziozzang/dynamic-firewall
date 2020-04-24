#!python
# -*- encoding: utf-8 -*-
# *=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
# Dynamic Firewall Support HTTP/HTTPS blocking
# *=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
# Code by Jioh L. Jung
# *=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*

import sys
import re
import os

import asyncio
from aiohttp import web
import ipaddress

import io
import time
import logging
import struct
import random
import json

import dns.resolver

import urllib.request
import re
import socket

import threading


# Global config
# Default parameters

class Config():
    """
    Configuration.
    Values are setup by ENV variable.
    values are seperated by ','
    """

    def __init__(self):
        # DNS Proxy. (only support A Record)
        self.UPSTREAM_DNS = "8.8.8.8,1.1.1.1"  # Default Upstream DNS Server to return to client
        self.EXTERNAL_DNS = "8.8.8.8,1.1.1.1"  # Default DNS Server to connect external
        self.ENDPOINT_URL = ""  #
        self.PROXY_PORTS = "80,443"  # HTTPS/TLS (SNI), HTTP(Host) Proxy ports
        self.LOGGER_URL = ""  # Not yet supported
        self.API_SERVER_PORT = "5555"  # Simple API Server Ports
        self.DNS_SERVER_PORT = "53"  # DNS Server (only UDP)
        self.API_SECRET = ""  # API Secret Passphase

        # Initialize values by Env val
        if "UPSTREAM_DNS" in os.environ: self.UPSTREAM_DNS = os.environ["UPSTREAM_DNS"]
        if "EXTERNAL_DNS" in os.environ: self.EXTERNAL_DNS = os.environ["EXTERNAL_DNS"]
        if "ENDPOINT_URL" in os.environ: self.ENDPOINT_URL = os.environ["ENDPOINT_URL"]
        if "PROXY_PORTS" in os.environ: self.PROXY_PORTS = os.environ["PROXY_PORTS"]
        if "LOGGER_URL" in os.environ: self.LOGGER_URL = os.environ["LOGGER_URL"]
        if "API_SERVER_PORT" in os.environ: self.API_SERVER_PORT = os.environ["API_SERVER_PORT"]
        if "DNS_SERVER_PORT" in os.environ: self.DNS_SERVER_PORT = os.environ["DNS_SERVER_PORT"]
        if "API_SECRET" in os.environ: self.API_SECRET = os.environ["API_SECRET"]

        self.upstream_dns_servers = []
        self.external_dns_servers = []
        for i in self.UPSTREAM_DNS.split(","): self.upstream_dns_servers.append(i.strip())
        for i in self.EXTERNAL_DNS.split(","): self.external_dns_servers.append(i.strip())
        self.apiserver_port = int(self.API_SERVER_PORT)
        self.dnsserver_port = int(self.DNS_SERVER_PORT)
        # Sequence


class IPCheck():
    """
    Client IP Checker. only allowed IP networks will allow.
    IP networks can be '0.0.0.0/0' or '10.1.2.0/24'
    Warn: IP network is not IP Address. if you set '10.1.2.1/24' -> You will get ERROR!!!
    """

    def __init__(self):
        self.allows = []

    def get_all(self):
        return self.allows

    def add(self, ipnet):
        if not ipnet in self.allows:
            self.allows.append(ipnet)
            return True
        return False

    def remove(self, ipnet):
        if ipnet in self.allows:
            self.allows.remove(ipnet)
            return True
        return False

    def check_allowed(self, ipaddr):
        found = False
        for ipnet in self.allows:
            if ipaddress.IPv4Address(ipaddr) in ipaddress.IPv4Network(ipnet):
                found = True
                break
        return found


class Rules():
    """
    Allow or Deny Target Host Rule Engine
    Target Host Name can be use with Regular Expression.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.entries = {}
        self.rules = []
        self.allowed_client = []

    def _rebuild(self):
        self.rules.clear()
        keys = list(self.entries.keys())
        keys.sort()
        for k in keys: self.rules.append(self.entries[k])

    def get_list(self):
        self.lock.acquire()
        res = []
        keys = list(self.entries.keys())
        keys.sort()
        for k in keys:
            res.append({
                "id": k,
                "type": self.entries[k]["type"],  # 0 - allow passthru / 1 - deny or drop / 2 - deny but upstream
                "domain": self.entries[k]["domain"],
                "regex": self.entries[k]["regex"],
            })
        rres = {"rules": res, "size": len(keys)}
        self.lock.release()
        return rres

    def add_item(self, ids, domains, types, regexs=False):
        k = ids
        regex_compiled = None
        if regexs: regex_compiled = re.compile(domains)
        v = {"id": ids, "domain": domains, "type": types, "regex": regexs, "regex_cmp": regex_compiled}
        self.lock.acquire()
        if k in self.entries.keys():  # Duplicated Key Exist
            self.lock.release()
            return False
        else:
            self.entries[k] = v
        self._rebuild()
        self.lock.release()
        return True

    def delete_item(self, ids):
        res = True
        self.lock.acquire()
        if ids in self.entries.keys():
            del (self.entries[ids])
        else:  # No Entry to Delete
            res = False
        self._rebuild()
        self.lock.release()
        return res

    def check_domain(self, domain):
        # Return: (found?, allowed?, DNS Query to upstream?, id, domain/string, parsed by regex?)
        domain_tmp = domain.strip(".")
        res_found, res_allowed, res_upstream, res_id, res_domain, res_regex = False, False, False, 0, None, False

        self.lock.acquire()
        for i in self.rules:
            if not i["regex"]:
                if i["domain"] == domain_tmp:
                    res_found = True
            else:
                if i["regex_cmp"].match(domain_tmp) is not None:  # RegEx Match
                    res_found = True
            if res_found:
                if i["type"] == 0:  # 0 - allow passthru / 1 - deny or drop / 2 - deny but upstream
                    res_allowed, res_upstream = True, False
                elif i["type"] == 1:
                    res_allowed, res_upstream = False, False
                elif i["type"] == 2:
                    res_allowed, res_upstream = False, True
                res_id, res_domain, res_regex = i["id"], i["domain"], i["regex"]
                break
        self.lock.release()
        return (res_found, res_allowed, res_upstream, res_id, res_domain, res_regex)


config = Config()
ipcheck = IPCheck()
rule = Rules()


# IP Address Checker.
def get_external_ip():
    """
    Get External IP Address (Maybe public IP Address)
    :return: IP Address(string)
    """
    if "EXT_IP" in os.environ:
        return os.environ["EXT_IP"]
    site = urllib.request.Request("http://checkip.dyndns.org/")
    cont = urllib.request.urlopen(site).read().decode("utf-8")
    grab = re.findall('([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', cont)
    address = grab[0]
    return address


def get_local_ip():
    """
    Get Internal Self IP Address(maybe private IP Address)
    :return: IP Address(string)
    """
    if "SELF_IP" in os.environ:
        return os.environ["SELF_IP"]
    return [(s.connect(('8.8.8.8', 80)), s.getsockname()[0], s.close()) \
            for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]


def query_dns(domain, types="A", single_ip=True, use_upstream=True):
    """
    Ask DNS to upstream Server and acquire DNS record.
    :param domain: domain name to lookup
    :param types: type of DNS record(string), you can set 'A', 'AAAA', 'MX', 'NX'.....
    :param single_ip: get only one ip address string or get as list?
    :param use_upstream: want to use query to upstream?
    :return: single ip string or ip addresses list. or None(not found, or upstream DNS doesn't response)
    """
    resolver = dns.resolver.Resolver()
    if use_upstream:
        resolver.nameservers = config.upstream_dns_servers
    else:
        resolver.nameservers = config.external_dns_servers
    try:
        ans = resolver.query(domain, types)
        if single_ip:
            ip = random.choices(ans)[0].address
        else:
            ip = []
            for i in ans:
                ip.append(i.address)
        return ip
    except dns.resolver.NoAnswer:  # No Response from Upstream
        return None
    except dns.resolver.NXDOMAIN:  # No such Record
        return None


############################################################
# Decode Packet (HTTPS/TLS's SNI & HTTP's Host)
def extract_server_name(packet):
    """
    Decode and Extract Server Name(Information came from Host filed or SNI field). and check packet type
    :param packet: Packet Body which has HTTPS/HTTP Headers.
    :return: (target host(sting), packet type(string). packet type can be 'unknown', 'http', 'https'
    """
    if packet.startswith(b'\x16\x03'):  # TLS Header Detection
        # For SNI Proxy Packet(HTTPS)
        logging.debug("Query is HTTPS")
        stream = io.BytesIO(packet)
        stream.read(0x2b)
        session_id_length = ord(stream.read(1))
        stream.read(session_id_length)
        cipher_suites_length, = struct.unpack('>h', stream.read(2))
        stream.read(cipher_suites_length + 2)
        extensions_length, = struct.unpack('>h', stream.read(2))
        extensions = {}
        while True:
            data = stream.read(2)
            if not data:
                break
            etype, = struct.unpack('>h', data)
            elen, = struct.unpack('>h', stream.read(2))
            edata = stream.read(elen)
            if etype == 0:
                server_name = edata[5:].decode()
                return (server_name, "https")
    else:
        stream = packet.split(b"\r\n\r\n", 1)
        if len(stream) < 2:  # not HTTP header format
            return (None, "unknown")
        else:
            stream = stream[0]  # Extract Header Parts
        stream = stream.decode("utf-8").lower()
        if stream.startswith("get") or stream.startswith("post") or \
                stream.startswith("put") or stream.startswith("delete") or \
                stream.startswith("head") or stream.startswith("set") or \
                stream.startswith("patch") or stream.startswith("options"):
            # Check Real HTTP Header.(Include RESTful Request)
            logging.debug("Query is HTTP")
            hdrs = [i.strip() for i in stream.split("\r\n")]
            for i in hdrs[1:]:
                k, v = i.split(":", 1)
                if k == "host":
                    return (v.strip().lower(), "http")
    return (None, "unknown")


# AsyncIO Controller Class
class Controller(object):
    """
    ASyncIO Server Controller. This Class can control loops, include bootup and cleanup.
    """

    def __init__(self, loop=None):
        self._loop = loop or asyncio.get_event_loop()
        self.servers = []  # Servers to close.

    def add_server(self, server):
        self.servers.append(server)

    def get_loop(self):
        return self._loop

    def start(self, and_loop=True):
        if and_loop:
            self._loop.run_forever()

    def stop(self, and_loop=True):
        for i in self.servers:
            i.close()
        if and_loop:
            self._loop.close()


# DNS Query parsing. (A record only)
class DNSQuery:
    """
    Simple DNS Request Packet Decode & Extract(A Record Only)
    """

    def __init__(self, data):
        self.data = data
        self.domain = b''

        tipo = ((data[2]) >> 3) & 15  # Opcode bits
        if tipo == 0:  # Standard query
            ini = 12
            lon = (data[ini])
            while lon != 0:
                self.domain += data[ini + 1:ini + lon + 1] + b'.'
                ini += lon + 1
                lon = (data[ini])
        logging.debug("DNS Query Parsed: {0}".format(self.domain))
        self.domain = self.domain.decode("ascii")


class DNSResponse:
    """
    DNS Response Packet Generating
    """

    def __init__(self, query):
        self.data = query.data
        self.packet = b''
        result_ip = None

        try:
            all_questions = self.dns_extract_questions(self.data)
        except IndexError:
            # Response Empty if broken Questions
            self.packet = self.dns_empty_response()
            return

        # Checking Rules
        result_found, result_allowed, result_upstream, res_id, res_domain, res_regex = rule.check_domain(
            query.domain[:-1])
        if not result_found:
            print("Result cannot found")

        # logging.debug(">> Matched Request(BLOCK): " + query.domain)
        if result_allowed:
            result_ip = get_local_ip()
            print("Result Allowed. Local IP=>", result_ip)

        # Need Upstream Resolving
        elif result_upstream:
            result_ip = query_dns(query.domain, use_upstream=True)
            if result_ip is None:
                logging.debug(">> Unable to parse request")
            else:
                logging.debug(">> Unmatched request: " + query.domain + ":" + result_ip)

        # Set Empty Response
        if (result_ip is None) or ((result_allowed == False) and (result_upstream == False)):
            self.packet = self.dns_empty_response()
        else:

            # Filter only those questions, which have QTYPE=A and QCLASS=IN
            # TODO this is very limiting, remove QTYPE filter in future, handle different QTYPEs
            accepted_questions = []
            for question in all_questions:
                name = str(b'.'.join(question['name']), encoding='UTF-8')
                """
                QTYPE: A:\x00\x01 / AAAA: \x00\x1C / MX: \x00\x0F / NS: \x00\x02
                https://en.wikipedia.org/wiki/List_of_DNS_record_types
                """
                if question['qtype'] == b'\x00\x01' and question['qclass'] == b'\x00\x01':
                    accepted_questions.append(question)
                    print('\033[32m{}\033[39m - QT:{}/QC:{}'.format(name, question['qtype'], question['qclass']))
                else:
                    print('\033[31m{}\033[39m - QT:{}/QC:{}'.format(name, question['qtype'], question['qclass']))

            self.packet = (
                    self.dns_response_header(self.data) +
                    self.dns_response_questions(accepted_questions) +
                    self.dns_response_answers(accepted_questions, result_ip)
            )

    def dns_empty_response(self):
        """
        Return Empty DNS Response
        """
        # Build the response packet
        packet = self.data[:2] + b'\x81\x83'  # Reply Code: No Such Name
        #                                                                  0 answer rrs   0 additional, 0 auth
        packet += self.data[4:6] + b'\x00\x00' + b'\x00\x00\x00\x00'  # Questions and Answers Counts
        packet += self.data[12:]  # Original Domain Name Question
        print("Empty Response")
        return packet

    def dns_extract_questions(self, data):
        """
        Extracts question section from DNS request data.
        See http://tools.ietf.org/html/rfc1035 4.1.2. Question section format.
        """
        questions = []
        # Get number of questions from header's QDCOUNT
        n = (data[4] << 8) + data[5]
        # Where we actually read in data? Start at beginning of question sections.
        pointer = 12 # DNS_HEADER_LENGTH = 2
        # Read each question section
        for i in range(n):
            question = {
                'name': [],
                'qtype': '',
                'qclass': '',
            }
            length = data[pointer]
            # Read each label from QNAME part
            while length != 0:
                start = pointer + 1
                end = pointer + length + 1
                question['name'].append(data[start:end])
                pointer += length + 1
                length = data[pointer]
            # Read QTYPE
            question['qtype'] = data[pointer + 1:pointer + 3]
            # Read QCLASS
            question['qclass'] = data[pointer + 3:pointer + 5]
            # Move pointer 5 octets further (zero length octet, QTYPE, QNAME)
            pointer += 5
            questions.append(question)
        return questions

    def dns_response_header(self, data):
        """
        Generates DNS response header.
        See http://tools.ietf.org/html/rfc1035 4.1.1. Header section format.
        """
        header = b''
        # ID - copy it from request
        header += data[:2]
        # QR     1    response
        # OPCODE 0000 standard query
        # AA     0    not authoritative
        # TC     0    not truncated
        # RD     0    recursion not desired
        # RA     0    recursion not available
        # Z      000  unused
        # RCODE  0000 no error condition
        header += b'\x80\x00'
        # QDCOUNT - question entries count, set to QDCOUNT from request
        header += data[4:6]
        # ANCOUNT - answer records count, set to QDCOUNT from request
        header += data[4:6]
        # NSCOUNT - authority records count, set to 0
        header += b'\x00\x00'
        # ARCOUNT - additional records count, set to 0
        header += b'\x00\x00'
        return header

    def dns_response_questions(self, questions):
        """
        Generates DNS response questions.
        See http://tools.ietf.org/html/rfc1035 4.1.2. Question section format.
        """
        sections = b''
        for question in questions:
            section = b''
            for label in question['name']:
                # Length octet
                section += bytes([len(label)])
                section += label
            # Zero length octet
            section += b'\x00'
            section += question['qtype']
            section += question['qclass']
            sections += section
        return sections

    def dns_response_answers(self, questions, ip):
        """
        Generates DNS response answers.
        See http://tools.ietf.org/html/rfc1035 4.1.3. Resource record format.
        """
        records = b''
        for question in questions:
            record = b''
            for label in question['name']:
                # Length octet
                record += bytes([len(label)])
                record += label
            # Zero length octet
            record += b'\x00'
            # TYPE - just copy QTYPE
            # TODO QTYPE values set is superset of TYPE values set, handle different QTYPEs, see RFC 1035 3.2.3.
            record += question['qtype']
            # CLASS - just copy QCLASS
            # TODO QCLASS values set is superset of CLASS values set, handle at least * QCLASS, see RFC 1035 3.2.5.
            record += question['qclass']
            # TTL - 32 bit unsigned integer. Set to 0 to inform, that response
            # should not be cached. (TTL: Set to Zero)
            record += b'\x00\x00\x00\x00'
            # RDLENGTH - 16 bit unsigned integer, length of RDATA field.
            # In case of QTYPE=A and QCLASS=IN, RDLENGTH=4.
            record += b'\x00\x04'
            # RDATA - in case of QTYPE=A and QCLASS=IN, it's IPv4 address.
            # record += b''.join(map(
            #    lambda x: bytes([int(x)]),
            #    IP.split('.')
            # ))
            record += ipaddress.ip_address(ip).packed
            records += record
        return records


# DNS Packet Handler.
class DNSPacketHandler:
    """
    DNS Packet Handler.
    """

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        (host, port) = address
        query_res = DNSQuery(data)

        # Client Authentication
        if not ipcheck.check_allowed(address[0]):  # Authentication
            logging.debug('>> [NOT ALLOWED] DNS Request from: %s' % (host,))
            return

        logging.debug('>> DNS Request from: %s' % (host,))
        response = DNSResponse(query_res).packet
        self.transport.sendto(response, address)

        logging.debug('>> DNS Request Sent: %s' % (host,))


########################################################
# REST API Parts
# async def hello(request):
#    return web.Response(text="Hello, world")
def check_secret(data):
    """
    While API is called, check Secret token.
    :param data: parsed post parameters
    :return: (Success?(bool), if failed Response JSON struct with error message)
    """
    if len(config.API_SECRET) > 0:
        if not 'secret' in data.keys() or config.API_SECRET != str(data['secret']):
            return (False, web.json_response({'success': False, 'error': "secret is diffrent"}))
    return (True, None)


async def delete_rule(request):
    # curl -XDELETE 0.0.0.0:5555/rule -D 'id=1'  -v
    data = await request.post()
    r, v = check_secret(data)
    if not r: return v

    try:
        ids = int(data['id'])
        return web.json_response({'success': rule.delete_item(ids)})
    except Exception as e:
        return web.json_response({'success': False, 'error': str(e)})


async def add_rule(request):
    # curl -XPUT 0.0.0.0:5555/rule -d 'id=1&domain=google.com&type=0&regex=false'  -v
    # curl -XPUT 0.0.0.0:5555/rule -d 'id=2&domain=github.com&type=0&regex=false'  -v
    # Allow All host
    # curl -XPUT 0.0.0.0:5555/rule -d 'id=60000&domain=.*&type=0&regex=true'  -v
    data = await request.post()
    r, v = check_secret(data)
    if not r: return v

    try:
        ids, domain, types, regexs = int(data['id']), str(data['domain']), int(data['type']), (
                str(data['regex']).lower() == "true")
        return web.json_response({'success': rule.add_item(ids, domain, types, regexs)})
    except Exception as e:
        return web.json_response({'success': False, 'error': str(e)})


async def get_all_rules(request):
    # curl 0.0.0.0:5555/rules
    if len(config.API_SECRET) > 0:
        return web.json_response({'success': False, 'error': 'required secret'})

    res = rule.get_list()
    res['success'] = True
    return web.json_response(res)


async def post_get_all_rules(request):
    # curl -XPOST 0.0.0.0:5555/rules -d 'secret=ASDF'  -v
    data = await request.post()

    r, v = check_secret(data)
    if not r: return v

    res = rule.get_list()
    res['success'] = True
    return web.json_response(res)


async def delete_ipaddr(request):
    # curl -XDELETE 0.0.0.0:5555/ipaddr -D 'addr=10.2.1.0/24'  -v
    data = await request.post()
    r, v = check_secret(data)
    if not r: return v

    try:
        addr = str(data['addr'])
        return web.json_response({'success': ipcheck.remove(addr)})
    except Exception as e:
        return web.json_response({'success': False, 'error': str(e)})


async def add_ipaddr(request):
    # curl -XPUT 0.0.0.0:5555/ipaddr -d 'addr=10.2.1.0/24'  -v
    # curl -XPUT 0.0.0.0:5555/ipaddr -d 'addr=127.0.0.1/24'  -v
    data = await request.post()
    r, v = check_secret(data)
    if not r: return v

    try:
        addr = str(data['addr'])
        return web.json_response({'success': ipcheck.add(addr)})
    except Exception as e:
        return web.json_response({'success': False, 'error': str(e)})


async def get_all_ipaddr(request):
    # curl 0.0.0.0:5555/ipaddr
    if len(config.API_SECRET) > 0:
        return web.json_response({'success': False, 'error': 'required secret'})

    res = {}
    res["allow_ipaddrs"] = ipcheck.get_all()
    res['success'] = True
    return web.json_response(res)


async def post_get_all_ipaddr(request):
    # curl -XPOST 0.0.0.0:5555/ipaddr -d 'secret=ASDF'  -v
    data = await request.post()

    r, v = check_secret(data)
    if not r: return v

    res = {}
    res["allow_ipaddrs"] = ipcheck.get_all()
    res['success'] = True
    return web.json_response(res)


# API Routing
app = web.Application()
app.add_routes([web.delete('/rule', delete_rule)])
app.add_routes([web.put('/rule', add_rule)])
app.add_routes([web.post('/rules', post_get_all_rules)])
app.add_routes([web.get('/rules', get_all_rules)])

app.add_routes([web.delete('/ipaddr', delete_ipaddr)])
app.add_routes([web.put('/ipaddr', add_ipaddr)])
app.add_routes([web.post('/ipaddr', post_get_all_ipaddr)])
app.add_routes([web.get('/ipaddr', get_all_ipaddr)])


class RESTServers(object):
    """
    REST Server with aiohttp. with low level controlling
    """

    def __init__(self, controller, app, host, port):
        self._app, self.controller, self._host, self._port = app, controller, host, port

    async def aio_server_main(self):
        # with AppRunner
        # https://aiohttp.readthedocs.io/en/stable/web_reference.html#aiohttp-web-app-runners-reference
        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, self._host, self._port)
        await self._site.start()

    def warmup(self):
        self.controller.get_loop().run_until_complete(self.aio_server_main())
        logging.info('Listening established on {0}/aiohttp'.format(self._port))


# DNS Server Class
class DNSServers(object):
    """
    DNS Server with AsyncIO
    """

    def __init__(self, controller, host, port):
        self.controller, self._host, self._port = controller, host, port
        self._server_core = self.controller.get_loop().create_datagram_endpoint(
            DNSPacketHandler, local_addr=(host, port))

    def warmup(self):
        self._server, _transport = self.controller.get_loop().run_until_complete(self._server_core)
        self.controller.add_server(self._server)
        logging.info('Listening UDP Socket on {0}'.format(self._port))


async def dial(client_conn, server_conn):
    """dial between client and server"""

    async def io_copy(reader, writer):
        """bytes stream copy"""
        try:
            while True:
                data = await reader.read(32)
                if not data: break
                writer.write(data)
        except:
            pass
        finally:
            writer.close()

    asyncio.ensure_future(io_copy(client_conn[0], server_conn[1]))
    asyncio.ensure_future(io_copy(server_conn[0], client_conn[1]))


# Proxy Server Class
class ProxyServers(object):
    """
    SNI Proxy Server
    """

    def __init__(self, controller, host, port):
        self.controller, self._host, self._port = controller, host, port
        self._server_core = asyncio.start_server(self.handle_connection, port=self._port)

    def warmup(self):
        self._server = self.controller.get_loop().run_until_complete(self._server_core)
        self.controller.add_server(self._server)
        logging.info('Listening established on {0}'.format(self._server.sockets[0].getsockname()))

    def refuse_request(self, writer):
        """
        request alert handshake failure
        """
        # 0x15 => Content Type: Alert
        # 0x0301 => Version: TLS v1
        # 0x0002 => Length: 2
        # 0x02 => Alert Message Level: Fatal
        # 0x28 => Alert Message Descrption: Handshake Failure
        writer.write(b'\x15\x03\x01\x00\x02\x02\x28')
        writer.close()

    async def handle_connection(self, reader, writer):
        # Some Code From https://github.com/zengxs/sniproxy
        """
        process tls_v1 request
        """
        time_start = time.time()
        peername = writer.get_extra_info('peername')

        # IP Check
        if not ipcheck.check_allowed(peername[0]):
            writer.close()
            logging.info('Client IP is Banned.')
            return

        headers = await reader.read(4096)
        server_host, packet_types = extract_server_name(headers)

        logging.debug('Attmpt connect to {}:{}/{}'.format(server_host, self._port, packet_types))

        if server_host is None:
            writer.close()
            logging.info('Cannot find Host Header or SNI field on TLS Packet.')
            return

        result_found, result_allowed, result_upstream, res_id, res_domain, res_regex = rule.check_domain(server_host)
        if result_allowed is False:
            writer.close()
            logging.info('Not Allowed Host.')
            return

        target_server_ip = query_dns(server_host, use_upstream=False)
        if target_server_ip is None:
            # Cannot Resolve Host
            logging.info('Host Cannot Resolved "{}"'.format(server_host))
            writer.close()
            return

        logging.info('Host Resolved "{} -> {}"'.format(server_host, target_server_ip))

        time_before_req = time.time()
        logging.debug('Time usage before real request: {} millisecs'.format((time_before_req - time_start) * 1000))

        try:
            server_conn = await asyncio.open_connection(target_server_ip, self._port)
            # rewrite client hello to server
            server_conn[1].write(headers)

            logging.debug('Time for open_connection and send client hello: {} millisecs'.format(
                (time.time() - time_before_req) * 1000))

            # dial between client and server
            asyncio.ensure_future(dial((reader, writer), server_conn))
            log_message = "Allowed"
            logging.info(
                'Accepted connection[{}] from {}, attmpt connect to "{}({}):{}": {}'.format(packet_types, peername,
                                                                                            server_host,
                                                                                            target_server_ip,
                                                                                            self._port, log_message))
        except Exception as e:
            writer.close()
            logging.info('Error while Communication.', e)


# Main Executor
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    # AsyncIO controller
    ctl = Controller()

    # Set Servers
    server_dns = DNSServers(ctl, "0.0.0.0", config.dnsserver_port)
    server_rest = RESTServers(ctl, app, "0.0.0.0", config.apiserver_port)

    proxies = []
    for i in config.PROXY_PORTS.split(","):
        port = int(i)
        print("ADD PORT:", port)
        proxies.append(ProxyServers(ctl, None, port))

    # Server Up!
    try:
        server_dns.warmup()
        server_rest.warmup()
        for i in proxies:
            i.warmup()
        ctl.start()
    except KeyboardInterrupt:
        pass  # Press Ctrl+C to stop
    finally:
        ctl.stop()

# Testing using cURL (SNI/HTTP)
# curl http://github.com --resolve github.com:80:127.0.0.1 -vvv
# curl https://github.com --resolve github.com:443:127.0.0.1 -vvv
# Testing DNS
# dig @0.0.0.0 google.com

# Sample Allow All
# curl -XPUT 0.0.0.0:5555/rule -d 'id=60000&domain=.*&type=0&regex=true' -v
# curl -XPUT 0.0.0.0:5555/ipaddr -d 'addr=127.0.0.0/24' -v
# curl https://github.com --resolve github.com:443:127.0.0.1 -vvv
