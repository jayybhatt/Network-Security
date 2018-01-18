## Boosted SSH

This is a **plugboard** proxy for a normal publicly accessible ssh server.

This README explains the motivation for this project.
For Implementation details please read Report.txt

#### Motivation
Consider for example the case of an **SSH server** with a public IP address. No
matter how securely the server has been configured and how strong keys are
used, it might suffer from a **zero day vulnerability** that allows remote code
execution even before the completion of the authentication process. This could
allow attackers to compromise the server even without having proper
authentication credentials. The **Heartbleed OpenSSL bug** is a recent example of
such a serious vulnerability against SSL/TLS.

The plugboard proxy developed here, named **pbproxy**, adds an *extra
layer of encryption* to connections towards TCP services. Instead of connecting
directly to the service, clients connect to pbproxy (running on the same
server), which then **relays** all traffic to the actual service. Before relaying
the traffic, pbproxy *always* decrypts it using a static symmetric key. This
means that if the data of any connection towards the protected server is not
properly encrypted, then it will turn into garbage before reaching the
protected service.

Attackers who might want to exploit a zero day vulnerability in the protected
service will first have to know the secret key for having a chance to
successfully deliver their attack vector to the server. This of course assumes
that the plugboard proxy does not suffer from any vulnerability itself. 

Given that its task and its code are much simpler compared to an actual service
(e.g., an SSH server), its code can be audited more easily and it can be more
confidently exposed as a publicly accessible service.

Clients who want to access the protected server should proxy their traffic
through a local instance of pbroxy, which will encrypt the traffic using the
same symmetric key used by the server. In essence, pbproxy can act both as
a client-side proxy and as server-side reverse proxy.

**USAGE -**

```
pbproxy [-l port] -k keyfile destination port

  -l  Reverse-proxy mode: listen for inbound connections on *port* and relay
      them to *destination*:*port*

  -k  Use the symmetric key contained in <keyfile> (as a hexadecimal string)
```

* The program is written in C, using the OpenSSL library for all
  cryptographic operations, and run on Linux
* Data is encrypted/decrypted using AES in CTR mode (bi-directional
  communication)
* In client mode, plaintext traffic is read from stdin
* In server mode, pbrpoxy keeps listening for incoming connections after
  a previous session is terminated
  
Going back to the SSH example, let's see how pbproxy can be used to harden an
SSH server. Assume that we want to protect a publicly accessible sshd running
on vuln.cs.stonybrook.edu. First, we configure sshd to listen *only* on the
localhost interface, making it inaccessible from the public network. Then, we
fire up a reverse pbproxy instance on the same host:

```
  pbproxy -k mykey -l 2222 localhost 22
```

Clients can then connect to the SSH server using the following command:

```
  ssh -o "ProxyCommand pbproxy -k mykey vuln.cs.stonybrook.edu 2222" localhost
```

This will result in a data flow similar to the following:

```
ssh <--stdin/stdout--> pbproxy-c <--socket 1--> pbproxy-s <--socket 2--> sshd

|______________________________|               |_____________________________|
             client                                        server           
```

To test the setup, a similar data flow can be achieved using netcat instead
of pbproxy, by first running it on the same server as sshd as follows:

```
  nc -l -p 2222 -c 'nc localhost 22'
```

Then connecting from the client machine as follows:

```
  ssh -o "ProxyCommand nc vuln.cs.stonybrook.edu 2222" localhost
``` 
