# **2. BACKEND INITIALIZATION**

The entrypoint of backend application is the "main" function in [backend/src/main.go](../backend/src/main.go).

This function will generate server DTLS certificate, discover local IPs and external IP by asking configured STUN Server, create the conference manager object, start UDP listener, HTTP server with WebSocket for Signaling, then wait for client requests.

## **2.1. Waiting loop**

It starts with creating a wait group, adds threads that needs to be added to the wait list. The *waitGroup.Wait()* method runs in a loop that waits until waitGroup item count becomes zero, so the process doesn't end.

<sup>from [backend/src/main.go](../backend/src/main.go)</sup>

```go
func main() {
    waitGroup := new(sync.WaitGroup)
    ...
    waitGroup.Wait()
}
```

## **2.2. Loading configuration**

Configuration file is loaded from [config.yaml](../backend/config.yml).

Sources:

* [A Medium article](https://medium.com/@bnprashanth256/reading-configuration-files-and-environment-variables-in-go-golang-c2607f912b63)
* [Viper project (Github)](https://github.com/spf13/viper)

<sup>from [backend/src/main.go](../backend/src/main.go)</sup>

```go
    config.Load()
```

## **2.3. DTLS initialization, generating self-signed certificate**

One piece of the process after a client's first request is DTLS Handshake. We will discuss further in chapter [05. DTLS HANDSHAKE](./05-DTLS-HANDSHAKE.md)

During this handshake process, each peer send their digitally signed certificate each other to identify and prove themselves.

This certifcate is a [X.509 certificate](https://en.wikipedia.org/wiki/X.509). In the DTLS handshake, you can use a pair of private key and public key, which:

* Previously generated and digitally signed by a known [Certificate Authority](https://en.wikipedia.org/wiki/Certificate_authority) (keys are stored in disk, database, configuration file, or somewhere in sort of formats)
* Previously generated and digitally signed by yourself ([Self-signed Certificate](https://en.wikipedia.org/wiki/Self-signed_certificate) by 3rd party software like OpenSSL) (keys are stored in disk or database, configuration file, or somewhere in sort of formats)
* **(Our preference)** On-the-fly generated and digitally signed by yourself (same principles with Self-signed Certificate) but stored temporarily in RAM, it changes with every start of the application.

<sup>from [backend/src/main.go](../backend/src/main.go)</sup>

```go
    dtls.Init()
```

When we go deeper into dtls.Init() function, we find ourselves at "GenerateServerCertificate" function in [backend/src/dtls/crypto.go](../backend/src/dtls/crypto.go)

This function calls generateServerCertificatePrivateKey, which generates a random private key using specified "rand.Reader" (using standard random generator of Go) and sign it using [ECDSA - Elliptic Curve Digital Signature Algorithm](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) with P-256 (secp256r1) [curve](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography).

You can use different random generators (in cryptography, randomness is an important thing, and is your "random number" truly random? [See this post](https://stackoverflow.com/questions/4156907/why-is-random-not-so-random)). Cryptographic libraries like OpenSSL can generate random values in different way of randomness.

Also we can use different methods to generate private and public keys, but in this project we preferred these options.

<sup>from [backend/src/dtls/crypto.go](../backend/src/dtls/crypto.go)</sup>

```go
func generateServerCertificatePrivateKey() (*ecdsa.PrivateKey, error) {
    return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
```

Now, we have randomly generated private key, and it's signed form (public key) in same object ([ecdsa.PrivateKey](https://pkg.go.dev/crypto/ecdsa#PrivateKey)). We create an [X.509 Certificate](https://pkg.go.dev/crypto/x509#Certificate) as byte array, then put them together into a [tls.Certificate](https://pkg.go.dev/crypto/tls#Certificate) object.

<sup>from [backend/src/dtls/crypto.go](../backend/src/dtls/crypto.go)</sup>

```go
    pubKey := &serverCertificatePrivateKey.PublicKey
    template := x509.Certificate{
        SerialNumber: serialNumber,
        Version:      2,
        IsCA:         true,
        Subject: pkix.Name{
            CommonName: "WebRTC-Nuts-and-Bolts",
        },
        NotBefore: time.Now(),
        NotAfter:  time.Now().Add(time.Hour * 24 * 180),

        KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
        ExtKeyUsage: []x509.ExtKeyUsage{
            x509.ExtKeyUsageClientAuth,
            x509.ExtKeyUsageServerAuth,
        },
        BasicConstraintsValid: true,
    }

    raw, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, serverCertificatePrivateKey)
    if err != nil {
        return nil, err
    }

    return &tls.Certificate{
        Certificate: [][]byte{raw},
        PrivateKey:  serverCertificatePrivateKey,
        Leaf:        &template,
    }, nil
```

We store the generated certificate as global variable, "dtls.ServerCertificate" (*tls.Certificate)

Then, we should get fingerprint hash of this Server Certificate, to use further in SDP generation. We call "GetCertificateFingerprintFromBytes" function in [backend/src/dtls/crypto.go](../backend/src/dtls/crypto.go)

This function takes the byte array consists of certificate content, calculates [SHA256 Checksum](https://en.wikipedia.org/wiki/SHA-2) of it, result will be 32 bytes. Then, it converts this 32 bytes array to string which separated with ":", like "12:B9:B6:79:44:19:52:26:1D:01:63:2B:8B:3C:7D:19:CC:B2:5F:B5:9D:68:94:39:8D:01:D0:7B:40:6E:44:65". We store the result as global variable, "dtls.ServerCertificateFingerprint" (string)

<sup>from [backend/src/dtls/crypto.go](../backend/src/dtls/crypto.go)</sup>

```go
func GetCertificateFingerprintFromBytes(certificate []byte) string {
    fingerprint := sha256.Sum256(certificate)

    var buf bytes.Buffer
    for i, f := range fingerprint {
        if i > 0 {
            fmt.Fprintf(&buf, ":")
        }
        fmt.Fprintf(&buf, "%02X", f)
    }
    return buf.String()
}
```

Sources: 

* [WebRTC for the Curious: Securing](https://webrtcforthecurious.com/docs/04-securing/#securing) (this source also contains details of DTLS Handshake which we will discuss further)
* [Pion WebRTC DTLS project, GenerateSelfSigned function (Github)](https://github.com/pion/dtls/blob/bee42643f57a7f9c85ee3aa6a45a4fa9811ed122/pkg/crypto/selfsign/selfsign.go#L22)
* [What Is an X.509 Certificate & How Does It Work?
](https://sectigo.com/resource-library/what-is-x509-certificate)
* [Generate a self-signed certificate in Go (Gist)
](https://gist.github.com/samuel/8b500ddd3f6118d052b5e6bc16bc4c09)
* SHA256 Sum on command line [source 1](https://www.baeldung.com/linux/sha-256-from-command-line), [source 2](https://techdocs.akamai.com/download-ctr/docs/verify-checksum)


## **2.4. Gathering local and external IPs**

We need to know which IPs (local or external) that our server is reachable on, to use further in SDP generation (candidates part).

<sup>from [backend/src/main.go](../backend/src/main.go)</sup>

```go
    discoveredServerIPs := discoverServerIPs()
```

* Discovery of local IP addresses of available and active [network interfaces](https://en.wikipedia.org/wiki/Network_interface): Made via  "GetLocalIPs" function in [backend/src/common/networkutils.go](../backend/src/common/networkutils.go). Due to our application runs in a container, and we didn't configure Docker networking type of container as "host", we can gather only container's network interfaces, not the host machine. Expected output is one IP that in our Docker's subnet, usually starts with 172.

<br>
Note: Anyone outside the Docker network (including the host machine itself) cannot reach using this IP address. The other side of Docker networking interface to the host machine has a different gateway IP. But we include it in our result anyway.

* Including previously configured IP address to the result: In this project, we can't discover our LAN IP by code. So we have a configuration entry "server/udp/dockerHostIp" in [backend/config.yml](../backend/config.yml), accessing by "config.Val.Server.UDP.DockerHostIp" global variable. We include it in our result statically, if not empty.

* Discovery of external (WAN) IP, even if behind NAT. A logical and applicable way to learn our WAN IP (our router's IP open to internet) is to ask someone else outside our network. As there are some globally available free STUN Servers, we can use one which is set up by ourselves; however, it is important that the STUN Server should be outside of our network, we should access it by WAN. We need a STUN (Session Traversal Utilities for NAT) client to speak in STUN protocol, so our project implements it with only required parts (not all STUN messages or attributes implemented).

Sources:

* [WebRTC for the Curious: STUN](https://webrtcforthecurious.com/docs/03-connecting/#stun)
* [Wikipedia: STUN](https://en.wikipedia.org/wiki/STUN)
* [Some STUN Server addresses](https://gist.github.com/zziuni/3741933)
* [STUN Protocol RFC - Session Traversal Utilities for NAT](https://datatracker.ietf.org/doc/html/rfc5389)


### **2.4.1. Using our STUN Client**

We create a STUN Client via "NewStunClient" function in [backend/src/stun/stunclient.go](../backend/src/stun/stunclient.go). This function takes some arguments:

* serverAddr: Configured STUN Server Address (can be accessed via config.Val.Server.StunServerAddr). Default is "stun.l.google.com:19302".
* ufrag: "User fragment" is a string can be considered as "user name" for STUN Server. We generate a random ufrag via "GenerateICEUfrag" function in [backend/src/agent/generators.go](../backend/src/agent/generators.go).
* pwd: Can be considered as "password" for STUN Server.  We generate a random ufrag via "GenerateICEPwd" function in [backend/src/agent/generators.go](../backend/src/agent/generators.go).

<sup>from [backend/src/stun/stunclient.go](../backend/src/stun/stunclient.go)</sup>

```go
func NewStunClient(serverAddr string, ufrag string, pwd string) *StunClient {
    return &StunClient{
        ServerAddr: serverAddr,
        Ufrag:      ufrag,
        Pwd:        pwd,
    }
}
```

We call our STUN Client's Discover() method, then add it to our candidate IP list.

<sup>from [backend/src/main.go](../backend/src/main.go)</sup>

```go
    mappedAddress, err := stunClient.Discover()
```

### **2.4.2. Implementing STUN Protocol (as Client)**

<sup>STUN packet structure</sup>

```console
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0 0|     STUN Message Type     |         Message Length        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Magic Cookie                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                     Transaction ID (96 bits)                  |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             Data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Our STUN message struct in [backend/src/stun/message.go](../backend/src/stun/message.go):

<sup>from [backend/src/stun/message.go](../backend/src/stun/message.go)</sup>

```go
type Message struct {
    MessageType   MessageType
    TransactionID [TransactionIDSize]byte
    Attributes    map[AttributeType]Attribute
    RawMessage    []byte
}
```

As a client, to ask our IP to the server, we should create a *STUN Binding Request* message and encode it to a byte array.

* We generate a random 12 bytes (96 bits) Transaction ID via "generateTransactionID" function in [backend/src/stun/stunclient.go](../backend/src/stun/stunclient.go)
* Create a STUN message with "STUN Message Type" of MessageTypeBindingRequest (consists of Method: MessageMethodStunBinding (0x0001) and Class: MessageClassRequest (0x00)), generated Transaction ID and STUN Magic Cookie (constant value: 0x2112A442).
<br>
You can find:

    * MessageType constants in [backend/src/stun/messagetype.go](../backend/src/stun/messagetype.go)
    * MessageClass constants in [backend/src/stun/messageclass.go](../backend/src/stun/messageclass.go)
    * MessageMethod constants in [backend/src/stun/messagemethod.go](../backend/src/stun/messagemethod.go)

* Now, our steps for sending binding request are:
    * We resolve IP address of ServerAddr (with port number)
    * Create binding request message object
    * Encode it into a byte array
        * Before encoding, we call "preEncode" function in [backend/src/stun/message.go](../backend/src/stun/message.go) to remove attributes which has AttrMessageIntegrity and AttrFingerprint types, if exist, then add an attribute which has AttrSoftware type.
        * After encoding, we call "postEncode" function in [backend/src/stun/message.go](../backend/src/stun/message.go) to add attributes which has AttrMessageIntegrity and AttrFingerprint types. While adding these two attributes; we should calculate SHA1 [HMAC](https://en.wikipedia.org/wiki/HMAC) of the message via "calculateHmac" function using "pwd" value as key to [hmac.New](https://pkg.go.dev/crypto/hmac#New), then calculate [CRC32](https://en.wikipedia.org/wiki/Cyclic_redundancy_check) checksum of the message via "calculateFingerprint" function, by [crc32.ChecksumIEEE](https://pkg.go.dev/hash/crc32#ChecksumIEEE).
    * Start an UDP listener (without specifying any IP or port)
    * Write encoded byte array to STUN Server UDP address via started listener.

<sup>from [backend/src/stun/stunclient.go](../backend/src/stun/stunclient.go)</sup>

```go
    serverUDPAddr, err := net.ResolveUDPAddr("udp", c.ServerAddr)
    if err != nil {
        return nil, err
        //return NATError, nil, err
    }
    bindingRequest := createBindingRequest(transactionID)
    encodedBindingRequest := bindingRequest.Encode(c.Pwd)
    conn, err := net.ListenUDP("udp", nil)
    if err != nil {
        return nil, err
    }
    defer conn.Close()
    conn.WriteToUDP(encodedBindingRequest, serverUDPAddr)
```

After we have sent *STUN Binding Request* message successfully, we expect that the STUN Server sends us *STUN Binding Response*.

* Now, our steps for reading incoming binding response are:
    * Waiting for incoming bytes via conn.ReadFromUDP
    * If any packet was received, we check "is packet's sender our STUN Server?". We ignore any packet from other peers
    * Decode the byte array into "stun.Message" object
    * Calculate HMAC and Fingerprint (CRC32) values and compare with message's AttrMessageIntegrity and AttrFingerprint attributes, via stunMessage.Validate function
    * If message integrity and authorization check succeeded, we decode the attribute that contains result IP address encoded with XOR, via DecodeAttrXorMappedAddress function, and return as result.

<sup>from [backend/src/stun/stunclient.go](../backend/src/stun/stunclient.go)</sup>

```go
    buf := make([]byte, 1024)

    for {
        bufLen, addr, err := conn.ReadFromUDP(buf)
        if err != nil {
            return nil, err
        }
        // If requested target server address and responder address not fit, ignore the packet
        if !addr.IP.Equal(serverUDPAddr.IP) || addr.Port != serverUDPAddr.Port {
            continue
        }
        stunMessage, stunErr := DecodeMessage(buf, 0, bufLen)
        if stunErr != nil {
            panic(stunErr)
        }
        stunMessage.Validate(c.Ufrag, c.Pwd)
        if !bytes.Equal(stunMessage.TransactionID[:], transactionID[:]) {
            continue
        }
        xorMappedAddressAttr, ok := stunMessage.Attributes[AttrXorMappedAddress]
        if !ok {
            continue
        }
        mappedAddress := DecodeAttrXorMappedAddress(xorMappedAddressAttr, stunMessage.TransactionID)
        return mappedAddress, nil
    }
```

At the end, now we have gathered all available IP addresses.

Sources:

* [go-stun project (Github)](https://github.com/ccding/go-stun)

## **2.5. Initialize Conference Manager**

We create our ConferenceManager object that manages active conferences, server side ICE Agents per conference, and SDP Offer Answers, incoming via signaling WebSocket.

The ConferenceManager has Run() method to listen ChanSdpOffer [Go Channel](https://go.dev/tour/concurrency/2) in infinite loop, we call this method as [Go Routine](https://medium.com/technofunnel/understanding-golang-and-goroutines-72ac3c9a014d), so it runs in parallel thread. We increase waitGroup's waiting list.

<sup>from [backend/src/main.go](../backend/src/main.go)</sup>

```go
    conferenceManager = conference.NewConferenceManager(discoveredServerIPs, config.Val.Server.UDP.SinglePort)
    waitGroup.Add(1)
    go conferenceManager.Run(waitGroup)
```

Sources:

* [Channel in Golang](https://www.geeksforgeeks.org/channel-in-golang/)
* [Goroutines](https://golangbot.com/goroutines/)

## **2.6. Starting UDP Listener**

We create our UdpListener object that starts to listen specified UDP port and process incoming packets.

The UdpListener has Run() method to listen UDP port in infinite loop, we call this method as [Go Routine](https://medium.com/technofunnel/understanding-golang-and-goroutines-72ac3c9a014d), so it runs in parallel thread. We increase waitGroup's waiting list.

<sup>from [backend/src/main.go](../backend/src/main.go)</sup>

```go
    var udpListener = udp.NewUdpListener("0.0.0.0", config.Val.Server.UDP.SinglePort, conferenceManager)
    waitGroup.Add(1)
    go udpListener.Run(waitGroup)
```

At the "Run" function in [backend/src/udp/udpListener.go](../backend/src/udp/udpListener.go), we create [net.UDPConn](https://pkg.go.dev/net#ListenUDP) object.

* Now, our steps for reading incoming binding response are:
    * Waiting for incoming bytes via conn.ReadFromUDP
    * Check if the sender IP and port socket known by us, if known, get it as destinationSocket variable
    * Otherwise, if this packet is the first packet coming from the sender, we expect that this packet is STUN Binding Request. If it is, we read it's ufrag value (two ufrags separated by ":", one for client ICE agent, one for server ICE agent), and check if we have a Server ICE Agent with incoming ufrag. Then we check if the client ufrag is known by us (previously came by SDP Offer Answer from the client)
    * If everything is OK, we create an "agent.UDPClientSocket" object and set it to Server ICE Agent's and UDP Listener's sockets map
    * Then, forward incoming packet to the "AddBuffer" function of "agent.UDPClientSocket" (we will discuss further)
    * AddBuffer function acts as demultiplexer for different types of packets (different types of protocols) on same connection.

<sup>from [backend/src/udp/udpListener.go](../backend/src/udp/udpListener.go)</sup>

```go
    conn, err := net.ListenUDP("udp", &net.UDPAddr{
        IP:   net.IP{0, 0, 0, 0},
        Port: udpListener.Port,
    })

    ...

    udpListener.conn = conn

    defer conn.Close()
    ...

    for {
        bufLen, addr, err := conn.ReadFromUDP(buf)
        if err == nil {
            // Is the client socket known and authenticated by server before?
            destinationSocket, ok := udpListener.Sockets[string(addr.IP)+":"+string(rune(addr.Port))]

            if !ok {
                // If client socket is not known by server, it can be a STUN binding request.
                // Read the server and client ufrag (user fragment) string concatenated via ":" and split it.
                ...
            }
            // Now the client socket is known by server, we forward incoming byte array to our socket object dedicated for the client.
            destinationSocket.AddBuffer(buf, 0, bufLen)
        }

        ...
    }
```

## **2.7. Starting Signaling HTTP Server**

We create our signaling.HttpServer object that starts to listen specified signaling port and process incoming HTTP requests.

The HttpServer has Run() method to listen signaling port in infinite loop, we call this method as [Go Routine](https://medium.com/technofunnel/understanding-golang-and-goroutines-72ac3c9a014d), so it runs in parallel thread. We increase waitGroup's waiting list.

<sup>from [backend/src/main.go](../backend/src/main.go)</sup>

```go
    httpServer, err := signaling.NewHttpServer(fmt.Sprintf(":%d", config.Val.Server.Signaling.WsPort), conferenceManager)
    ...
    waitGroup.Add(1)
    go httpServer.Run(waitGroup)
```

At the "NewHttpServer" function in [backend/src/signaling/httpserver.go](../backend/src/signaling/httpserver.go), we create signaling.HttpServer object and a signaling.WsHub object that manages WebSocket operations. Also we map "/" and "/ws" path patterns to handler functions.

"/" path for home page placeholder
<br>
"/ws" path for WebSocket requests.

<sup>from [backend/src/signaling/httpserver.go](../backend/src/signaling/httpserver.go)</sup>

```go
func NewHttpServer(httpServerAddr string, conferenceManager *conference.ConferenceManager) (*HttpServer, error) {
    wsHub := newWsHub(conferenceManager)

    httpServer := &HttpServer{
        HttpServerAddr: httpServerAddr,
        WsHub:          wsHub,
    }
    http.HandleFunc("/", httpServer.serveHome)
    http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
        httpServer.serveWs(w, r)
    })

    return httpServer, nil
}
```

At the "Run" function in [backend/src/signaling/httpserver.go](../backend/src/signaling/httpserver.go), we call wsHub.run() and http.ListenAndServe to start signaling HTTP server.

Sources:

* [Gorilla WebSocket: Chat Example (GitHub)](https://github.com/gorilla/websocket/tree/master/examples/chat)

Now, our server application is waiting for client interactions on:

* For signaling requests on WebSocket port 8081 (default)
* For incoming UDP packets (STUN, DTLS, RTP, RTCP, etc... packets) on port 15000 (default)

We are ready to answer client interactions!

<br>

---

<div align="right">

[&lt;&nbsp;&nbsp;Previous chapter: RUNNING IN DEVELOPMENT MODE](./01-RUNNING-IN-DEV-MODE.md)&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[Next chapter: FIRST CLIENT COMES IN&nbsp;&nbsp;&gt;](./03-FIRST-CLIENT-COMES-IN.md)

</div>
