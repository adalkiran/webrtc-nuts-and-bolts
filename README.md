# **WebRTC Nuts and Bolts**


[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white&style=flat-square)](https://www.linkedin.com/in/alper-dalkiran/)
[![Twitter](https://img.shields.io/badge/Twitter-1DA1F2?style=for-the-badge&logo=twitter&logoColor=white&style=flat-square)](https://twitter.com/aalperdalkiran)
[HitCount](https://hits.dwyl.com/adalkiran/webrtc-nuts-and-bolts.svg?style=flat-square&show=unique)
![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

A holistic way of understanding how WebRTC and its protocols run in practice, **with code and detailed documentation**. "The nuts and bolts" (practical side instead of theoretical facts, pure implementation details) of required protocols without using external dependencies or libraries.

When you run the project and follow the instructions, web page initializes the webcam, does handshake with the backend application (executes several WebRTC processes), at the end, the backend catches keyframe images and saves them as JPEG image files. You can see your caught keyframes at /backend/output/ folder as shoot1.jpg, shoot2.jpg etc... if multiple keyframes were caught.

You can track which steps taken during this journey by debugging or tracking the output at console.

![Backend initial output](docs/images/01-07-backend-initial-output.png)

<br>

## **WHY THIS PROJECT?**

This project was initially started to learn Go language and was made for experimental and educational purposes only, not for production use.

After some progress on the development, I decided to pivot my experimental work to a walkthrough document. Because although there are lots of resources that exist already on the Internet, they cover small chunks of WebRTC concepts or protocols atomically. And they use the standard way of inductive method which teach in pieces then assemble them.

But my style of learning leans on the deductive method instead of others, so instead of learning atomic pieces and concepts first, going linearly from beginning to the end, and learning an atomic piece on the time when learning this piece is required.

<br>

## **DOCUMENTATION**

The adventure of a WebRTC stream from start to finish can be found documented as step by step in [docs folder](docs/)

<br>

## **COVERAGE**

Web front-end side: Pure Typescript implementation:
* Communicate with signaling backend WebSocket,
* Gathering webcam streaming track from browser and send this track to backend via UDP.

Server back-end side: Pure Go language implementation:
* A simple signaling back-end WebSocket to transfer [SDP (Session Description Protocol)](https://en.wikipedia.org/wiki/Session_Description_Protocol) using [Gorilla WebSocket](https://github.com/gorilla/websocket) library.
* Single port UDP listener, supports demultiplexing different data packet types (STUN, DTLS handshake, SRTP, SRTCP) coming from the same UDP connection.
* Protocol implementations of (only required parts):
  * [STUN (Session Traversal Utilities for NAT)](https://en.wikipedia.org/wiki/STUN) for discovering external IP behind NAT by a STUN server and replying to the client's STUN binding request came by UDP connection.
  * [DTLS (Datagram Transport Layer Security)](https://en.wikipedia.org/wiki/Datagram_Transport_Layer_Security) for secure handshake, authenticating each oter, and crypto key exchange process. DTLS is similar to [TLS (Transport Layer Security)](https://tr.wikipedia.org/wiki/Transport_Layer_Security), DTLS runs over UDP instead of TCP. This project supports only DTLS v1.2.
  * [RTP (Real-time Transport Protocol)](https://en.wikipedia.org/wiki/Real-time_Transport_Protocol) for transferring media packets in fragments.
  * [SRTP (Secure Real-time Transport Protocol)](https://en.wikipedia.org/wiki/Secure_Real-time_Transport_Protocol), a secure version of RTP.
* Only header parsing for [VP8 video format](https://en.wikipedia.org/wiki/VP8) to depacketizing fragmented packets to construct a video frame. [libvpx-go](https://github.com/xlab/libvpx-go) was used for decoding VP8 keyframe as image.
* [github.com/fatih/color](https://github.com/fatih/color) was used while printing colored output on console while logging.
* Implementation of TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 [cipher suite](https://www.keyfactor.com/blog/cipher-suites-explained/) support using [Go Cryptography](https://pkg.go.dev/golang.org/x/crypto) library.


<br>

## **INSTALLATION and RUNNING**

This project was designed to run in Docker Container. Docker Compose file creates two containers: webrtcnb-ui and webrtcnb-backend.

**Important Note:**
<br>
First of all, you should learn your machine's LAN IP address and write it into [backend/config.yml](backend/config.yml) file at server/udp/dockerHostIp section.
<br>
Because, we didn't configure the docker networking type as "host", and the backend application in the container cannot discover the host machine's (your physical computer) real LAN IP but it needs this information to run correctly. Unfortunately, it can't run with 127.0.0.1. The LAN IPs usually start with 192 or 10.
<br>
Tried to configure the docker networking type as "host", but it doesn't work in Docker Desktop for Mac, because of Docker's subsystem runs in a Linux VM on MacOS, and it always returns 192.168.65.1 as gateway.

You can run it production mode or development mode.

### **Production Mode**

* Clone this repo and run in terminal:

```sh
$ docker-compose up -d
```

* Wait until Go and Node modules were installed and configured. This can take some time. You can checkout the download status by:

```sh
$ docker-compose logs -f
```

* After waiting for enough time, open a web browser and visit http://localhost:8080 (Tested on Chrome)

### <a name="dev-mode"></a> **Development Mode: VS Code Remote - Containers**

To continue with VS Code and if this is your first time to work with Remote Containers in VS Code, you can checkout [this link](https://code.visualstudio.com/docs/remote/containers) to learn how Remote Containers work in VS Code and follow the installation steps of [Remote Development extension pack](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.vscode-remote-extensionpack).

Then, follow these steps:

* Clone this repo to your local filesystem
* Open the folder "webrtc-nuts-and-bolts" with VS Code by "Open Folder..." command. This opens the root folder of the project.
* Press <kbd>F1</kbd> and select **"Remote Containers: Open Folder in Container..."** then select "backend" folder in "webrtc-nuts-and-bolts".
* This command creates (if they don't exist) required containers in Docker, then connects inside of webrtcnb-backend container for development and debugging purposes.
* Wait until the containers created, configured and related VS Code server extensions installed inside the container. This can take some time. VS Code can ask for some required installations, click "Install All" for these prompts.
* After completion of all installations, press <kbd>F5</kbd> to start server application.
* Then, open a web browser and visit http://localhost:8080 (Tested on Chrome)

<br>

## **ASSUMPTIONS**

Full-compliant WebRTC libraries should support a wide range of protocol details defined in RFC documents, client/server implementation differences, fallbacks for different protocol versions, a wide variety of cipher suites and media encoders/decoders. Also should be implemented as state machines, because WebRTC contains has some parts which managed as state machines, eg: [ICE (Interactive Connectivity Establishment)](https://en.wikipedia.org/wiki/Interactive_Connectivity_Establishment), [DTLS (Datagram Transport Layer Security)](https://en.wikipedia.org/wiki/Datagram_Transport_Layer_Security) handshake, etc...


In **WebRTC Nuts and Bolts** scenario, some assumptions have been made to focus only on required set of details.

| Full-compliant WebRTC libraries | WebRTC Nuts and Bolts | 
|---|---|
| WebRTC has no client or server concepts in its [peer-to-peer](https://tr.wikipedia.org/wiki/Peer-to-peer) nature, there are controlling or controlled peers. | This project aims to act as listener server and it only receives media, not sends. To make the code more simplistic and cleaner; the concepts "client" instead of "local peer" and "server" instead of "remote peer" has been used. |
| Should support both controlling and controlled roles. | Go language side will act only as server (ICE controlling), SDP offer will come from this side, then SDP answer will be expected from the client. |
| For separation of concerns and to maintain architectural extensibility, all WebRTC libraries were implemented as separate packages/repos (STUN package, DTLS package, SRTP package, etc...) | To keep it simple, this project was designed as [monorepo](https://en.wikipedia.org/wiki/Monorepo) but separated into packages. This choice depends on architectural needs and technical maintenance needs. |
| Should support DTLS fragmentation. |  DTLS fragmentation is not supported. |
| Should support multiple cipher suites for compatibility with different types of peers. More cipher suites can be found at [here](https://developers.cloudflare.com/ssl/ssl-tls/cipher-suites/). |  Only TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 is supported. |
| Should implement packet reply detection, handling corrupted packets, handling unordered packet sequences and packet losses, byte array length checks, lots of security protections against cyberattacks, etc... | This project was developed to run in only ideal conditions. Incoming malicious packets were not considered. |

<br>

## **RESOURCES**

I want to thank to contributors of the awesome sources which were referred during development of this project and writing this documentation. You can find these sources below, also in between the lines in code and documentation.

* [Wikipedia](https://en.wikipedia.org)
* [WebRTC For The Curious](https://webrtcforthecurious.com): Awesome resource on theoretical concepts of WebRTC. It is vendor agnostic. Created by creators of [Pion project](https://github.com/pion)
* [Pion project](https://github.com/pion)
  * [Pion DTLS](https://github.com/pion/dtls): A library for DTLS protocol, developed in Go. Some parts about cryptography used with from this project, with modifications.
  * [Pion SRTP](https://github.com/pion/srtp): A library for SRTP protocol, developed in Go. Some parts about cryptography used with from this project, with modifications.
* [Jitsi](https://github.com/jitsi)
  * [Jitsi ice4j](https://github.com/jitsi/ice4j): A library for ICE processes including gathering ICE candidates, developed in Java and Kotlin. You can start to explore from [here](https://github.com/jitsi/ice4j/blob/d7c0e27a1cde7b877b34d8bb68dc39f18dc45f16/src/main/java/org/ice4j/ice/harvest/SinglePortUdpHarvester.java) and [here](https://github.com/jitsi/ice4j/blob/d7c0e27a1cde7b877b34d8bb68dc39f18dc45f16/src/main/java/org/ice4j/ice/harvest/AbstractUdpListener.java#L47)
  * [Jitsi Media Transform](https://github.com/jitsi/jitsi-media-transform): A library for ICE processes including gathering ICE candidates, developed in Java and Kotlin. You can find different protocol implementations [here](https://github.com/jitsi/jitsi-media-transform/tree/master/src/main/kotlin/org/jitsi/nlj)
  * [Jitsi Videobridge](https://github.com/jitsi/jitsi-videobridge): A server application that orchestrates these processes and serves API interfaces, developed in Java and Kotlin
* [The Bouncy Castle Crypto Package For Java](https://github.com/bcgit/bc-java): A library for TLS processes and cryptography, developed in Java. 
* [Tinydtls](https://github.com/eclipse/tinydtls): A library for DTLS processes, developed in C.
* [Mozilla Web Docs: WebRTC API](https://developer.mozilla.org/en-US/docs/Web/API/WebRTC_API): A documentation on WebRTC API at browser side.
* Several RFC Documents: In code and documentation of this project, you can find several RFC document links cited.
<br>

## **LICENSE**

WebRTC Nuts and Bolts is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full license text.