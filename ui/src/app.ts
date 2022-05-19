import $ from "jquery";
import * as sdpTransform from 'sdp-transform';
import * as webrtcnbSdp from './sdp';

class RTC {
    localConnection: RTCPeerConnection;
    localTracks: MediaStreamTrack[] = [];

    constructor() {
        this.localConnection = this.createLocalPeerConnection();
    }

    createLocalPeerConnection() {
        const result = new RTCPeerConnection({
            iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
        });
        result.onicecandidate = (e: RTCPeerConnectionIceEvent) => {
            if ((<any>e.target).iceGatheringState != 'complete') {
                return;
            }
            console.log('onicecandidate', e.candidate, '\n', e);
            const parsedSdp: sdpTransform.SessionDescription = sdpTransform.parse(this.localConnection.localDescription.sdp);
            this.localDescriptionChanged(parsedSdp);
        };
        result.addEventListener('track', e => {
            console.log('onTrack', e);
        });
        result.onicecandidateerror = (e: Event) => {
            console.log('onicecandidateerror', e);
        };
        result.onconnectionstatechange = (e: Event) => {
            console.log('onconnectionstatechange', (<any>e.target).connectionState, '\n', e);
        };
        result.oniceconnectionstatechange = (e: Event) => {
            console.log('oniceconnectionstatechange', (<any>e.target).iceConnectionState, '\n', e);
            if ((<any>e.target).iceConnectionState == 'disconnected') {
                this.stop(true);
            }
        };
        result.onicegatheringstatechange = (e: Event) => {
            console.log('onicegatheringstatechange', (<any>e.target).iceGatheringState, '\n', e);
        };
        result.onnegotiationneeded = (e: Event) => {
            console.log('onnegotiationneeded', e);
        };
        result.onsignalingstatechange = (e: Event) => {
            console.log('onsignalingstatechange', (<any>e.target).signalingState, '\n', e);
        };
        return result;
    }

    createOffer(): Promise<sdpTransform.SessionDescription> {
        return this.localConnection.createOffer()
            .then(sdp => {
                this.localConnection.setLocalDescription(sdp);
                const parsedSdp: sdpTransform.SessionDescription = sdpTransform.parse(sdp.sdp);
                console.log('setLocalDescription', 'type:', sdp.type, 'sdp:\n', parsedSdp);
                return parsedSdp;
            })
    }

    createLocalTracks(): Promise<MediaStream> {
        return navigator.mediaDevices.getUserMedia({
            video: {
                height: 720
            },
            audio: true
        });
    }

    start() {
        return this.createLocalTracks()
            .then(stream => {
                stream.getTracks().forEach(track => {
                    this.localTracks.push(track);
                    this.localConnection.addTrack(track);
                });
            })
            .catch(e => {
                console.error("Error while starting: ", e);
                alert("Error while starting:\n" + e);
                this.stop(true);
            })
            .then(() => signaling.connect());
    }

    stop(closeConnection: Boolean) {
        this.localTracks.forEach(localTrack => {
            localTrack.enabled = false;
            localTrack.stop();
        });
        if (closeConnection) {
            this.localConnection.close();
            //Recreate a new RTCPeerConnection which is in "stable" signaling state.
            this.localConnection = this.createLocalPeerConnection();
        }
        this.localTracks = [];
        console.log('Stopping tracks. closeConnection: ', closeConnection);
    }

    localDescriptionChanged(parsedSdp: sdpTransform.SessionDescription) {
        this.sendSdpToSignaling(parsedSdp);
    }

    sendSdpToSignaling(parsedSdp: sdpTransform.SessionDescription) {
        console.log('sendSdpToSignaling', parsedSdp);
        signaling.ws.send(JSON.stringify({type: "SdpOfferAnswer", data: parsedSdp}));
    }

    acceptOffer(offerSdp: string) {
        return this.localConnection.setRemoteDescription({
            type: 'offer',
            sdp: offerSdp
        })
        .then(() => {
            return this.localConnection.createAnswer()
                .then((answer: RTCSessionDescriptionInit) => {
                    console.log('answer', answer.type, answer.sdp);
                    this.localConnection.setLocalDescription(answer);
                });
        });
    }
}

class Signaling {
    ws: WebSocket;

    connect() {
        console.log("Start connect() http://localhost:8081/ws/");
        this.ws = new WebSocket('ws://localhost:8081/ws');

        this.ws.onopen = () => {
            console.log('client side socket connection established');
        };

        this.ws.onclose = () => {
            console.log('client side socket connection disconnected');
        };

        this.ws.onerror = (error) => {
            console.log('Websocket error:', error);
            rtc.stop(true);
            alert("Could not connect to websocket. Ready state: " + (<WebSocket>error.target).readyState);
        };

        this.ws.onmessage = (message) => {
            const data = message.data ? JSON.parse(message.data) : null;
            console.log('Received from WS:', message.data);
            if (!data) {
                return;
            }
            switch (data.type) {
                case 'Welcome':
                    signaling.ws.send(JSON.stringify({type: "JoinConference", data: {
                        conferenceName: "defaultConference"
                    }}));

                    break;
                case 'SdpOffer':
                const sdpOffer: webrtcnbSdp.SdpMessage = <webrtcnbSdp.SdpMessage>data.data;
                const offerSdp 
                
                = sdpTransform.write({
                    origin: {
                        username: 'a_user',
                        sessionId: sdpOffer.sessionId,
                        sessionVersion: 2,
                        netType: 'udp',
                        ipVer: 4,
                        address: '127.0.0.1'
                    },
                    timing: {
                        start: 0,stop: 0
                    },
                    setup: 'actpass',
                    iceOptions: 'trickle',
                    media: sdpOffer.mediaItems.map(mediaItem => {
                        return {
                            mid: mediaItem.mediaId.toString(),
                            type: mediaItem.type,
                            port: 9,
                            rtcpMux: 'rtcp-mux',
                            protocol: 'UDP/TLS/RTP/SAVPF',
                            payloads: mediaItem.payloads,
                            connection: {
                                version: 4,
                                ip: '0.0.0.0'
                            },
                            iceUfrag: mediaItem.ufrag,
                            icePwd: mediaItem.pwd,
                            fingerprint: {
                                type: mediaItem.fingerprintType,
                                hash: mediaItem.fingerprintHash,
                            },
                            candidates: mediaItem.candidates.map(candidate => {
                                return { 
                                    foundation: '0',
                                    component: 1,
                                    transport: candidate.transport,
                                    priority: 2113667327,
                                    ip: candidate.ip,
                                    port: candidate.port,
                                    type: candidate.type
                                };
                            }),

                            rtp: [{
                                payload: parseInt(mediaItem.payloads),
                                codec: mediaItem.rtpCodec,
                            }],
                            fmtp: []
                        };
                    })
                });
                console.log('offerSdp', offerSdp);
                rtc.acceptOffer(offerSdp);
                break;
            }
        };
    }

    close() {
        this.ws.close();
    }
}

const rtc = new RTC();
(<any>window).rtc = rtc;

const signaling = new Signaling();
(<any>window).signaling = signaling;

function initApp() {
    $('#BtnCreatePC').on('click', () => rtc.start());
    $('#BtnStopPC').on('click', () => rtc.stop(true));
    $(window).bind('beforeunload', () => rtc.stop(true));
    
}

initApp();