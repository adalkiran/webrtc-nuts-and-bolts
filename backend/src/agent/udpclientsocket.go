package agent

import (
	"net"
	"strings"

	"github.com/adalkiran/webrtc-nuts-and-bolts/src/dtls"
	"github.com/adalkiran/webrtc-nuts-and-bolts/src/logging"
	"github.com/adalkiran/webrtc-nuts-and-bolts/src/rtcp"
	"github.com/adalkiran/webrtc-nuts-and-bolts/src/rtp"
	"github.com/adalkiran/webrtc-nuts-and-bolts/src/srtp"
	"github.com/adalkiran/webrtc-nuts-and-bolts/src/stun"
	"github.com/adalkiran/webrtc-nuts-and-bolts/src/transcoding"
)

var (
	handshakeManager = dtls.NewHandshakeManager()
	srtpManager      = srtp.NewSRTPManager()
)

type UDPClientSocket struct {
	Addr             *net.UDPAddr
	ServerUfrag      string
	ServerPwd        string
	ClientUfrag      string
	Conn             *net.UDPConn
	HandshakeContext *dtls.HandshakeContext
	SRTPContext      *srtp.SRTPContext

	RtpDepacketizer  chan *rtp.Packet
	vp8Depacketizer  chan *rtp.Packet
	vp8Decoder       *transcoding.VP8Decoder
	RtpPacketBuffer  map[uint16]*rtp.Packet
	LastRtpPacketSeq uint16
}

func NewUDPClientSocket(addr *net.UDPAddr, serverUfrag string, serverPwd string, clientUfrag string, conn *net.UDPConn, expectedFingerprintHash string) (*UDPClientSocket, error) {

	result := &UDPClientSocket{
		Addr:             addr,
		ServerUfrag:      serverUfrag,
		ServerPwd:        serverPwd,
		ClientUfrag:      clientUfrag,
		Conn:             conn,
		HandshakeContext: handshakeManager.NewContext(addr, conn, clientUfrag, expectedFingerprintHash),
		SRTPContext:      nil,

		RtpDepacketizer: make(chan *rtp.Packet, 1),
		vp8Depacketizer: make(chan *rtp.Packet, 1),
		RtpPacketBuffer: map[uint16]*rtp.Packet{},
	}
	result.HandshakeContext.OnDTLSStateChangeHandler = result.OnDTLSStateChangeEvent
	var err error
	result.vp8Decoder, err = transcoding.NewVP8Decoder(result.vp8Depacketizer)
	if err != nil {
		return nil, err
	}
	go result.runRtpDepacketizer()
	return result, nil
}

func (ms *UDPClientSocket) AddBuffer(buf []byte, offset int, arrayLen int) {
	logging.Descf(logging.ProtoUDP, "A packet received. The byte array (<u>%d bytes</u>) not parsed yet. Demultiplexing via if-else blocks.", arrayLen)
	if stun.IsMessage(buf, offset, arrayLen) {
		logging.Descf(logging.ProtoSTUN, "This is a STUN message.")
		stunMessage, stunErr := stun.DecodeMessage(buf, 0, arrayLen)
		if stunErr != nil {
			panic(stunErr)
		}
		logging.Descf(logging.ProtoSTUN, "We are checking integrity and authentication of the STUN message.")
		stunMessage.Validate(ms.ServerUfrag, ms.ServerPwd)
		logging.Infof(logging.ProtoSTUN, "Received <u>%s</u> message from: <u>%s</u>\n", stunMessage.MessageType, ms.Addr)

		switch stunMessage.MessageType {
		case stun.MessageTypeBindingRequest:
			userNameAttr, userNameExists := stunMessage.Attributes[stun.AttrUserName]
			if !userNameExists {
				return
			}
			userNameParts := strings.Split(string(userNameAttr.Value), ":")
			serverUfrag := userNameParts[0]
			clientUfrag := userNameParts[1]
			logging.Descf(logging.ProtoSTUN, "We are checking: are the incoming STUN binding request's user fragment (first part of username attribute) <u>%s</u> and our server ICE Agent's ufrag <u>%s</u> same?", serverUfrag, ms.ServerUfrag)

			if serverUfrag != ms.ServerUfrag {
				logging.Descf(logging.ProtoUDP, "STUN Binding Request message forwarded wrong agent, serverUfrag <u>%s</u> points, ignore it.", serverUfrag)
				return
			}
			if clientUfrag != ms.ClientUfrag {
				logging.Descf(logging.ProtoUDP, "It seems a STUN Binding Request message received after processed first one, clientUfrag <u>%s</u>, ignore it.", clientUfrag)
				return
			}
			logging.Descf(logging.ProtoSTUN, "This is a STUN Binding Request message with transaction <u>%s</u>, user name <u>%s</u>.  Client says to the server \"hey, I received some ICE candidates (IP-port pairs) via Signaling, I'm trying these candidates one by one. If this binding request message arrives at you, and you send me a binding response packet, I will understand that we can communicate by this channel, then I will start a DTLS handshake by sending a DTLS ClientHello message.\"", stunMessage.TransactionID, string(userNameAttr.Value))

			bindingResponse := createBindingResponse(stunMessage, ms.Addr, string(userNameAttr.Value))
			logging.Infof(logging.ProtoSTUN, "Sending response to <u>%v:%v</u> for transaction <u>%s</u>, user name <u>%s</u>\n", ms.Addr.IP, ms.Addr.Port, stunMessage.TransactionID, string(userNameAttr.Value))
			encodedBindingResponse := bindingResponse.Encode(ms.ServerPwd)

			ms.Conn.WriteToUDP(encodedBindingResponse, ms.Addr)
			logging.Descf(logging.ProtoSTUN, "Now we are waiting for a DTLS ClientHello packet from the client!")
		}
	} else if dtls.IsDtlsPacket(buf, offset, arrayLen) {
		logging.Descf(logging.ProtoDTLS, "This is a DTLS packet.")
		for offset < arrayLen {
			dtlsHeader, dtlsHandshakeHeader, dtlsMessage, newOffset, dtlsErr := dtls.DecodeDtlsMessage(ms.HandshakeContext, buf, offset, arrayLen)
			offset = newOffset
			if dtlsErr != nil {
				logging.Errorf(logging.ProtoDTLS, "Error %s", dtlsErr)
				return
			}
			if dtlsMessage == nil {
				//If nil was returned without an error, this messsage should be ignored
				return
			}
			alertMessage, ok := dtlsMessage.(*dtls.Alert)
			if ok {
				logging.Errorf(logging.ProtoUDP, "Received Alert: %s", alertMessage)
				return
			}
			logging.LineSpacer(2)
			logging.Infof(logging.ProtoDTLS, "Received message (<u>Flight %d</u>)\n%s\n%s\n%s", ms.HandshakeContext.Flight, dtlsHeader, dtlsHandshakeHeader, dtlsMessage)
			logging.LineSpacer(2)

			switch dtlsMessage.GetContentType() {
			case dtls.ContentTypeHandshake:
				err := handshakeManager.ProcessIncomingMessage(ms.HandshakeContext, dtlsMessage.(dtls.BaseDtlsHandshakeMessage))
				if err != nil {
					panic(err)
				}
			case dtls.ContentTypeAlert:
				alertMessage, _ := dtlsMessage.(*dtls.Alert)
				//If alert received after DTLS process completed successfully, process it here, if during a handshake, process it in handshake manager.
				if ms.HandshakeContext.DTLSState == dtls.DTLSStateConnected {
					logging.Errorf(logging.ProtoUDP, "Received Alert: %s", alertMessage)
					return
				} else {
					err := handshakeManager.ProcessIncomingAlert(ms.HandshakeContext, alertMessage)
					if err != nil {
						logging.Errorf(logging.ProtoUDP, "Error: %s", err)
						return
					}
				}
			}
		}
	} else if rtp.IsRtpPacket(buf, offset, arrayLen) {
		logging.Descf(logging.ProtoRTP, " This is a RTP packet.")
		rtpPacket, offset, err := rtp.DecodePacket(buf, offset, arrayLen)
		if err != nil {
			logging.Errorf(logging.ProtoRTP, "Unknown message from: %s, %v. Err: %v\n", ms.Addr, buf[offset:offset+arrayLen], err)
			return
		}
		logging.Infof(logging.ProtoRTP, "Received packet: %s\n", rtpPacket)
		ms.RtpDepacketizer <- rtpPacket
	} else if rtcp.IsRtcpPacket(buf, offset, arrayLen) {
		logging.Descf(logging.ProtoRTP, "This is a RTCP packet.")
		rtcpPacket, offset, err := rtcp.DecodePacket(buf, offset, arrayLen)
		if err != nil {
			logging.Warningf(logging.ProtoRTCP, "Unknown message from: <u>%s</u>, <u>%v</u>. Err: %v\n", ms.Addr, buf[offset:offset+arrayLen], err)
			return
		}
		logging.Infof(logging.ProtoRTCP, "Received packet: %s\n", rtcpPacket)
	} else {
		logging.Descf(logging.ProtoUDP, "This packet in a different format which is not known by the server, ignoring it.")
		logging.Warningf(logging.ProtoUDP, "Unknown message from: <u>%s</u>, <u>%v</u>", ms.Addr, buf[offset:offset+arrayLen])
	}
}

func createBindingResponse(request *stun.Message, addr *net.UDPAddr, userName string) *stun.Message {
	responseMessage := stun.NewMessage(stun.MessageTypeBindingSuccessResponse, request.TransactionID)

	responseMessage.SetAttribute(*stun.CreateAttrXorMappedAddress(responseMessage.TransactionID[:], addr))
	responseMessage.SetAttribute(*stun.CreateAttrUserName(userName))

	return responseMessage
}

func (ms *UDPClientSocket) runRtpDepacketizer() {
	defer close(ms.RtpDepacketizer)
	defer close(ms.vp8Depacketizer)
	go ms.vp8Decoder.Run()
	for rtpPacket := range ms.RtpDepacketizer {
		decrypted, err := ms.SRTPContext.DecryptRTPPacket(rtpPacket)
		rtpPacket.Payload = decrypted
		if err != nil {
			logging.Errorf(logging.ProtoDTLS, "Error while decrypting: %s", err)
			continue
		}
		switch rtpPacket.Header.PayloadType {
		case rtp.PayloadTypeVP8:
			ms.vp8Depacketizer <- rtpPacket
		}
	}
}

func (ms *UDPClientSocket) OnDTLSStateChangeEvent(dtlsState dtls.DTLSState) {
	logging.Infof(logging.ProtoDTLS, "State Changed: <u>%s</u> [<u>%v:%v</u>].\n", dtlsState, ms.HandshakeContext.Addr.IP, ms.HandshakeContext.Addr.Port)
	switch dtlsState {
	case dtls.DTLSStateConnected:
		logging.Descf(logging.ProtoDTLS, "DTLS Handshake succeeded. Will be waiting for SRTP packets, but before them, we should init SRTP context and SRTP cipher suite, with SRTP Protection Profile <u>%s</u>.", ms.HandshakeContext.SRTPProtectionProfile)
		ms.SRTPContext = srtpManager.NewContext(ms.Addr, ms.Conn, srtp.ProtectionProfile(ms.HandshakeContext.SRTPProtectionProfile))
		keyLength, err := ms.SRTPContext.ProtectionProfile.KeyLength()
		if err != nil {
			panic(err)
		}
		saltLength, err := ms.SRTPContext.ProtectionProfile.SaltLength()
		if err != nil {
			panic(err)
		}
		logging.Descf(logging.ProtoDTLS, "We should generate keying material from DTLS context. Key length: %d, Salt Length: %d, Total bytes length (consists of client and server key-salt pairs): <u>%d</u>", keyLength, saltLength, keyLength*2+saltLength*2)
		keyingMaterial, err := ms.HandshakeContext.ExportKeyingMaterial(keyLength*2 + saltLength*2)
		if err != nil {
			panic(err)
		}
		srtpManager.InitCipherSuite(ms.SRTPContext, keyingMaterial)
	}
}
