package dtls

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"net"

	"github.com/adalkiran/webrtc-nuts-and-bolts/src/common"
	"github.com/adalkiran/webrtc-nuts-and-bolts/src/logging"
)

type HandshakeManager struct {
}

func NewHandshakeManager() *HandshakeManager {
	result := &HandshakeManager{}
	return result
}

func (m *HandshakeManager) NewContext(addr *net.UDPAddr, conn *net.UDPConn, clientUfrag string, expectedFingerprintHash string) *HandshakeContext {
	result := &HandshakeContext{
		Addr:                    addr,
		Conn:                    conn,
		ClientUfrag:             clientUfrag,
		ExpectedFingerprintHash: expectedFingerprintHash,
		DTLSState:               DTLSStateNew,
		// TODO: For now, we choose one curve type hardcoded. It should be choosen by a negotiation process.
		CurveType:                 CurveTypeNamedCurve,
		HandshakeMessagesReceived: map[HandshakeType][]byte{},
		HandshakeMessagesSent:     map[HandshakeType][]byte{},
	}
	return result
}

//https://www.feistyduck.com/library/openssl-cookbook/online/ch-testing-with-openssl.html
//https://tools.ietf.org/id/draft-ietf-tls-dtls13-35.html

func (m *HandshakeManager) ProcessIncomingMessage(context *HandshakeContext, incomingMessage BaseDtlsHandshakeMessage) error {
	switch message := incomingMessage.(type) {
	case *ClientHello:
		switch context.Flight {
		case Flight0:
			context.SetDTLSState(DTLSStateConnecting)
			context.ProtocolVersion = message.Version
			context.Cookie = generateDtlsCookie()
			logging.Descf(logging.ProtoDTLS, "DTLS Cookie was generated and set to <u>0x%x</u> in handshake context (<u>%d bytes</u>).", context.Cookie, len(context.Cookie))

			context.Flight = Flight2
			logging.Descf(logging.ProtoDTLS, "Running into <u>Flight %d</u>.", context.Flight)
			logging.LineSpacer(2)
			helloVerifyRequestResponse := createDtlsHelloVerifyRequest(context)
			m.SendMessage(context, &helloVerifyRequestResponse)
			return nil
		case Flight2:
			if len(message.Cookie) == 0 {
				context.Flight = Flight0
				logging.Errorf(logging.ProtoDTLS, "Expected not empty Client Hello Cookie but <nil> found!")
				logging.Descf(logging.ProtoDTLS, "Running into <u>Flight %d</u>.", context.Flight)
				logging.LineSpacer(2)
				return nil
			}
			if !bytes.Equal(context.Cookie, message.Cookie) {
				return m.setStateFailed(context, errors.New("client hello cookie is invalid"))
			}
			negotiatedCipherSuite, err := m.negotiateOnCipherSuiteIDs(message.CipherSuiteIDs)
			if err != nil {
				return m.setStateFailed(context, err)
			}
			context.CipherSuite = negotiatedCipherSuite
			logging.Descf(logging.ProtoDTLS, "Negotiation on cipher suites: Client sent a list of cipher suites, server selected one of them (mutually supported), and assigned in handshake context: %s", negotiatedCipherSuite)
			for _, extensionItem := range message.Extensions {
				switch msgExtension := extensionItem.(type) {
				case *ExtSupportedEllipticCurves:
					negotiatedCurve, err := m.negotiateOnCurves(msgExtension.Curves)
					if err != nil {
						return m.setStateFailed(context, err)
					}
					context.Curve = negotiatedCurve
					logging.Descf(logging.ProtoDTLS, "Negotiation on curves: Client sent a list of curves, server selected one of them (mutually supported), and assigned in handshake context: <u>%s</u>", negotiatedCurve)
				case *ExtUseSRTP:
					negotiatedProtectionProfile, err := m.negotiateOnSRTPProtectionProfiles(msgExtension.ProtectionProfiles)
					if err != nil {
						return m.setStateFailed(context, err)
					}
					context.SRTPProtectionProfile = negotiatedProtectionProfile
					logging.Descf(logging.ProtoDTLS, "Negotiation on SRTP protection profiles: Client sent a list of SRTP protection profiles, server selected one of them (mutually supported), and assigned in handshake context: <u>%s</u>", negotiatedProtectionProfile)
				case *ExtUseExtendedMasterSecret:
					context.UseExtendedMasterSecret = true
					logging.Descf(logging.ProtoDTLS, "Client sent UseExtendedMasterSecret extension, client wants to use ExtendedMasterSecret. We will generate the master secret via extended way further.")
				}
			}

			context.ClientRandom = &message.Random
			logging.Descf(logging.ProtoDTLS, "Client sent Client Random, it set to <u>0x%x</u> in handshake context.", message.Random.Encode())
			context.ServerRandom = new(Random)
			context.ServerRandom.Generate()
			logging.Descf(logging.ProtoDTLS, "We generated Server Random, set to <u>0x%x</u> in handshake context.", context.ServerRandom.Encode())

			serverPublicKey, serverPrivateKey, err := GenerateCurveKeypair(context.Curve)
			if err != nil {
				return m.setStateFailed(context, err)
			}

			context.ServerPublicKey = serverPublicKey
			context.ServerPrivateKey = serverPrivateKey
			logging.Descf(logging.ProtoDTLS, "We generated Server Public and Private Key pair via <u>%s</u>, set in handshake context. Public Key: <u>0x%x</u>", context.Curve, context.ServerPublicKey)

			clientRandomBytes := context.ClientRandom.Encode()[:]
			serverRandomBytes := context.ServerRandom.Encode()[:]

			logging.Descf(logging.ProtoDTLS, "Generating ServerKeySignature. It will be sent to client via ServerKeyExchange DTLS message further.")
			context.ServerKeySignature, err = GenerateKeySignature(
				clientRandomBytes,
				serverRandomBytes,
				context.ServerPublicKey,
				context.Curve, //x25519
				ServerCertificate.PrivateKey,
				context.CipherSuite.HashAlgorithm)
			if err != nil {
				return m.setStateFailed(context, err)
			}
			logging.Descf(logging.ProtoDTLS, "ServerKeySignature was generated and set in handshake context (<u>%d bytes</u>).", len(context.ServerKeySignature))

			context.Flight = Flight4
			logging.Descf(logging.ProtoDTLS, "Running into <u>Flight %d</u>.", context.Flight)
			logging.LineSpacer(2)
			serverHelloResponse := createDtlsServerHello(context)
			m.SendMessage(context, &serverHelloResponse)
			certificateResponse := createDtlsCertificate()
			m.SendMessage(context, &certificateResponse)
			serverKeyExchangeResponse := createDtlsServerKeyExchange(context)
			m.SendMessage(context, &serverKeyExchangeResponse)
			certificateRequestResponse := createDtlsCertificateRequest(context)
			m.SendMessage(context, &certificateRequestResponse)
			serverHelloDoneResponse := createDtlsServerHelloDone(context)
			m.SendMessage(context, &serverHelloDoneResponse)
		}
	case *Certificate:
		context.ClientCertificates = message.Certificates
		logging.Descf(logging.ProtoDTLS, "Generating certificate fingerprint hash from incoming Client Certificate...")
		certificateFingerprintHash := GetCertificateFingerprintFromBytes(context.ClientCertificates[0])
		logging.Descf(logging.ProtoDTLS, "Checking fingerprint hash of client certificate incoming by this packet <u>%s</u> equals to expected fingerprint hash <u>%s</u> came from Signaling SDP", certificateFingerprintHash, context.ExpectedFingerprintHash)
		if context.ExpectedFingerprintHash != certificateFingerprintHash {
			return m.setStateFailed(context, errors.New("incompatible fingerprint hashes from SDP and DTLS data"))
		}
	case *CertificateVerify:
		logging.Descf(logging.ProtoDTLS, "Checking incoming HashAlgorithm <u>%s</u> equals to negotiated before via hello messages <u>%s</u>", message.AlgoPair.HashAlgorithm, context.CipherSuite.HashAlgorithm)
		logging.Descf(logging.ProtoDTLS, "Checking incoming SignatureAlgorithm <u>%s</u> equals to negotiated before via hello messages <u>%s</u>", message.AlgoPair.SignatureAlgorithm, context.CipherSuite.SignatureAlgorithm)
		logging.LineSpacer(2)
		if !(context.CipherSuite.HashAlgorithm == message.AlgoPair.HashAlgorithm &&
			HashAlgorithm(context.CipherSuite.SignatureAlgorithm) == HashAlgorithm(message.AlgoPair.SignatureAlgorithm)) {
			return m.setStateFailed(context, errors.New("incompatible signature scheme"))
		}
		handshakeMessages, handshakeMessageTypes, ok := m.concatHandshakeMessages(context, false, false)
		if !ok {
			return m.setStateFailed(context, errors.New("error while concatenating handshake messages"))
		}
		logging.Descf(logging.ProtoDTLS,
			common.JoinSlice("\n", false,
				common.ProcessIndent("Verifying client certificate...", "+", []string{
					fmt.Sprintf("Concatenating messages in single byte array: \n<u>%s</u>", common.JoinSlice("\n", true, handshakeMessageTypes...)),
					fmt.Sprintf("Generating hash from the byte array (<u>%d bytes</u>) via <u>%s</u>.", len(handshakeMessages), context.CipherSuite.HashAlgorithm),
					"Verifying the calculated hash, the incoming signature by CertificateVerify message and client certificate public key.",
				})))
		err := VerifyCertificate(handshakeMessages, context.CipherSuite.HashAlgorithm, message.Signature, context.ClientCertificates)
		if err != nil {
			return m.setStateFailed(context, err)
		}
	case *ClientKeyExchange:
		context.ClientKeyExchangePublic = message.PublicKey
		if !context.IsCipherSuiteInitialized {
			err := m.initCipherSuite(context)
			if err != nil {
				return m.setStateFailed(context, err)
			}
		}
	case *Finished:
		logging.Descf(logging.ProtoDTLS, "Received first encrypted message and decrypted successfully: Finished (epoch was increased to <u>%d</u>)", context.ClientEpoch)
		logging.LineSpacer(2)

		handshakeMessages, handshakeMessageTypes, ok := m.concatHandshakeMessages(context, true, true)
		if !ok {
			return m.setStateFailed(context, errors.New("error while concatenating handshake messages"))
		}
		logging.Descf(logging.ProtoDTLS,
			common.JoinSlice("\n", false,
				common.ProcessIndent("Verifying Finished message...", "+", []string{
					fmt.Sprintf("Concatenating messages in single byte array: \n<u>%s</u>", common.JoinSlice("\n", true, handshakeMessageTypes...)),
					fmt.Sprintf("Generating hash from the byte array (<u>%d bytes</u>) via <u>%s</u>, using server master secret.", len(handshakeMessages), context.CipherSuite.HashAlgorithm),
				})))
		calculatedVerifyData, err := VerifyFinishedData(handshakeMessages, context.ServerMasterSecret, context.CipherSuite.HashAlgorithm)
		if err != nil {
			return m.setStateFailed(context, err)
		}
		logging.Descf(logging.ProtoDTLS, "Calculated Finish Verify Data: <u>0x%x</u> (<u>%d bytes</u>). This data will be sent via Finished message further.", calculatedVerifyData, len(calculatedVerifyData))
		context.Flight = Flight6
		logging.Descf(logging.ProtoDTLS, "Running into <u>Flight %d</u>.", context.Flight)
		logging.LineSpacer(2)
		changeCipherSpecResponse := createDtlsChangeCipherSpec(context)
		m.SendMessage(context, &changeCipherSpecResponse)
		context.IncreaseServerEpoch()

		finishedResponse := createDtlsFinished(context, calculatedVerifyData)
		m.SendMessage(context, &finishedResponse)
		logging.Descf(logging.ProtoDTLS, "Sent first encrypted message successfully: Finished (epoch was increased to <u>%d</u>)", context.ServerEpoch)
		logging.LineSpacer(2)

		logging.Infof(logging.ProtoDTLS, "Handshake Succeeded with <u>%v:%v</u>.\n", context.Addr.IP, context.Addr.Port)
		context.SetDTLSState(DTLSStateConnected)
	default:
	}
	return nil
}

func (m *HandshakeManager) ProcessIncomingAlert(context *HandshakeContext, incomingAlert *Alert) error {
	return m.setStateFailed(context, fmt.Errorf("received alert: %s", incomingAlert))
}

func (m *HandshakeManager) SendMessage(context *HandshakeContext, message BaseDtlsMessage) {
	encodedMessageBody := message.Encode()
	encodedMessage := make([]byte, 0)
	var handshakeHeader *HandshakeHeader
	switch message.GetContentType() {
	case ContentTypeHandshake:
		handshakeMessage := message.(BaseDtlsHandshakeMessage)
		handshakeHeader = &HandshakeHeader{
			HandshakeType:   handshakeMessage.GetHandshakeType(),
			Length:          NewUint24FromUInt32((uint32(len(encodedMessageBody)))),
			MessageSequence: context.ServerHandshakeSequenceNumber,
			FragmentOffset:  NewUint24FromUInt32(0),
			FragmentLength:  NewUint24FromUInt32((uint32(len(encodedMessageBody)))),
		}
		context.IncreaseServerHandshakeSequence()
		encodedHandshakeHeader := handshakeHeader.Encode()
		encodedMessage = append(encodedMessage, encodedHandshakeHeader...)
		encodedMessage = append(encodedMessage, encodedMessageBody...)
		context.HandshakeMessagesSent[handshakeMessage.GetHandshakeType()] = encodedMessage
	case ContentTypeChangeCipherSpec:
		encodedMessage = append(encodedMessage, encodedMessageBody...)
	}

	sequenceNumber := [6]byte{}
	sequenceNumber[len(sequenceNumber)-1] += byte(context.ServerSequenceNumber)
	header := &RecordHeader{
		ContentType:    message.GetContentType(),
		Version:        DtlsVersion1_2,
		Epoch:          context.ServerEpoch,
		SequenceNumber: sequenceNumber,
		Length:         uint16(len(encodedMessage)),
	}

	if context.ServerEpoch > 0 {
		// Epoch is greater than zero, we should encrypt it.
		if context.IsCipherSuiteInitialized {
			encryptedMessage, err := context.GCM.Encrypt(header, encodedMessage)
			if err != nil {
				panic(err)
			}
			encodedMessage = encryptedMessage
			header.Length = uint16(len(encodedMessage))
		}
	}

	encodedHeader := header.Encode()
	encodedMessage = append(encodedHeader, encodedMessage...)

	logging.Infof(logging.ProtoDTLS, "Sending message (<u>Flight %d</u>)\n%s\n%s\n%s", context.Flight, header, handshakeHeader, message)
	logging.LineSpacer(2)

	context.Conn.WriteToUDP(encodedMessage, context.Addr)
	context.IncreaseServerSequence()
}

func (m *HandshakeManager) setStateFailed(context *HandshakeContext, err error) error {
	context.SetDTLSState(DTLSStateFailed)
	return err
}

func generateDtlsCookie() []byte {
	result := make([]byte, 20)
	if _, err := rand.Read(result); err != nil {
		panic(err)
	}
	return result
}

func createDtlsHelloVerifyRequest(context *HandshakeContext) HelloVerifyRequest {
	result := HelloVerifyRequest{
		// TODO: Before sending a ServerHello, we should negotiate on same protocol version which client supported and server supported protocol versions.
		// But for now, we accept the version directly came from client.
		Version: context.ProtocolVersion,
		Cookie:  context.Cookie,
	}
	return result
}

func createDtlsServerHello(context *HandshakeContext) ServerHello {
	result := ServerHello{
		// TODO: Before sending a ServerHello, we should negotiate on same protocol version which client supported and server supported protocol versions.
		// But for now, we accept the version directly came from client.
		Version:       context.ProtocolVersion,
		Random:        *context.ServerRandom,
		CipherSuiteID: context.CipherSuite.ID, //CipherSuiteID_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 0xc02b
		Extensions:    map[ExtensionType]Extension{},
	}
	if context.UseExtendedMasterSecret {
		AddExtension(result.Extensions, new(ExtUseExtendedMasterSecret))
	}
	AddExtension(result.Extensions, new(ExtRenegotiationInfo))

	if context.SRTPProtectionProfile != 0 {
		useSRTP := new(ExtUseSRTP)
		useSRTP.ProtectionProfiles = []SRTPProtectionProfile{context.SRTPProtectionProfile} // SRTPProtectionProfile_AEAD_AES_128_GCM 0x0007
		AddExtension(result.Extensions, useSRTP)
	}
	supportedPointFormats := new(ExtSupportedPointFormats)
	// TODO: For now, we choose one point format hardcoded. It should be choosen by a negotiation process.
	supportedPointFormats.PointFormats = []PointFormat{PointFormatUncompressed} // 0x00
	AddExtension(result.Extensions, supportedPointFormats)

	return result
}

func createDtlsCertificate() Certificate {
	logging.Descf(logging.ProtoDTLS, "Sending Server certificate (<u>%d bytes</u>) to the client.", len(ServerCertificate.Certificate))
	result := Certificate{
		Certificates: ServerCertificate.Certificate,
	}
	return result
}

func createDtlsServerKeyExchange(context *HandshakeContext) ServerKeyExchange {
	logging.Descf(logging.ProtoDTLS, "Sending Server key exchange data PublicKey <u>0x%x</u> and ServerKeySignature (<u>%d bytes</u>) to the client.", context.ServerPublicKey, len(context.ServerPublicKey))
	result := ServerKeyExchange{
		EllipticCurveType: context.CurveType, //CurveTypeNamedCurve 0x03
		NamedCurve:        context.Curve,     //CurveX25519 0x001d            //x25519
		PublicKey:         context.ServerPublicKey,
		AlgoPair: AlgoPair{
			HashAlgorithm:      context.CipherSuite.HashAlgorithm,      //HashAlgorithmSHA256 4
			SignatureAlgorithm: context.CipherSuite.SignatureAlgorithm, //SignatureAlgorithmECDSA 3
		},
		Signature: context.ServerKeySignature,
	}
	return result
}

func createDtlsCertificateRequest(context *HandshakeContext) CertificateRequest {
	result := CertificateRequest{
		// TODO: For now, we choose one certificate type hardcoded. It should be choosen by a negotiation process.
		CertificateTypes: []CertificateType{
			CertificateTypeECDSASign, //0x40
		},
		AlgoPairs: []AlgoPair{
			{
				HashAlgorithm:      context.CipherSuite.HashAlgorithm,      //HashAlgorithmSHA256 4
				SignatureAlgorithm: context.CipherSuite.SignatureAlgorithm, //SignatureAlgorithmECDSA 3
			},
			/*{
				HashAlgorithm:      2, //SHA1
				SignatureAlgorithm: 1, //RSA
			},*/
		},
	}

	return result
}

func createDtlsServerHelloDone(context *HandshakeContext) ServerHelloDone {
	result := ServerHelloDone{}

	return result
}

func createDtlsFinished(context *HandshakeContext, calculatedVerifyData []byte) Finished {
	result := Finished{
		VerifyData: calculatedVerifyData,
	}

	return result
}

func createDtlsChangeCipherSpec(context *HandshakeContext) ChangeCipherSpec {
	result := ChangeCipherSpec{}

	return result
}

func (m *HandshakeManager) initCipherSuite(context *HandshakeContext) error {
	preMasterSecret, err := GeneratePreMasterSecret(context.ClientKeyExchangePublic, context.ServerPrivateKey, context.Curve)
	if err != nil {
		return err
	}
	clientRandomBytes := context.ClientRandom.Encode()[:]
	serverRandomBytes := context.ServerRandom.Encode()[:]

	if context.UseExtendedMasterSecret {
		handshakeMessages, handshakeMessageTypes, ok := m.concatHandshakeMessages(context, false, false)
		if !ok {
			return errors.New("error while concatenating handshake messages")
		}
		logging.Descf(logging.ProtoDTLS,
			common.JoinSlice("\n", false,
				common.ProcessIndent("Initializing cipher suite...", "+", []string{
					fmt.Sprintf("Concatenating messages in single byte array: \n<u>%s</u>", common.JoinSlice("\n", true, handshakeMessageTypes...)),
					fmt.Sprintf("Generating hash from the byte array (<u>%d bytes</u>) via <u>%s</u>.", len(handshakeMessages), context.CipherSuite.HashAlgorithm),
				})))
		handshakeHash := context.CipherSuite.HashAlgorithm.Execute(handshakeMessages)
		logging.Descf(logging.ProtoDTLS, "Calculated Hanshake Hash: 0x%x (%d bytes). This data will be used to generate Extended Master Secret further.", handshakeHash, len(handshakeHash))
		context.ServerMasterSecret, err = GenerateExtendedMasterSecret(preMasterSecret, handshakeHash, context.CipherSuite.HashAlgorithm)
		logging.Descf(logging.ProtoDTLS, "Generated ServerMasterSecret (Extended): <u>0x%x</u> (<u>%d bytes</u>), using Pre-Master Secret and Hanshake Hash. Client Random and Server Random was not used.", context.ServerMasterSecret, len(context.ServerMasterSecret))

	} else {
		context.ServerMasterSecret, err = GenerateMasterSecret(preMasterSecret, clientRandomBytes, serverRandomBytes, context.CipherSuite.HashAlgorithm)
		logging.Descf(logging.ProtoDTLS, "Generated ServerMasterSecret (Not Extended): <u>0x%x</u> (<u>%d bytes</u>), using Pre-Master Secret, Client Random and Server Random.", context.ServerMasterSecret, len(context.ServerMasterSecret))
	}
	if err != nil {
		return err
	}
	gcm, err := InitGCM(context.ServerMasterSecret, clientRandomBytes, serverRandomBytes, *context.CipherSuite)
	if err != nil {
		return err
	}
	context.GCM = gcm
	context.IsCipherSuiteInitialized = true
	return nil

}

func (m *HandshakeManager) negotiateOnCipherSuiteIDs(clientCipherSuiteIDs []CipherSuiteID) (*CipherSuite, error) {
	for _, clientCipherSuiteID := range clientCipherSuiteIDs {
		foundCipherSuite, ok := SupportedCipherSuites[clientCipherSuiteID]
		if ok {
			return &foundCipherSuite, nil
		}
	}
	return nil, errors.New("cannot find mutually supported cipher suite between client and server")
}

func (m *HandshakeManager) negotiateOnCurves(clientCurves []Curve) (Curve, error) {
	for _, clientCurve := range clientCurves {
		_, ok := SupportedCurves[Curve(clientCurve)]
		if ok {
			return Curve(clientCurve), nil
		}
	}
	return 0, errors.New("cannot find mutually supported curve between client and server")
}

func (m *HandshakeManager) negotiateOnSRTPProtectionProfiles(protectionProfiles []SRTPProtectionProfile) (SRTPProtectionProfile, error) {
	for _, clientProtectionProfile := range protectionProfiles {
		_, ok := SupportedSRTPProtectionProfiles[SRTPProtectionProfile(clientProtectionProfile)]
		if ok {
			return SRTPProtectionProfile(clientProtectionProfile), nil
		}
	}
	return 0, errors.New("cannot find mutually supported SRTP protection profile between client and server")
}

func (m *HandshakeManager) concatHandshakeMessageTo(result []byte, resultTypes []string, messagesMap map[HandshakeType][]byte, mapType string, handshakeType HandshakeType) ([]byte, []string, bool) {
	item, ok := messagesMap[handshakeType]
	if !ok {
		return result, resultTypes, false
	}
	result = append(result, item...)
	resultTypes = append(resultTypes, fmt.Sprintf("%s (%s)", handshakeType, mapType))
	return result, resultTypes, true
}

func (m *HandshakeManager) concatHandshakeMessages(context *HandshakeContext, includeReceivedCertificateVerify bool, includeReceivedFinished bool) ([]byte, []string, bool) {
	result := make([]byte, 0)
	resultTypes := make([]string, 0)
	var ok bool
	result, resultTypes, ok = m.concatHandshakeMessageTo(result, resultTypes, context.HandshakeMessagesReceived, "recv", HandshakeTypeClientHello)
	if !ok {
		return nil, nil, false
	}
	result, resultTypes, ok = m.concatHandshakeMessageTo(result, resultTypes, context.HandshakeMessagesSent, "sent", HandshakeTypeServerHello)
	if !ok {
		return nil, nil, false
	}
	result, resultTypes, ok = m.concatHandshakeMessageTo(result, resultTypes, context.HandshakeMessagesSent, "sent", HandshakeTypeCertificate)
	if !ok {
		return nil, nil, false
	}
	result, resultTypes, ok = m.concatHandshakeMessageTo(result, resultTypes, context.HandshakeMessagesSent, "sent", HandshakeTypeServerKeyExchange)
	if !ok {
		return nil, nil, false
	}
	result, resultTypes, ok = m.concatHandshakeMessageTo(result, resultTypes, context.HandshakeMessagesSent, "sent", HandshakeTypeCertificateRequest)
	if !ok {
		return nil, nil, false
	}
	result, resultTypes, ok = m.concatHandshakeMessageTo(result, resultTypes, context.HandshakeMessagesSent, "sent", HandshakeTypeServerHelloDone)
	if !ok {
		return nil, nil, false
	}
	result, resultTypes, ok = m.concatHandshakeMessageTo(result, resultTypes, context.HandshakeMessagesReceived, "recv", HandshakeTypeCertificate)
	if !ok {
		return nil, nil, false
	}
	result, resultTypes, ok = m.concatHandshakeMessageTo(result, resultTypes, context.HandshakeMessagesReceived, "recv", HandshakeTypeClientKeyExchange)
	if !ok {
		return nil, nil, false
	}
	if includeReceivedCertificateVerify {
		result, resultTypes, ok = m.concatHandshakeMessageTo(result, resultTypes, context.HandshakeMessagesReceived, "recv", HandshakeTypeCertificateVerify)
		if !ok {
			return nil, nil, false
		}
	}
	if includeReceivedFinished {
		result, resultTypes, ok = m.concatHandshakeMessageTo(result, resultTypes, context.HandshakeMessagesReceived, "recv", HandshakeTypeFinished)
		if !ok {
			return nil, nil, false
		}
	}

	return result, resultTypes, true
}
