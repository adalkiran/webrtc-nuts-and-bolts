package dtls

import (
	"net"

	"github.com/adalkiran/webrtc-nuts-and-bolts/src/logging"
)

type HandshakeContext struct {
	//Client IP and Port
	Addr *net.UDPAddr
	//Server UDP listener connection
	Conn                    *net.UDPConn
	ClientUfrag             string
	ExpectedFingerprintHash string

	DTLSState                DTLSState
	OnDTLSStateChangeHandler func(DTLSState)

	ProtocolVersion         DtlsVersion
	CipherSuite             *CipherSuite
	CurveType               CurveType
	Curve                   Curve
	SRTPProtectionProfile   SRTPProtectionProfile
	ClientRandom            *Random
	ClientKeyExchangePublic []byte

	ServerRandom       *Random
	ServerMasterSecret []byte
	ServerPublicKey    []byte
	ServerPrivateKey   []byte
	ServerKeySignature []byte
	ClientCertificates [][]byte

	IsCipherSuiteInitialized bool
	GCM                      *GCM

	UseExtendedMasterSecret bool

	HandshakeMessagesReceived map[HandshakeType][]byte
	HandshakeMessagesSent     map[HandshakeType][]byte

	ClientEpoch                   uint16
	ClientSequenceNumber          uint16
	ServerEpoch                   uint16
	ServerSequenceNumber          uint16
	ServerHandshakeSequenceNumber uint16

	Cookie []byte
	Flight Flight

	KeyingMaterialCache []byte
}

func (c *HandshakeContext) IncreaseServerEpoch() {
	c.ServerEpoch++
	c.ServerSequenceNumber = 0
}

func (c *HandshakeContext) IncreaseServerSequence() {
	c.ServerSequenceNumber++
}

func (c *HandshakeContext) IncreaseServerHandshakeSequence() {
	c.ServerHandshakeSequenceNumber++
}

type Flight byte

const (
	Flight0 Flight = 0
	Flight2 Flight = 2
	Flight4 Flight = 4
	Flight6 Flight = 6
)

//https://github.com/pion/dtls/blob/bee42643f57a7f9c85ee3aa6a45a4fa9811ed122/state.go#L182
func (c *HandshakeContext) ExportKeyingMaterial(length int) ([]byte, error) {
	if c.KeyingMaterialCache != nil {
		return c.KeyingMaterialCache, nil
	}
	encodedClientRandom := c.ClientRandom.Encode()
	encodedServerRandom := c.ServerRandom.Encode()
	var err error
	logging.Descf(logging.ProtoDTLS, "Exporting keying material from DTLS context (<u>expected length: %d</u>)...", length)
	c.KeyingMaterialCache, err = GenerateKeyingMaterial(c.ServerMasterSecret, encodedClientRandom, encodedServerRandom, c.CipherSuite.HashAlgorithm, length)
	if err != nil {
		return nil, err
	}
	return c.KeyingMaterialCache, nil
}

func (c *HandshakeContext) SetDTLSState(dtlsState DTLSState) {
	if c.DTLSState == dtlsState {
		return
	}
	c.DTLSState = dtlsState
	if c.OnDTLSStateChangeHandler != nil {
		c.OnDTLSStateChangeHandler(dtlsState)
	}
}
