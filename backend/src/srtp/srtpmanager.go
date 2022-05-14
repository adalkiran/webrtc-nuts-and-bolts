package srtp

import (
	"net"

	"github.com/adalkiran/webrtc-nuts-and-bolts/src/logging"
)

type SRTPManager struct {
}

func NewSRTPManager() *SRTPManager {
	return &SRTPManager{}
}

func (m *SRTPManager) NewContext(addr *net.UDPAddr, conn *net.UDPConn, protectionProfile ProtectionProfile) *SRTPContext {
	result := &SRTPContext{
		Addr:              addr,
		Conn:              conn,
		ProtectionProfile: protectionProfile,
		srtpSSRCStates:    map[uint32]*srtpSSRCState{},
	}
	return result
}

func (m *SRTPManager) extractEncryptionKeys(protectionProfile ProtectionProfile, keyingMaterial []byte) (*EncryptionKeys, error) {
	// https://github.com/pion/srtp/blob/82008b58b1e7be7a0cb834270caafacc7ba53509/keying.go#L14
	keyLength, err := protectionProfile.KeyLength()
	if err != nil {
		return nil, err
	}
	saltLength, err := protectionProfile.SaltLength()
	if err != nil {
		return nil, err
	}

	offset := 0
	clientMasterKey := keyingMaterial[offset : offset+keyLength]
	offset += keyLength
	serverMasterKey := keyingMaterial[offset : offset+keyLength]
	offset += keyLength
	clientMasterSalt := keyingMaterial[offset : offset+saltLength]
	offset += saltLength
	serverMasterSalt := keyingMaterial[offset : offset+saltLength]

	result := &EncryptionKeys{
		ClientMasterKey:  clientMasterKey,
		ClientMasterSalt: clientMasterSalt,
		ServerMasterKey:  serverMasterKey,
		ServerMasterSalt: serverMasterSalt,
	}
	return result, nil
}

func (m *SRTPManager) InitCipherSuite(context *SRTPContext, keyingMaterial []byte) error {
	logging.Descf(logging.ProtoSRTP, "Initializing SRTP Cipher Suite...")
	keys, err := m.extractEncryptionKeys(context.ProtectionProfile, keyingMaterial)
	if err != nil {
		return err
	}
	logging.Descf(logging.ProtoSRTP, "Extracted encryption keys from keying material (<u>%d bytes</u>) [protection profile <u>%s</u>]\n\tClientMasterKey: <u>0x%x</u> (<u>%d bytes</u>)\n\tClientMasterSalt: <u>0x%x</u> (<u>%d bytes</u>)\n\tServerMasterKey: <u>0x%x</u> (<u>%d bytes</u>)\n\tServerMasterSalt: <u>0x%x</u> (<u>%d bytes</u>)",
		len(keyingMaterial), context.ProtectionProfile,
		keys.ClientMasterKey, len(keys.ClientMasterKey),
		keys.ClientMasterSalt, len(keys.ClientMasterSalt),
		keys.ServerMasterKey, len(keys.ServerMasterKey),
		keys.ServerMasterSalt, len(keys.ServerMasterSalt))
	logging.Descf(logging.ProtoSRTP, "Initializing GCM using ClientMasterKey and ClientMasterSalt")
	gcm, err := InitGCM(keys.ClientMasterKey, keys.ClientMasterSalt)
	if err != nil {
		return err
	}
	context.GCM = gcm
	return nil

}
