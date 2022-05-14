package srtp

import "fmt"

type ProtectionProfile uint16

const (
	ProtectionProfile_AEAD_AES_128_GCM ProtectionProfile = ProtectionProfile(0x0007)
)

type EncryptionKeys struct {
	ServerMasterKey  []byte
	ServerMasterSalt []byte
	ClientMasterKey  []byte
	ClientMasterSalt []byte
}

func (p ProtectionProfile) String() string {
	var result string
	switch p {
	case ProtectionProfile_AEAD_AES_128_GCM:
		result = "SRTP_AEAD_AES_128_GCM"
	default:
		result = "Unknown SRTP Protection Profile"
	}
	return fmt.Sprintf("%s (0x%04x)", result, uint16(p))
}

func (p ProtectionProfile) KeyLength() (int, error) {
	switch p {
	case ProtectionProfile_AEAD_AES_128_GCM:
		return 16, nil
	}
	return 0, fmt.Errorf("unknown protection profile: %d", p)
}

func (p ProtectionProfile) SaltLength() (int, error) {
	switch p {
	case ProtectionProfile_AEAD_AES_128_GCM:
		return 12, nil
	}
	return 0, fmt.Errorf("unknown protection profile: %d", p)
}

func (p ProtectionProfile) AeadAuthTagLength() (int, error) {
	switch p {
	case ProtectionProfile_AEAD_AES_128_GCM:
		return 16, nil
	}
	return 0, fmt.Errorf("unknown protection profile: %d", p)
}

func InitGCM(masterKey, masterSalt []byte) (*GCM, error) {
	gcm, err := NewGCM(masterKey, masterSalt)
	if err != nil {
		return nil, err
	}
	return gcm, nil
}
