package dtls

import (
	"crypto"
	"crypto/sha256"
	"fmt"
	"hash"
)

// See for complete overview: https://www.iana.org/assignments/tls-parameters/tls-parameters.xml

// Only TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 was implemented.
// See for further Cipher Suite types: https://www.rfc-editor.org/rfc/rfc8422.html#section-6
type CipherSuiteID uint16

// Only NamedCurve was implemented.
// See for further CurveType types: https://www.rfc-editor.org/rfc/rfc8422.html#section-5.4
type CurveType byte

// Only X25519 was implemented.
// See for further NamedCurve types: https://www.rfc-editor.org/rfc/rfc8422.html#section-5.1.1
type Curve uint16

// Only Uncompressed was implemented.
// See for further Elliptic Curve Point Format types: https://www.rfc-editor.org/rfc/rfc8422.html#section-5.1.2
type PointFormat byte

// Only SHA256 was implemented.
// See for further Hash Algorithm types (in "HashAlgorithm" enum):  https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.1.4.1
type HashAlgorithm byte

// Only ECDSA was implemented.
// See for further Signature Algorithm types: (in "signed_params" bullet, SignatureAlgorithm enum) https://www.rfc-editor.org/rfc/rfc8422.html#section-5.4
// See also (in "SignatureAlgorithm" enum): https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.1.4.1
type SignatureAlgorithm byte

// Only ECDSA Sign was implemented.
// See for further ClientCertificateType types (in "ClientCertificateType" enum):  https://www.rfc-editor.org/rfc/rfc8422.html#section-5.5
// See also https://tools.ietf.org/html/rfc5246#section-7.4.4
type CertificateType byte

type KeyExchangeAlgorithm byte

// Only SRTP_AEAD_AES_128_GCM was implemented.
// See for further SRTP Protection Profile types: https://www.iana.org/assignments/srtp-protection/srtp-protection.xhtml
type SRTPProtectionProfile uint16

type CipherSuite struct {
	ID                   CipherSuiteID
	KeyExchangeAlgorithm KeyExchangeAlgorithm
	CertificateType      CertificateType
	HashAlgorithm        HashAlgorithm
	SignatureAlgorithm   SignatureAlgorithm
}

const (
	// Only TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 was implemented.
	// See for further Cipher Suite types: https://www.rfc-editor.org/rfc/rfc8422.html#section-6
	CipherSuiteID_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 CipherSuiteID = CipherSuiteID(0xc02b)

	// Only NamedCurve was implemented.
	// See for further CurveType types: https://www.rfc-editor.org/rfc/rfc8422.html#section-5.4
	CurveTypeNamedCurve CurveType = CurveType(0x03)

	// Only X25519 was implemented.
	// See for further NamedCurve types: https://www.rfc-editor.org/rfc/rfc8422.html#section-5.1.1
	CurveX25519 Curve = Curve(0x001d)

	// Only Uncompressed was implemented.
	// See for further Elliptic Curve Point Format types: https://www.rfc-editor.org/rfc/rfc8422.html#section-5.1.2
	PointFormatUncompressed PointFormat = PointFormat(0)

	// Only SHA256 was implemented.
	// See for further Hash Algorithm types (in "HashAlgorithm" enum):  https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.1.4.1
	HashAlgorithmSHA256 HashAlgorithm = HashAlgorithm(4)

	// Only ECDSA was implemented.
	// See for further Signature Algorithm types: (in "signed_params" bullet, SignatureAlgorithm enum) https://www.rfc-editor.org/rfc/rfc8422.html#section-5.4
	// See also (in "SignatureAlgorithm" enum): https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.1.4.1
	SignatureAlgorithmECDSA SignatureAlgorithm = SignatureAlgorithm(3)

	// Only ECDSA Sign was implemented.
	// See for further ClientCertificateType types (in "ClientCertificateType" enum):  https://www.rfc-editor.org/rfc/rfc8422.html#section-5.5
	// See also https://tools.ietf.org/html/rfc5246#section-7.4.4
	CertificateTypeECDSASign CertificateType = CertificateType(64)

	KeyExchangeAlgorithmNone  KeyExchangeAlgorithm = KeyExchangeAlgorithm(0) //Value is not important
	KeyExchangeAlgorithmECDHE KeyExchangeAlgorithm = KeyExchangeAlgorithm(1) //Value is not important

	// Only SRTP_AEAD_AES_128_GCM was implemented.
	// See for further SRTP Protection Profile types: https://www.iana.org/assignments/srtp-protection/srtp-protection.xhtml
	SRTPProtectionProfile_AEAD_AES_128_GCM SRTPProtectionProfile = SRTPProtectionProfile(0x0007)
)

var (
	SupportedCurves = map[Curve]bool{
		CurveX25519: true,
	}

	SupportedSRTPProtectionProfiles = map[SRTPProtectionProfile]bool{
		SRTPProtectionProfile_AEAD_AES_128_GCM: true,
	}

	SupportedCipherSuites = map[CipherSuiteID]CipherSuite{
		CipherSuiteID_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: {
			ID:                   CipherSuiteID_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			KeyExchangeAlgorithm: KeyExchangeAlgorithmECDHE,
			CertificateType:      CertificateTypeECDSASign,
			HashAlgorithm:        HashAlgorithmSHA256,
			SignatureAlgorithm:   SignatureAlgorithmECDSA,
		},
	}
)

func (cs CipherSuiteID) String() string {
	var result string
	switch cs {
	case CipherSuiteID_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		result = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	default:
		result = "Unknown Cipher Suite"
	}
	return fmt.Sprintf("%s (0x%x)", result, uint16(cs))
}

func (ct CurveType) String() string {
	var result string
	switch ct {
	case CurveTypeNamedCurve:
		result = "NamedCurve"
	default:
		result = "Unknown Curve Type"
	}
	return fmt.Sprintf("%s (0x%02x)", result, byte(ct))
}

func (c Curve) String() string {
	var result string
	switch c {
	case CurveX25519:
		result = "X25519"
	default:
		result = "Unknown Curve"
	}
	return fmt.Sprintf("%s (0x%04x)", result, uint16(c))
}

func (pf PointFormat) String() string {
	var result string
	switch pf {
	case PointFormatUncompressed:
		result = "Uncompressed"
	default:
		result = "Unknown Point Format"
	}
	return fmt.Sprintf("%s (0x%02x)", result, byte(pf))
}

func (alg HashAlgorithm) String() string {
	var result string
	switch alg {
	case HashAlgorithmSHA256:
		result = "SHA256"
	default:
		result = "Unknown Hash Algoritm"
	}
	return fmt.Sprintf("%s (0x%02x)", result, byte(alg))
}

func (alg HashAlgorithm) Execute(input []byte) []byte {
	switch alg {
	case HashAlgorithmSHA256:
		digest := sha256.Sum256(input)
		return digest[:]
	}
	return nil
}

func (alg HashAlgorithm) CryptoHashType() crypto.Hash {
	switch alg {
	case HashAlgorithmSHA256:
		return crypto.SHA256
	}
	return 0
}

func (alg HashAlgorithm) GetFunction() func() hash.Hash {
	switch alg {
	case HashAlgorithmSHA256:
		return sha256.New
	}
	return nil
}
func (alg SignatureAlgorithm) String() string {
	var result string
	switch alg {
	case SignatureAlgorithmECDSA:
		result = "ECDSA"
	default:
		result = "Unknown Signature Algoritm"
	}
	return fmt.Sprintf("%s (0x%02x)", result, byte(alg))
}

func (ct CertificateType) String() string {
	var result string
	switch ct {
	case CertificateTypeECDSASign:
		result = "ECDSASign"
	default:
		result = "Unknown Certificate Type"
	}
	return fmt.Sprintf("%s (0x%02x)", result, byte(ct))
}

func (alg KeyExchangeAlgorithm) String() string {
	var result string
	switch alg {
	case KeyExchangeAlgorithmNone:
		result = "None"
	case KeyExchangeAlgorithmECDHE:
		result = "ECDHE"
	default:
		result = fmt.Sprintf("Unknown Key Exchange Algorithm (%02x)", byte(alg))
	}
	return result
}

func (p SRTPProtectionProfile) String() string {
	var result string
	switch p {
	case SRTPProtectionProfile_AEAD_AES_128_GCM:
		result = "SRTP_AEAD_AES_128_GCM"
	default:
		result = "Unknown SRTP Protection Profile"
	}
	return fmt.Sprintf("%s (0x%04x)", result, uint16(p))
}

func (cs CipherSuite) String() string {
	return fmt.Sprintf("ID: <u>%s</u>, KeyExchangeAlgorithm: <u>%s</u>, CertificateType: <u>%s</u>, HashAlgorithm: <u>%s</u>, SignatureAlgorithm: <u>%s</u>", cs.ID, cs.KeyExchangeAlgorithm, cs.CertificateType, cs.HashAlgorithm, cs.SignatureAlgorithm)
}
