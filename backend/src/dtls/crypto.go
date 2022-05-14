package dtls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/adalkiran/webrtc-nuts-and-bolts/src/common"
	"github.com/adalkiran/webrtc-nuts-and-bolts/src/logging"
	"golang.org/x/crypto/curve25519"
)

type ecdsaSignature struct {
	R, S *big.Int
}

// See: https://github.com/pion/dtls/blob/bee42643f57a7f9c85ee3aa6a45a4fa9811ed122/pkg/crypto/selfsign/selfsign.go#L22
// See: https://gist.github.com/samuel/8b500ddd3f6118d052b5e6bc16bc4c09

func generateServerCertificatePrivateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func GenerateServerCertificate(cn string) (*tls.Certificate, error) {
	serverCertificatePrivateKey, err := generateServerCertificatePrivateKey()
	if err != nil {
		return nil, err
	}
	logging.Descf(logging.ProtoCRYPTO, "Server certificate generated using Elliptic secp256r1 curve <u>%s</u>", serverCertificatePrivateKey.Params().Name)
	maxBigInt := new(big.Int) // Max random value, a 130-bits integer, i.e 2^130 - 1
	maxBigInt.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(maxBigInt, big.NewInt(1))
	serialNumber, _ := rand.Int(rand.Reader, maxBigInt)

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
		//DNSNames:              []string{cn},
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
}

func GenerateCurveKeypair(curve Curve) ([]byte, []byte, error) {
	switch curve {
	case CurveX25519:
		// TODO: For now, it generates only using X25519
		// https://github.com/pion/dtls/blob/bee42643f57a7f9c85ee3aa6a45a4fa9811ed122/pkg/crypto/elliptic/elliptic.go#L70
		tmp := make([]byte, 32)
		if _, err := rand.Read(tmp); err != nil {
			return nil, nil, err
		}

		var public, private [32]byte
		copy(private[:], tmp)

		curve25519.ScalarBaseMult(&public, &private)
		return public[:], private[:], nil
	}
	return nil, nil, errors.New("not supported curve")
}

func generateValueKeyMessage(clientRandom []byte, serverRandom []byte, publicKey []byte, curve Curve) []byte {
	//See signed_params enum: https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.3

	logging.Descf(logging.ProtoCRYPTO,
		common.JoinSlice("\n", false,
			common.ProcessIndent("Generating plaintext of signed_params values consist of:", "+", []string{
				fmt.Sprintf("Client Random <u>0x%x</u> (<u>%d bytes</u>)", clientRandom, len(clientRandom)),
				fmt.Sprintf("Server Random <u>0x%x</u> (<u>%d bytes</u>)", serverRandom, len(serverRandom)),
				common.ProcessIndent("ECDH Params:", "", []string{
					fmt.Sprintf("[0]: <u>%s</u>\n[1:2]: <u>%s</u>\n[3]: <u>%d</u> (public key length)", CurveTypeNamedCurve, curve, len(publicKey)),
				}),
				fmt.Sprintf("Public Key: <u>0x%x</u>", publicKey),
			})))
	serverECDHParams := make([]byte, 4)
	serverECDHParams[0] = byte(CurveTypeNamedCurve)
	binary.BigEndian.PutUint16(serverECDHParams[1:], uint16(curve))
	serverECDHParams[3] = byte(len(publicKey))

	plaintext := []byte{}
	plaintext = append(plaintext, clientRandom...)
	plaintext = append(plaintext, serverRandom...)
	plaintext = append(plaintext, serverECDHParams...)
	plaintext = append(plaintext, publicKey...)
	logging.Descf(logging.ProtoCRYPTO, "Generated plaintext of signed_params values: <u>0x%x</u> (<u>%d</u> bytes)", plaintext, len(plaintext))
	return plaintext
}

func GenerateKeySignature(clientRandom []byte, serverRandom []byte, publicKey []byte, curve Curve, privateKey crypto.PrivateKey, hashAlgorithm HashAlgorithm) ([]byte, error) {
	msg := generateValueKeyMessage(clientRandom, serverRandom, publicKey, curve)
	switch privateKeyObj := privateKey.(type) {
	case *ecdsa.PrivateKey:
		hashed := hashAlgorithm.Execute(msg) //SHA256 sum
		logging.Descf(logging.ProtoCRYPTO, "signed_params values hashed: <u>0x%x</u> (<u>%d</u> bytes)", hashed, len(hashed))
		signed, err := privateKeyObj.Sign(rand.Reader, hashed, hashAlgorithm.CryptoHashType()) //crypto.SHA256
		logging.Descf(logging.ProtoCRYPTO, "signed_params values signed (result will be called as ServerKeySignature): <u>0x%x</u> (<u>%d</u> bytes)", signed, len(signed))
		return signed, err
	}
	return nil, errors.New("not supported private key type")
}

func GetCertificateFingerprint(certificate *tls.Certificate) string {
	return GetCertificateFingerprintFromBytes(certificate.Certificate[0])
}
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

type EncryptionKeys struct {
	MasterSecret   []byte
	ClientWriteKey []byte
	ServerWriteKey []byte
	ClientWriteIV  []byte
	ServerWriteIV  []byte
}

func GeneratePreMasterSecret(publicKey []byte, privateKey []byte, curve Curve) ([]byte, error) {
	// TODO: For now, it generates only using X25519
	// https://github.com/pion/dtls/blob/bee42643f57a7f9c85ee3aa6a45a4fa9811ed122/pkg/crypto/prf/prf.go#L106
	switch curve {
	case CurveX25519:
		result, err := curve25519.X25519(privateKey, publicKey)
		if err != nil {
			return nil, err
		}
		logging.Descf(logging.ProtoCRYPTO, "Generated Pre-Master Secret using ClientKeyExchangePublic key and ServerPrivateKey via <u>%s</u>", curve)
		return result, nil
	}
	return nil, errors.New("not supported curve type")
}

func GenerateMasterSecret(preMasterSecret []byte, clientRandom []byte, serverRandom []byte, hashAlgorithm HashAlgorithm) ([]byte, error) {
	seed := append(append([]byte("master secret"), clientRandom...), serverRandom...)
	result, err := PHash(preMasterSecret, seed, 48, hashAlgorithm)
	if err != nil {
		return nil, err
	}
	logging.Descf(logging.ProtoCRYPTO, "Generated MasterSecret (not Extended) using Pre-Master Secret, Client Random and Server Random via <u>%s</u>: <u>0x%x</u> (<u>%d bytes</u>)", hashAlgorithm, result, len(result))
	return result, nil
}
func GenerateExtendedMasterSecret(preMasterSecret []byte, handshakeHash []byte, hashAlgorithm HashAlgorithm) ([]byte, error) {
	seed := append([]byte("extended master secret"), handshakeHash...)
	result, err := PHash(preMasterSecret, seed, 48, hashAlgorithm)
	if err != nil {
		return nil, err
	}
	logging.Descf(logging.ProtoCRYPTO, "Generated Extended MasterSecret using Pre-Master Secret, Handshake Hash via <u>%s</u>: <u>0x%x</u> (<u>%d bytes</u>)", hashAlgorithm, result, len(result))
	return result, nil
}
func GenerateKeyingMaterial(masterSecret []byte, clientRandom []byte, serverRandom []byte, hashAlgorithm HashAlgorithm, length int) ([]byte, error) {
	seed := append(append([]byte("EXTRACTOR-dtls_srtp"), clientRandom...), serverRandom...)
	result, err := PHash(masterSecret, seed, length, hashAlgorithm)
	if err != nil {
		return nil, err
	}
	logging.Descf(logging.ProtoCRYPTO, "Generated Keying Material using Master Secret, Client Random and Server Random via <u>%s</u>: <u>0x%x</u> (<u>%d bytes</u>)", hashAlgorithm, result, len(result))
	return result, nil
}

// See for further: https://github.com/pion/dtls/blob/a6397ff7282bc56dc37a68ea9211702edb4de1de/pkg/crypto/prf/prf.go#L155
func PHash(secret, seed []byte, requestedLength int, hashAlgorithm HashAlgorithm) ([]byte, error) {
	hashFunc := hashAlgorithm.GetFunction()

	hmacSHA256 := func(key, data []byte) ([]byte, error) {
		mac := hmac.New(hashFunc, key)
		if _, err := mac.Write(data); err != nil {
			return nil, err
		}
		return mac.Sum(nil), nil
	}

	var err error
	lastRound := seed
	out := []byte{}

	iterations := int(math.Ceil(float64(requestedLength) / float64(hashFunc().Size())))
	for i := 0; i < iterations; i++ {
		lastRound, err = hmacSHA256(secret, lastRound)
		if err != nil {
			return nil, err
		}
		withSecret, err := hmacSHA256(secret, append(lastRound, seed...))
		if err != nil {
			return nil, err
		}
		out = append(out, withSecret...)
	}

	return out[:requestedLength], nil
}

func GenerateEncryptionKeys(masterSecret []byte, clientRandom []byte, serverRandom []byte, keyLen int, ivLen int, hashAlgorithm HashAlgorithm) (*EncryptionKeys, error) {
	//https://github.com/pion/dtls/blob/bee42643f57a7f9c85ee3aa6a45a4fa9811ed122/pkg/crypto/prf/prf.go#L199
	logging.Descf(logging.ProtoCRYPTO, "Generating encryption keys with Key Length: <u>%d</u>, IV Length: <u>%d</u> via <u>%s</u>, using Master Secret, Server Random, Client Random...", keyLen, ivLen, hashAlgorithm)
	seed := append(append([]byte("key expansion"), serverRandom...), clientRandom...)
	keyMaterial, err := PHash(masterSecret, seed, (2*keyLen)+(2*ivLen), hashAlgorithm)
	if err != nil {
		return nil, err
	}

	clientWriteKey := keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]

	serverWriteKey := keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]

	clientWriteIV := keyMaterial[:ivLen]
	keyMaterial = keyMaterial[ivLen:]

	serverWriteIV := keyMaterial[:ivLen]

	return &EncryptionKeys{
		MasterSecret:   masterSecret,
		ClientWriteKey: clientWriteKey,
		ServerWriteKey: serverWriteKey,
		ClientWriteIV:  clientWriteIV,
		ServerWriteIV:  serverWriteIV,
	}, nil
}

func InitGCM(masterSecret, clientRandom, serverRandom []byte, cipherSuite CipherSuite) (*GCM, error) {
	//https://github.com/pion/dtls/blob/bee42643f57a7f9c85ee3aa6a45a4fa9811ed122/internal/ciphersuite/tls_ecdhe_ecdsa_with_aes_128_gcm_sha256.go#L60
	const (
		prfKeyLen = 16
		prfIvLen  = 4
	)
	logging.Descf(logging.ProtoCRYPTO, "Initializing GCM with Key Length: <u>%d</u>, IV Length: <u>%d</u>, these values are constants of <u>%s</u> cipher suite.",
		prfKeyLen, prfIvLen, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")

	keys, err := GenerateEncryptionKeys(masterSecret, clientRandom, serverRandom, prfKeyLen, prfIvLen, cipherSuite.HashAlgorithm)
	if err != nil {
		return nil, err
	}

	logging.Descf(logging.ProtoCRYPTO, "Generated encryption keys from keying material (Key Length: <u>%d</u>, IV Length: <u>%d</u>) (<u>%d bytes</u>)\n\tMasterSecret: <u>0x%x</u> (<u>%d bytes</u>)\n\tClientWriteKey: <u>0x%x</u> (<u>%d bytes</u>)\n\tServerWriteKey: <u>0x%x</u> (<u>%d bytes</u>)\n\tClientWriteIV: <u>0x%x</u> (<u>%d bytes</u>)\n\tServerWriteIV: <u>0x%x</u> (<u>%d bytes</u>)",
		prfKeyLen, prfIvLen, prfKeyLen*2+prfIvLen*2,
		keys.MasterSecret, len(keys.MasterSecret),
		keys.ClientWriteKey, len(keys.ClientWriteKey),
		keys.ServerWriteKey, len(keys.ServerWriteKey),
		keys.ClientWriteIV, len(keys.ClientWriteIV),
		keys.ServerWriteIV, len(keys.ServerWriteIV))

	gcm, err := NewGCM(keys.ServerWriteKey, keys.ServerWriteIV, keys.ClientWriteKey, keys.ClientWriteIV)
	if err != nil {
		return nil, err
	}
	return gcm, nil
}

func generateAEADAdditionalData(h *RecordHeader, payloadLen int) []byte {
	//https://github.com/pion/dtls/blob/b3e235f54b60ccc31aa10193807b5e8e394f17ff/pkg/crypto/ciphersuite/ciphersuite.go#L18
	/*
		var additionalData [13]byte
		binary.BigEndian.PutUint16(additionalData[0:], h.Epoch)
		copy(additionalData[2:], h.SequenceNumber[:])
		additionalData[8] = byte(h.ContentType)
		binary.BigEndian.PutUint16(additionalData[9:], uint16(h.Version))
		binary.BigEndian.PutUint16(additionalData[len(additionalData)-2:], uint16(payloadLen))

		return additionalData[:]
	*/

	/*
		var additionalData [13]byte
		binary.BigEndian.PutUint16(additionalData[0:], h.Epoch)
		copy(additionalData[2:], h.SequenceNumber[:])
		additionalData[8] = byte(h.ContentType)
		binary.BigEndian.PutUint16(additionalData[9:], uint16(h.Version))

		binary.BigEndian.PutUint16(additionalData[len(additionalData)-2:], uint16(payloadLen))

	*/

	var additionalData [13]byte
	// SequenceNumber MUST be set first
	// we only want uint48, clobbering an extra 2 (using uint64, Golang doesn't have uint48)
	binary.BigEndian.PutUint16(additionalData[:], h.Epoch)
	copy(additionalData[2:], h.SequenceNumber[:])
	additionalData[8] = byte(h.ContentType)
	binary.BigEndian.PutUint16(additionalData[9:], uint16(h.Version))
	binary.BigEndian.PutUint16(additionalData[len(additionalData)-2:], uint16(payloadLen))

	return additionalData[:]
}

func VerifyCertificate(handshakeMessages []byte, hashAlgorithm HashAlgorithm, clientSignature []byte, clientCertificates [][]byte) error {
	//https://github.com/pion/dtls/blob/b3e235f54b60ccc31aa10193807b5e8e394f17ff/crypto.go#L130
	if len(clientCertificates) == 0 {
		return errors.New("client has not sent any certificate")
	}
	clientCertificate, err := x509.ParseCertificate(clientCertificates[0])
	if err != nil {
		return err
	}
	switch clientCertificatePublicKey := clientCertificate.PublicKey.(type) {
	case *ecdsa.PublicKey:
		var ecdsaSign ecdsaSignature
		_, err := asn1.Unmarshal(clientSignature, &ecdsaSign)
		if err != nil {
			return err
		}
		if ecdsaSign.R.Sign() <= 0 || ecdsaSign.S.Sign() <= 0 {
			return errors.New("invalid ECDSA signature")
		}
		hash := hashAlgorithm.Execute(handshakeMessages)
		if !ecdsa.Verify(clientCertificatePublicKey, hash, ecdsaSign.R, ecdsaSign.S) {
			return errors.New("key-signature mismatch")
		}
		return nil
	default:
		return errors.New("unsupported certificate type")
	}
}

func VerifyFinishedData(handshakeMessages []byte, serverMasterSecret []byte, hashAlgorithm HashAlgorithm) ([]byte, error) {
	hashFunc := hashAlgorithm.GetFunction()()
	_, err := hashFunc.Write(handshakeMessages)
	if err != nil {
		return nil, err
	}
	seed := append([]byte("server finished"), hashFunc.Sum(nil)...)
	return PHash(serverMasterSecret, seed, 12, hashAlgorithm)
}
