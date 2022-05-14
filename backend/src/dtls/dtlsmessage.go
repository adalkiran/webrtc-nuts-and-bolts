package dtls

import (
	"encoding/binary"
	"errors"

	"github.com/adalkiran/webrtc-nuts-and-bolts/src/logging"
)

type uint24 [3]byte

func (b *uint24) ToUint32() uint32 {
	// https://stackoverflow.com/questions/45000982/convert-3-bytes-to-int-in-go
	return uint32(b[2]) | uint32(b[1])<<8 | uint32(b[0])<<16
}

func NewUint24FromUInt32(i uint32) uint24 {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(i))
	result := new(uint24)
	copy(result[:], buf[1:4])
	return *result
}

func NewUint24FromBytes(buf []byte) uint24 {
	result := new(uint24)
	copy(result[:], buf[0:3])
	return *result
}

type BaseDtlsMessage interface {
	GetContentType() ContentType
	Encode() []byte
	Decode(buf []byte, offset int, arrayLen int) (int, error)
	String() string
}

type BaseDtlsHandshakeMessage interface {
	GetContentType() ContentType
	GetHandshakeType() HandshakeType
	Encode() []byte
	Decode(buf []byte, offset int, arrayLen int) (int, error)
}

var (
	errIncompleteDtlsMessage    = errors.New("data contains incomplete DTLS message")
	errUnknownDtlsContentType   = errors.New("data contains unkown DTLS content type")
	errUnknownDtlsHandshakeType = errors.New("data contains unkown DTLS handshake type")
)

func IsDtlsPacket(buf []byte, offset int, arrayLen int) bool {
	return arrayLen > 0 && buf[offset] >= 20 && buf[offset] <= 63
}

func DecodeDtlsMessage(context *HandshakeContext, buf []byte, offset int, arrayLen int) (*RecordHeader, *HandshakeHeader, BaseDtlsMessage, int, error) {
	if arrayLen < 1 {
		return nil, nil, nil, offset, errIncompleteDtlsMessage
	}
	header, offset, err := DecodeRecordHeader(buf, offset, arrayLen)
	if err != nil {
		return nil, nil, nil, offset, err
	}

	if header.Epoch < context.ClientEpoch {
		// Ignore incoming message
		offset += int(header.Length)
		return nil, nil, nil, offset, nil
	}

	context.ClientEpoch = header.Epoch

	var decryptedBytes []byte
	var encryptedBytes []byte
	if header.Epoch > 0 {
		// Data arrives encrypted, we should decrypt it before.
		if context.IsCipherSuiteInitialized {
			encryptedBytes = buf[offset : offset+int(header.Length)]
			offset += int(header.Length)
			decryptedBytes, err = context.GCM.Decrypt(header, encryptedBytes)
			if err != nil {
				return nil, nil, nil, offset, err
			}
		}
	}

	switch header.ContentType {
	case ContentTypeHandshake:
		if decryptedBytes == nil {
			offsetBackup := offset
			handshakeHeader, offset, err := DecodeHandshakeHeader(buf, offset, arrayLen)
			if err != nil {
				return nil, nil, nil, offset, err
			}
			if handshakeHeader.Length.ToUint32() != handshakeHeader.FragmentLength.ToUint32() {
				// Ignore fragmented packets
				logging.Warningf(logging.ProtoDTLS, "Ignore fragmented packets: <u>%s</u>", header.ContentType)
				return nil, nil, nil, offset + int(handshakeHeader.FragmentLength.ToUint32()), nil
			}
			result, offset, err := decodeHandshake(header, handshakeHeader, buf, offset, arrayLen)
			if err != nil {
				return nil, nil, nil, offset, err
			}
			copyArray := make([]byte, offset-offsetBackup)
			copy(copyArray, buf[offsetBackup:offset])
			context.HandshakeMessagesReceived[handshakeHeader.HandshakeType] = copyArray

			return header, handshakeHeader, result, offset, err
		} else {
			handshakeHeader, decryptedOffset, err := DecodeHandshakeHeader(decryptedBytes, 0, len(decryptedBytes))
			if err != nil {
				return nil, nil, nil, offset, err
			}

			result, _, err := decodeHandshake(header, handshakeHeader, decryptedBytes, decryptedOffset, len(decryptedBytes)-decryptedOffset)

			copyArray := make([]byte, len(decryptedBytes))
			copy(copyArray, decryptedBytes)
			context.HandshakeMessagesReceived[handshakeHeader.HandshakeType] = copyArray

			return header, handshakeHeader, result, offset, err
		}
	case ContentTypeChangeCipherSpec:
		changeCipherSpec := &ChangeCipherSpec{}
		offset, err := changeCipherSpec.Decode(buf, offset, arrayLen)
		if err != nil {
			return nil, nil, nil, offset, err
		}
		return header, nil, changeCipherSpec, offset, nil
	case ContentTypeAlert:
		alert := &Alert{}
		if decryptedBytes == nil {
			offset, err = alert.Decode(buf, offset, arrayLen)
		} else {
			_, err = alert.Decode(decryptedBytes, 0, len(decryptedBytes))
		}
		if err != nil {
			return nil, nil, nil, offset, err
		}
		return header, nil, alert, offset, nil

	default:
		return nil, nil, nil, offset, errUnknownDtlsContentType
	}
}

func decodeHandshake(header *RecordHeader, handshakeHeader *HandshakeHeader, buf []byte, offset int, arrayLen int) (BaseDtlsMessage, int, error) {
	var result BaseDtlsMessage
	switch handshakeHeader.HandshakeType {
	case HandshakeTypeClientHello:
		result = new(ClientHello)
	case HandshakeTypeServerHello:
		result = new(ServerHello)
	case HandshakeTypeCertificate:
		result = new(Certificate)
	case HandshakeTypeServerKeyExchange:
		result = new(ServerKeyExchange)
	case HandshakeTypeCertificateRequest:
		result = new(CertificateRequest)
	case HandshakeTypeServerHelloDone:
		result = new(ServerHelloDone)
	case HandshakeTypeClientKeyExchange:
		result = new(ClientKeyExchange)
	case HandshakeTypeCertificateVerify:
		result = new(CertificateVerify)
	case HandshakeTypeFinished:
		result = new(Finished)
	default:
		return nil, offset, errUnknownDtlsHandshakeType
	}
	offset, err := result.Decode(buf, offset, arrayLen)
	return result, offset, err

}
