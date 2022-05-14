package dtls

import "fmt"

type AlertLevel byte

const (
	AlertLevelWarning AlertLevel = 1
	AlertLevelFatal   AlertLevel = 2
)

func (al *AlertLevel) String() string {
	var result string
	switch *al {
	case AlertLevelWarning:
		result = "Warning"
	case AlertLevelFatal:
		result = "Fatal"
	default:
		result = "Unknown Alert Type"
	}
	return fmt.Sprintf("%s (%v)", result, *al)
}

type AlertDescription byte

const (
	AlertDescriptionCloseNotify            AlertDescription = 0
	AlertDescriptionUnexpectedMessage      AlertDescription = 10
	AlertDescriptionBadRecordMac           AlertDescription = 20
	AlertDescriptionDecryptionFailed       AlertDescription = 21
	AlertDescriptionRecordOverflow         AlertDescription = 22
	AlertDescriptionDecompressionFailure   AlertDescription = 30
	AlertDescriptionHandshakeFailure       AlertDescription = 40
	AlertDescriptionNoCertificate          AlertDescription = 41
	AlertDescriptionBadCertificate         AlertDescription = 42
	AlertDescriptionUnsupportedCertificate AlertDescription = 43
	AlertDescriptionCertificateRevoked     AlertDescription = 44
	AlertDescriptionCertificateExpired     AlertDescription = 45
	AlertDescriptionCertificateUnknown     AlertDescription = 46
	AlertDescriptionIllegalParameter       AlertDescription = 47
	AlertDescriptionUnknownCA              AlertDescription = 48
	AlertDescriptionAccessDenied           AlertDescription = 49
	AlertDescriptionDecodeError            AlertDescription = 50
	AlertDescriptionDecryptError           AlertDescription = 51
	AlertDescriptionExportRestriction      AlertDescription = 60
	AlertDescriptionProtocolVersion        AlertDescription = 70
	AlertDescriptionInsufficientSecurity   AlertDescription = 71
	AlertDescriptionInternalError          AlertDescription = 80
	AlertDescriptionUserCanceled           AlertDescription = 90
	AlertDescriptionNoRenegotiation        AlertDescription = 100
	AlertDescriptionUnsupportedExtension   AlertDescription = 110
)

func (ad *AlertDescription) String() string {
	var result string
	switch *ad {
	case AlertDescriptionCloseNotify:
		result = "CloseNotify"
	case AlertDescriptionUnexpectedMessage:
		result = "UnexpectedMessage"
	case AlertDescriptionBadRecordMac:
		result = "BadRecordMac"
	case AlertDescriptionDecryptionFailed:
		result = "DecryptionFailed"
	case AlertDescriptionRecordOverflow:
		result = "RecordOverflow"
	case AlertDescriptionDecompressionFailure:
		result = "DecompressionFailure"
	case AlertDescriptionHandshakeFailure:
		result = "HandshakeFailure"
	case AlertDescriptionNoCertificate:
		result = "NoCertificate"
	case AlertDescriptionBadCertificate:
		result = "BadCertificate"
	case AlertDescriptionUnsupportedCertificate:
		result = "UnsupportedCertificate"
	case AlertDescriptionCertificateRevoked:
		result = "CertificateRevoked"
	case AlertDescriptionCertificateExpired:
		result = "CertificateExpired"
	case AlertDescriptionCertificateUnknown:
		result = "CertificateUnknown"
	case AlertDescriptionIllegalParameter:
		result = "IllegalParameter"
	case AlertDescriptionUnknownCA:
		result = "UnknownCA"
	case AlertDescriptionAccessDenied:
		result = "AccessDenied"
	case AlertDescriptionDecodeError:
		result = "DecodeError"
	case AlertDescriptionDecryptError:
		result = "DecryptError"
	case AlertDescriptionExportRestriction:
		result = "ExportRestriction"
	case AlertDescriptionProtocolVersion:
		result = "ProtocolVersion"
	case AlertDescriptionInsufficientSecurity:
		result = "InsufficientSecurity"
	case AlertDescriptionInternalError:
		result = "InternalError"
	case AlertDescriptionUserCanceled:
		result = "UserCanceled"
	case AlertDescriptionNoRenegotiation:
		result = "NoRenegotiation"
	case AlertDescriptionUnsupportedExtension:
		result = "UnsupportedExtension"

	default:
		result = "Unknown Alert Description"
	}
	return fmt.Sprintf("%s (%v)", result, *ad)
}

type Alert struct {
	Level       AlertLevel
	Description AlertDescription
}

func (m *Alert) GetContentType() ContentType {
	return ContentTypeAlert
}

func (m *Alert) String() string {
	return fmt.Sprintf("Alert %s %s", &m.Level, &m.Description)
}

func (m *Alert) Decode(buf []byte, offset int, arrayLen int) (int, error) {
	m.Level = AlertLevel(buf[offset])
	offset++
	m.Description = AlertDescription(buf[offset])
	offset++
	return offset, nil
}

func (m *Alert) Encode() []byte {
	result := []byte{byte(m.Level), byte(m.Description)}
	return result
}
