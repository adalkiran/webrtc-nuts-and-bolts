package dtls

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/adalkiran/webrtc-nuts-and-bolts/src/common"
)

type ExtUseExtendedMasterSecret struct {
}

func (e *ExtUseExtendedMasterSecret) String() string {
	return "[UseExtendedMasterSecret]"
}

func (e *ExtUseExtendedMasterSecret) ExtensionType() ExtensionType {
	return ExtensionTypeUseExtendedMasterSecret
}

func (e *ExtUseExtendedMasterSecret) Encode() []byte {
	return []byte{}
}

func (e *ExtUseExtendedMasterSecret) Decode(extensionLength int, buf []byte, offset int, arrayLen int) error {
	return nil
}

type ExtRenegotiationInfo struct {
}

func (e *ExtRenegotiationInfo) String() string {
	return "[RenegotiationInfo]"
}

func (e *ExtRenegotiationInfo) ExtensionType() ExtensionType {
	return ExtensionTypeRenegotiationInfo
}

func (e *ExtRenegotiationInfo) Encode() []byte {
	// Empty byte array length is zero
	return []byte{0}
}

func (e *ExtRenegotiationInfo) Decode(extensionLength int, buf []byte, offset int, arrayLen int) error {
	return nil
}

type ExtUseSRTP struct {
	ProtectionProfiles []SRTPProtectionProfile
	Mki                []byte
}

func (e *ExtUseSRTP) String() string {
	protectionProfilesStr := make([]string, len(e.ProtectionProfiles))
	for i, p := range e.ProtectionProfiles {
		protectionProfilesStr[i] = p.String()
	}
	return common.JoinSlice("\n", false,
		"[UseSRTP]",
		common.ProcessIndent("Protection Profiles:", "+", protectionProfilesStr),
	)
}

func (e *ExtUseSRTP) ExtensionType() ExtensionType {
	return ExtensionTypeUseSRTP
}

func (e *ExtUseSRTP) Encode() []byte {
	result := make([]byte, 2+(len(e.ProtectionProfiles)*2)+1+len(e.Mki))
	offset := 0
	binary.BigEndian.PutUint16(result[offset:], uint16(len(e.ProtectionProfiles)*2))
	offset += 2
	for i := 0; i < len(e.ProtectionProfiles); i++ {
		binary.BigEndian.PutUint16(result[offset:], uint16(e.ProtectionProfiles[i]))
		offset += 2
	}
	result[offset] = byte(len(e.Mki))
	offset++
	copy(result[offset:], e.Mki)
	offset += len(e.Mki)
	return result
}

func (e *ExtUseSRTP) Decode(extensionLength int, buf []byte, offset int, arrayLen int) error {
	protectionProfilesLength := binary.BigEndian.Uint16(buf[offset : offset+2])
	offset += 2
	protectionProfilesCount := protectionProfilesLength / 2
	e.ProtectionProfiles = make([]SRTPProtectionProfile, protectionProfilesCount)
	for i := 0; i < int(protectionProfilesCount); i++ {
		e.ProtectionProfiles[i] = SRTPProtectionProfile(binary.BigEndian.Uint16(buf[offset : offset+2]))
		offset += 2
	}
	mkiLength := buf[offset]
	offset++

	e.Mki = make([]byte, mkiLength)
	copy(e.Mki, buf[offset:offset+int(mkiLength)])
	offset += int(mkiLength)

	return nil
}

// Only Uncompressed was implemented.
// See for further Elliptic Curve Point Format types: https://www.rfc-editor.org/rfc/rfc8422.html#section-5.1.2
type ExtSupportedPointFormats struct {
	PointFormats []PointFormat
}

func (e *ExtSupportedPointFormats) String() string {
	return fmt.Sprintf("[SupportedPointFormats] Point Formats: %s", fmt.Sprint(e.PointFormats))
}

func (e *ExtSupportedPointFormats) ExtensionType() ExtensionType {
	return ExtensionTypeSupportedPointFormats
}

func (e *ExtSupportedPointFormats) Encode() []byte {
	result := make([]byte, 1+(len(e.PointFormats)))
	offset := 0
	result[offset] = byte(len(e.PointFormats))
	offset++
	for i := 0; i < len(e.PointFormats); i++ {
		result[offset] = byte(e.PointFormats[i])
		offset++
	}
	return result
}

func (e *ExtSupportedPointFormats) Decode(extensionLength int, buf []byte, offset int, arrayLen int) error {
	pointFormatsCount := buf[offset]
	offset++
	e.PointFormats = make([]PointFormat, pointFormatsCount)
	for i := 0; i < int(pointFormatsCount); i++ {
		e.PointFormats[i] = PointFormat(buf[offset])
		offset++
	}

	return nil
}

// Only X25519 was implemented.
// See for further NamedCurve types: https://www.rfc-editor.org/rfc/rfc8422.html#section-5.1.1
type ExtSupportedEllipticCurves struct {
	Curves []Curve
}

func (e *ExtSupportedEllipticCurves) String() string {
	curvesStr := make([]string, len(e.Curves))
	for i, c := range e.Curves {
		curvesStr[i] = c.String()
	}
	return common.JoinSlice("\n", false,
		"[SupportedEllipticCurves]",
		common.ProcessIndent("Curves:", "+", curvesStr),
	)
}

func (e *ExtSupportedEllipticCurves) ExtensionType() ExtensionType {
	return ExtensionTypeSupportedEllipticCurves
}

func (e *ExtSupportedEllipticCurves) Encode() []byte {
	result := make([]byte, 1+(len(e.Curves)*2))
	offset := 0
	binary.BigEndian.PutUint16(result[offset:], uint16(len(e.Curves)))
	offset += 2
	for i := 0; i < len(e.Curves); i++ {
		binary.BigEndian.PutUint16(result[offset:], uint16(e.Curves[i]))
		offset += 2
	}
	return result
}

func (e *ExtSupportedEllipticCurves) Decode(extensionLength int, buf []byte, offset int, arrayLen int) error {
	curvesLength := binary.BigEndian.Uint16(buf[offset:])
	offset += 2
	curvesCount := curvesLength / 2
	e.Curves = make([]Curve, curvesCount)
	for i := 0; i < int(curvesCount); i++ {
		e.Curves[i] = Curve(binary.BigEndian.Uint16(buf[offset:]))
		offset += 2
	}

	return nil
}

// ExtUnknown is not for processing. It is only for debugging purposes.
type ExtUnknown struct {
	Type       ExtensionType
	DataLength uint16
}

func (e *ExtUnknown) String() string {
	return fmt.Sprintf("[Unknown Extension Type] Ext Type: <u>%d</u>, Data: <u>%d bytes</u>", e.Type, e.DataLength)
}

func (e *ExtUnknown) ExtensionType() ExtensionType {
	return 65535 // An invalid value
}

func (e *ExtUnknown) Encode() []byte {
	panic(errors.New("ExtUnknown cannot be encoded, it's readonly"))
}

func (e *ExtUnknown) Decode(extensionLength int, buf []byte, offset int, arrayLen int) error {
	return nil
}
