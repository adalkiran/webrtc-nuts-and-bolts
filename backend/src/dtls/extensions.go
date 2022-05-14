package dtls

import "encoding/binary"

type ExtensionType uint16

type Extension interface {
	ExtensionType() ExtensionType
	Encode() []byte
	Decode(extensionLength int, buf []byte, offset int, arrayLen int) error
	String() string
}

const (
	ExtensionTypeServerName                   ExtensionType = 0
	ExtensionTypeSupportedEllipticCurves      ExtensionType = 10
	ExtensionTypeSupportedPointFormats        ExtensionType = 11
	ExtensionTypeSupportedSignatureAlgorithms ExtensionType = 13
	ExtensionTypeUseSRTP                      ExtensionType = 14
	ExtensionTypeALPN                         ExtensionType = 16
	ExtensionTypeUseExtendedMasterSecret      ExtensionType = 23
	ExtensionTypeRenegotiationInfo            ExtensionType = 65281

	ExtensionTypeUnknown ExtensionType = 65535 //Not a valid value
)

func DecodeExtensionMap(buf []byte, offset int, arrayLen int) (map[ExtensionType]Extension, int, error) {
	result := map[ExtensionType]Extension{}
	length := binary.BigEndian.Uint16(buf[offset : offset+2])
	offset += 2
	offsetBackup := offset
	for offset < offsetBackup+int(length) {
		extensionType := ExtensionType(binary.BigEndian.Uint16(buf[offset : offset+2]))
		offset += 2
		extensionLength := binary.BigEndian.Uint16(buf[offset : offset+2])
		offset += 2
		var extension Extension = nil
		switch extensionType {
		case ExtensionTypeUseExtendedMasterSecret:
			extension = new(ExtUseExtendedMasterSecret)
		case ExtensionTypeUseSRTP:
			extension = new(ExtUseSRTP)
		case ExtensionTypeSupportedPointFormats:
			extension = new(ExtSupportedPointFormats)
		case ExtensionTypeSupportedEllipticCurves:
			extension = new(ExtSupportedEllipticCurves)
		default:
			extension = &ExtUnknown{
				Type:       extensionType,
				DataLength: extensionLength,
			}
		}
		if extension != nil {
			err := extension.Decode(int(extensionLength), buf, offset, arrayLen)

			if err != nil {
				return nil, offset, err
			}
			AddExtension(result, extension)
		}
		offset += int(extensionLength)
	}
	return result, offset, nil
}

func EncodeExtensionMap(extensionMap map[ExtensionType]Extension) []byte {
	result := make([]byte, 2)
	encodedBody := make([]byte, 0)
	for _, extension := range extensionMap {
		encodedExtension := extension.Encode()
		encodedExtType := make([]byte, 2)
		binary.BigEndian.PutUint16(encodedExtType, uint16(extension.ExtensionType()))
		encodedBody = append(encodedBody, encodedExtType...)

		encodedExtLen := make([]byte, 2)
		binary.BigEndian.PutUint16(encodedExtLen, uint16(len(encodedExtension)))
		encodedBody = append(encodedBody, encodedExtLen...)
		encodedBody = append(encodedBody, encodedExtension...)
	}
	binary.BigEndian.PutUint16(result[0:], uint16(len(encodedBody)))
	result = append(result, encodedBody...)
	return result
}

func AddExtension(extensionMap map[ExtensionType]Extension, extension Extension) {
	extType := extension.ExtensionType()
	// This is only for debugging purposes to assign unique map key value for unknown types
	if extType == ExtensionTypeUnknown {
		for {
			_, ok := extensionMap[extType]
			if !ok {
				break
			}
			extType--
		}
	}
	extensionMap[extType] = extension
}
