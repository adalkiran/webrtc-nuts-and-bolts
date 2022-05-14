package common

import "fmt"

func Uint8SliceToHexStr(slice []uint8) string {
	if len(slice) == 0 {
		return "<empty>"
	}
	result := make([]string, len(slice))
	for i, item := range slice {
		result[i] = fmt.Sprintf("0x%02x", item)
	}
	return fmt.Sprintf("%s", result)
}

func Uint16SliceToHexStr(slice []uint16) string {
	if len(slice) == 0 {
		return "<empty>"
	}
	result := make([]string, len(slice))
	for i, item := range slice {
		result[i] = fmt.Sprintf("0x%04x", item)
	}
	return fmt.Sprintf("%s", result)
}
