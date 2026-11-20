package utils

import (
	"bytes"
	"encoding/base64"
)

// Reference: https://github.com/Becivells/iconhash

// Mmh3Hash32 计算 mmh3 hash
func Mmh3Hash32(raw []byte) int32 {
	return int32(mmh3Sum32(raw))
}

// base64 encode
func Base64Encode(braw []byte) []byte {
	bckd := base64.StdEncoding.EncodeToString(braw)
	var buffer bytes.Buffer
	for i := 0; i < len(bckd); i++ {
		ch := bckd[i]
		buffer.WriteByte(ch)
		if (i+1)%76 == 0 {
			buffer.WriteByte('\n')
		}
	}
	buffer.WriteByte('\n')
	return buffer.Bytes()
}
