package gox

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/zan8in/afrog/v2/pkg/protocols/netxclient"
	"github.com/zan8in/pins/netx"
	urlutil "github.com/zan8in/pins/url"
)

var (
	negotiateProtocolRequest_enc  = "G8o+kd/4y8chPCaObKK8L9+tJVFBb7ntWH/EXJ74635V3UTXA4TFOc6uabZfuLr0Xisnk7OsKJZ2Xdd3l8HNLdMOYZXAX5ZXnMC4qI+1d/MXA2TmidXeqGt8d9UEF5VesQlhP051GGBSldkJkVrP/fzn4gvLXcwgAYee3Zi2opAvuM6ScXrMkcbx200ThnOOEx98/7ArteornbRiXQjnr6dkJEUDTS43AW6Jl3OK2876Yaz5iYBx+DW5WjiLcMR+b58NJRxm4FlVpusZjBpzEs4XOEqglk6QIWfWbFZYgdNLy3WaFkkgDjmB1+6LhpYSOaTsh4EM0rwZq2Z4Lr8TE5WcPkb/JNsWNbibKlwtNtp94fIYvAWgxt5mn/oXpfUD"
	sessionSetupRequest_enc       = "52HeCQEbsSwiSXg98sdD64qyRou0jARlvfQi1ekDHS77Nk/8dYftNXlFahLEYWIxYYJ8u53db9OaDfAvOEkuox+p+Ic1VL70r9Q5HuL+NMyeyeN5T5el07X5cT66oBDJnScs1XdvM6CBRtj1kUs2h40Z5Vj9EGzGk99SFXjSqbtGfKFBp0DhL5wPQKsoiXYLKKh9NQiOhOMWHYy/C+Iwhf3Qr8d1Wbs2vgEzaWZqIJ3BM3z+dhRBszQoQftszC16TUhGQc48XPFHN74VRxXgVe6xNQwqrWEpA4hcQeF1+QqRVHxuN+PFR7qwEcU1JbnTNISaSrqEe8GtRo1r2rs7+lOFmbe4qqyUMgHhZ6Pwu1bkhrocMUUzWQBogAvXwFb8"
	treeConnectRequest_enc        = "+b/lRcmLzH0c0BYhiTaYNvTVdYz1OdYYDKhzGn/3T3P4b6pAR8D+xPdlb7O4D4A9KMyeIBphDPmEtFy44rtto2dadFoit350nghebxbYA0pTCWIBd1kN0BGMEidRDBwLOpZE6Qpph/DlziDjjfXUz955dr0cigc9ETHD/+f3fELKsopTPkbCsudgCs48mlbXcL13GVG5cGwKzRuP4ezcdKbYzq1DX2I7RNeBtw/vAlYh6etKLv7s+YyZ/r8m0fBY9A57j+XrsmZAyTWbhPJkCg=="
	transNamedPipeRequest_enc     = "k/RGiUQ/tw1yiqioUIqirzGC1SxTAmQmtnfKd1qiLish7FQYxvE+h4/p7RKgWemIWRXDf2XSJ3K0LUIX0vv1gx2eb4NatU7Qosnrhebz3gUo7u25P5BZH1QKdagzPqtitVjASpxIjB3uNWtYMrXGkkuAm8QEitberc+mP0vnzZ8Nv/xiiGBko8O4P/wCKaN2KZVDLbv2jrN8V/1zY6fvWA=="
	trans2SessionSetupRequest_enc = "JqNw6PUKcWOYFisUoUCyD24wnML2Yd8kumx9hJnFWbhM2TQkRvKHsOMWzPVfggRrLl8sLQFqzk8bv8Rpox3uS61l480Mv7HdBPeBeBeFudZMntXBUa4pWUH8D9EXCjoUqgAdvw6kGbPOOKUq3WmNb0GDCZapqQwyUKKMHmNIUMVMAOyVfKeEMJA6LViGwyvHVMNZ1XWLr0xafKfEuz4qoHiDyVWomGjJt8DQd6+jgLk="
	negotiateProtocolRequest, _   = hex.DecodeString(AesDecrypt(negotiateProtocolRequest_enc, key))
	sessionSetupRequest, _        = hex.DecodeString(AesDecrypt(sessionSetupRequest_enc, key))
	treeConnectRequest, _         = hex.DecodeString(AesDecrypt(treeConnectRequest_enc, key))
	transNamedPipeRequest, _      = hex.DecodeString(AesDecrypt(transNamedPipeRequest_enc, key))
	trans2SessionSetupRequest, _  = hex.DecodeString(AesDecrypt(trans2SessionSetupRequest_enc, key))
)

func MS17010Scan(target string, variableMap map[string]any) error {
	var err error

	variableMap["request"] = nil
	variableMap["response"] = nil

	hostname, err := urlutil.Hostname(target)
	if err != nil {
		return err
	}

	address := fmt.Sprintf("%s:445", hostname)

	setRequest(address, variableMap)
	setTarget(address, variableMap)
	setFullTarget(address, variableMap)

	nc, err := netxclient.NewNetClient(address, netxclient.Config{})
	if err != nil {
		return err
	}

	client, err := netx.NewClient(address, *nc.Config())
	if err != nil {
		return err
	}
	defer client.Close()

	err = client.Send([]byte(negotiateProtocolRequest))
	if err != nil {
		return err
	}

	data, err := client.Receive()
	if err != nil || len(data) < 36 {
		return err
	}

	if binary.LittleEndian.Uint32(data[9:13]) != 0 {
		// status != 0
		return err
	}

	err = client.Send([]byte(sessionSetupRequest))
	if err != nil {
		return err
	}

	data, err = client.Receive()
	if err != nil || len(data) < 36 {
		return err
	}

	if binary.LittleEndian.Uint32(data[9:13]) != 0 {
		// status != 0
		//fmt.Printf("can't determine whether %s is vulnerable or not\n", ip)
		var Err = errors.New("can't determine whether target is vulnerable or not")
		return Err
	}

	// extract OS info
	var os string
	n := len(data)
	sessionSetupResponse := data[36:n]
	if wordCount := sessionSetupResponse[0]; wordCount != 0 {
		// find byte count
		byteCount := binary.LittleEndian.Uint16(sessionSetupResponse[7:9])
		if n != int(byteCount)+45 {
			fmt.Println("[-]", hostname+":445", "ms17010 invalid session setup AndX response")
		} else {
			// two continous null bytes indicates end of a unicode string
			for i := 10; i < len(sessionSetupResponse)-1; i++ {
				if sessionSetupResponse[i] == 0 && sessionSetupResponse[i+1] == 0 {
					os = string(sessionSetupResponse[10:i])
					os = strings.Replace(os, string([]byte{0x00}), "", -1)
					break
				}
			}
		}

	}

	userID := data[32:34]
	treeConnectRequest[32] = userID[0]
	treeConnectRequest[33] = userID[1]
	// TODO change the ip in tree path though it doesn't matter
	err = client.Send([]byte(treeConnectRequest))
	if err != nil {
		return err
	}

	data, err = client.Receive()
	if err != nil || len(data) < 36 {
		return err
	}

	treeID := data[28:30]
	transNamedPipeRequest[28] = treeID[0]
	transNamedPipeRequest[29] = treeID[1]
	transNamedPipeRequest[32] = userID[0]
	transNamedPipeRequest[33] = userID[1]

	err = client.Send([]byte(transNamedPipeRequest))
	if err != nil {
		return err
	}

	data, err = client.Receive()
	if err != nil || len(data) < 36 {
		return err
	}

	if data[9] == 0x05 && data[10] == 0x02 && data[11] == 0x00 && data[12] == 0xc0 {
		//fmt.Printf("%s\tMS17-010\t(%s)\n", ip, os)
		//if runtime.GOOS=="windows" {fmt.Printf("%s\tMS17-010\t(%s)\n", ip, os)
		//} else{fmt.Printf("\033[33m%s\tMS17-010\t(%s)\033[0m\n", ip, os)}
		result1 := fmt.Sprintf("[+] %s\tMS17-010\t(%s)", hostname, os)
		setResponse(result1, variableMap)

		// gologger.Info().Msg(result)
		// common.LogSuccess(result)
		// defer func() {
		// 	if common.SC != "" {
		// 		MS17010EXP(info)
		// 	}
		// }()
		// detect present of DOUBLEPULSAR SMB implant
		trans2SessionSetupRequest[28] = treeID[0]
		trans2SessionSetupRequest[29] = treeID[1]
		trans2SessionSetupRequest[32] = userID[0]
		trans2SessionSetupRequest[33] = userID[1]

		err = client.Send([]byte(trans2SessionSetupRequest))
		if err != nil {
			return nil
		}

		data, err = client.Receive()
		if err != nil || len(data) < 36 {
			return nil
		}

		if data[34] == 0x51 {
			result2 := fmt.Sprintf("[+] %s has DOUBLEPULSAR SMB IMPLANT", hostname)
			setResponse(result1+"\n"+result2, variableMap)
		}

	} else {
		result := fmt.Sprintf("[*] %s  (%s)", hostname, os)
		setResponse(result, variableMap)
	}

	return err

}

func init() {
	funcMap["ms17-010"] = MS17010Scan
}

var key = "0123456789abcdef"

func AesEncrypt(orig string, key string) string {
	// 转成字节数组
	origData := []byte(orig)
	k := []byte(key)
	// 分组秘钥
	// NewCipher该函数限制了输入k的长度必须为16, 24或者32
	block, _ := aes.NewCipher(k)
	// 获取秘钥块的长度
	blockSize := block.BlockSize()
	// 补全码
	origData = PKCS7Padding(origData, blockSize)
	// 加密模式
	blockMode := cipher.NewCBCEncrypter(block, k[:blockSize])
	// 创建数组
	cryted := make([]byte, len(origData))
	// 加密
	blockMode.CryptBlocks(cryted, origData)
	return base64.StdEncoding.EncodeToString(cryted)
}

func AesDecrypt(cryted string, key string) string {
	// 转成字节数组
	crytedByte, _ := base64.StdEncoding.DecodeString(cryted)
	k := []byte(key)
	// 分组秘钥
	block, _ := aes.NewCipher(k)
	// 获取秘钥块的长度
	blockSize := block.BlockSize()
	// 加密模式
	blockMode := cipher.NewCBCDecrypter(block, k[:blockSize])
	// 创建数组
	orig := make([]byte, len(crytedByte))
	// 解密
	blockMode.CryptBlocks(orig, crytedByte)
	// 去补全码
	orig = PKCS7UnPadding(orig)
	return string(orig)
}

// 补码
// AES加密数据块分组长度必须为128bit(byte[16])，密钥长度可以是128bit(byte[16])、192bit(byte[24])、256bit(byte[32])中的任意一个。
func PKCS7Padding(ciphertext []byte, blocksize int) []byte {
	padding := blocksize - len(ciphertext)%blocksize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// 去码
func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
