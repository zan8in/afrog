package utils

import "encoding/binary"

// MurmurHash3 x86_32 的纯 Go 实现（seed 固定为 0）。
//
// 为什么不直接用 github.com/spaolacci/murmur3：该库的纯 Go 分支用 unsafe 指针算术
// 逐 4 字节读取，在 Go 1.27 的 -race（checkptr）下会被判为非法指针运算并直接
// panic（checkptr: pointer arithmetic result points to invalid allocation），
// 使整个 -race 测试无法跑完。这里改用 encoding/binary 逐字读取，不碰 unsafe，
// 输出与上游按位一致（固定向量见 murmur3_test.go）。
//
// favicon 的 mmh3 值必须与公开指纹库对齐，所以这里只做「等价替换」，
// 不改动算法本身。
const (
	murmur3C1  uint32 = 0xcc9e2d51
	murmur3C2  uint32 = 0x1b873593
	murmur3R1         = 15
	murmur3R2         = 13
	murmur3Mul        = 0xe6546b64
)

// mmh3Sum32 返回 data 的 MurmurHash3 x86_32 哈希，等价于 murmur3.Sum32。
func mmh3Sum32(data []byte) uint32 {
	h1 := uint32(0)

	nblocks := len(data) / 4
	for i := 0; i < nblocks; i++ {
		k1 := binary.LittleEndian.Uint32(data[i*4:])

		k1 *= murmur3C1
		k1 = k1<<murmur3R1 | k1>>(32-murmur3R1)
		k1 *= murmur3C2

		h1 ^= k1
		h1 = h1<<murmur3R2 | h1>>(32-murmur3R2)
		h1 = h1*5 + murmur3Mul
	}

	var k1 uint32
	switch tail := data[nblocks*4:]; len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= murmur3C1
		k1 = k1<<murmur3R1 | k1>>(32-murmur3R1)
		k1 *= murmur3C2
		h1 ^= k1
	}

	h1 ^= uint32(len(data))
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16

	return h1
}
