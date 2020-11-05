package lzo

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestDecompCrasher1(t *testing.T) {
	Debug = t.Logf
	_, err := Decompress1X(strings.NewReader("\x00"), 0, 0)
	if err == nil {
		t.Fatalf("Decompress single null byte: got nil, want EOF")
	}
}

func TestDecompCrasher2(t *testing.T) {
	Debug = t.Logf
	_, err := Decompress1X(strings.NewReader("\x00\x030000000000000000000000\x01\x000\x000"), 0, 0)
	if err == nil {
		t.Fatalf("Decompress bogus bytes: got nil, want err")
	}
}

var (
	etchosts = []byte(`127.0.0.1	localhost
127.0.1.1	rminnich-MacBookPro

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

192.168.0.1 centre
192.168.0.2 up
192.168.0.3 api2 u00:07:32:4b:f9:f3
192.168.0.4 api3 u00:07:32:4c:04:e6
192.168.0.5 api4 u00:07:32:4c:25:36
192.168.0.6 rome r uc8:b3:73:1f:44:55
192.168.0.7 a apu2 u00:0d:b9:49:0f:04
192.168.0.9 a300 ua8:a1:59:23:6b:75
192.168.0.239 router

# dresden
192.168.0.10 dellbmc u98:90:96:ff:fa:81
192.168.0.11 dell u4c:d9:8f:7f:58:93
192.168.0.12 upxtreme upx u u00:07:32:73:92:bb
192.168.0.13 upxtreme upx u u00:07:32:73:92:bc

192.168.86.70 zero
192.168.86.86 x230 corebootthinkpad tp

192.168.0.100 dlpower dl

`)
	// This is /etc/hosts compressed with lzop -1
	etchosts1X = []byte{
		//LZO1X-1(15)       778       570  73.3%  2020-11-05 09:46  hosts
		// 1.030 2.080 0.940  Fl: 0x0300000d  Mo: 000000000000  Me: 2/1  OS:  3
		//Magic
		0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a,
		//Version
		0x10, 0x30,
		// Lib Version
		0x20, 0x80,
		// Needed Version
		0x09, 0x40,
		// Method
		0x02,
		// Level
		0x01,
		// Flags
		0x03, 0x00, 0x00, 0x0d,
		// No filter.
		// Mode -- lzop says zero, wtf.
		0x00, 0x00, 0x81, 0xa4,
		0x5f, 0x9c, 0x90, 0x54,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x34, 0xf9, 0x04,
		0x41, 0x00, 0x00, 0x03,
		0x0a,
		0x00, 0x00, 0x02, 0x3a,
		0xdc, 0x5c, 0xd2, 0x0e,
		// Start of compressed data.
		0x00, 0x02, 0x31, 0x32, 0x37, 0x2e, 0x30, 0x2e, 0x30, 0x2e,
		0x31, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x0a,
		0xac, 0x02, 0x00, 0x37, 0x31, 0x2e, 0x31, 0x09, 0x72, 0x6d, 0x69, 0x6e,
		0x6e, 0x69, 0x63, 0x68, 0x2d, 0x4d, 0x61, 0x63, 0x42, 0x6f, 0x6f, 0x6b,
		0x50, 0x72, 0x6f, 0x0a, 0x0a, 0x23, 0x20, 0x54, 0x68, 0x65, 0x20, 0x66,
		0x6f, 0x6c, 0x6c, 0x6f, 0x77, 0x69, 0x6e, 0x67, 0x20, 0x6c, 0x69, 0x6e,
		0x65, 0x73, 0x20, 0x61, 0x72, 0x65, 0x20, 0x64, 0x65, 0x73, 0x69, 0x72,
		0x61, 0x62, 0x6c, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x49, 0x50, 0x76,
		0x36, 0x20, 0x63, 0x61, 0x70, 0x80, 0x02, 0x60, 0x0b, 0x03, 0x73, 0x0a,
		0x3a, 0x3a, 0x31, 0x20, 0x60, 0x00, 0x01, 0x69, 0x70, 0x36, 0x2d, 0x27,
		0xbd, 0x01, 0x20, 0xb4, 0x01, 0x0b, 0x6f, 0x70, 0x62, 0x61, 0x63, 0x6b,
		0x0a, 0x66, 0x65, 0x30, 0x30, 0x3a, 0x3a, 0x30, 0xd0, 0x02, 0x06, 0x63,
		0x61, 0x6c, 0x6e, 0x65, 0x74, 0x0a, 0x66, 0x66, 0x28, 0x50, 0x00, 0x08,
		0x6d, 0x63, 0x61, 0x73, 0x74, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x7d,
		0x02, 0x32, 0x6c, 0x0a, 0x64, 0x08, 0x05, 0x61, 0x6c, 0x6c, 0x6e, 0x6f,
		0x64, 0x65, 0x73, 0xd1, 0x02, 0x32, 0x84, 0x08, 0x00, 0x01, 0x61, 0x6c,
		0x6c, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x73, 0x0a, 0x0a, 0x31, 0x39,
		0x32, 0x2e, 0x31, 0x36, 0x38, 0x70, 0x1d, 0x04, 0x20, 0x63, 0x65, 0x6e,
		0x74, 0x72, 0x65, 0x29, 0x48, 0x00, 0x01, 0x32, 0x20, 0x75, 0x70, 0x29,
		0x38, 0x00, 0x00, 0x07, 0x33, 0x20, 0x61, 0x70, 0x69, 0x32, 0x20, 0x75,
		0x30, 0x30, 0x3a, 0x30, 0x37, 0x3a, 0x33, 0x32, 0x3a, 0x34, 0x62, 0x3a,
		0x66, 0x39, 0x3a, 0x66, 0x33, 0x29, 0x8d, 0x00, 0x34, 0x6d, 0x04, 0x33,
		0x2a, 0x8c, 0x00, 0x04, 0x63, 0x3a, 0x30, 0x34, 0x3a, 0x65, 0x36, 0x29,
		0x8d, 0x00, 0x35, 0x6d, 0x04, 0x34, 0x2c, 0x8c, 0x00, 0x01, 0x32, 0x35,
		0x3a, 0x33, 0x2a, 0x8c, 0x00, 0x00, 0x09, 0x36, 0x20, 0x72, 0x6f, 0x6d,
		0x65, 0x20, 0x72, 0x20, 0x75, 0x63, 0x38, 0x3a, 0x62, 0x33, 0x3a, 0x37,
		0x33, 0x3a, 0x31, 0x66, 0x3a, 0x34, 0x34, 0x3a, 0x35, 0x35, 0x29, 0x24,
		0x01, 0x04, 0x37, 0x20, 0x61, 0x20, 0x61, 0x70, 0x75, 0xcc, 0x12, 0x0a,
		0x64, 0x3a, 0x62, 0x39, 0x3a, 0x34, 0x39, 0x3a, 0x30, 0x66, 0x3a, 0x30,
		0x34, 0x29, 0x94, 0x00, 0x00, 0x06, 0x39, 0x20, 0x61, 0x33, 0x30, 0x30,
		0x20, 0x75, 0x61, 0x38, 0x3a, 0x61, 0x31, 0x3a, 0x35, 0x39, 0x3a, 0x32,
		0x33, 0x3a, 0x36, 0x62, 0x3a, 0x37, 0x2a, 0x24, 0x01, 0x01, 0x32, 0x33,
		0x39, 0x20, 0xb0, 0x22, 0x6c, 0x39, 0x04, 0x64, 0x72, 0x65, 0x73, 0x64,
		0x65, 0x6e, 0x29, 0x0c, 0x01, 0x00, 0x0b, 0x31, 0x30, 0x20, 0x64, 0x65,
		0x6c, 0x6c, 0x62, 0x6d, 0x63, 0x20, 0x75, 0x39, 0x38, 0x3a, 0x39, 0x30,
		0x3a, 0x39, 0x36, 0x3a, 0x66, 0x66, 0x3a, 0x66, 0x61, 0x3a, 0x38, 0x31,
		0x2a, 0x9d, 0x00, 0x31, 0x9c, 0x04, 0x0f, 0x20, 0x75, 0x34, 0x63, 0x3a,
		0x64, 0x39, 0x3a, 0x38, 0x66, 0x3a, 0x37, 0x66, 0x3a, 0x35, 0x38, 0x3a,
		0x39, 0x2a, 0x91, 0x04, 0x31, 0x60, 0x2b, 0x09, 0x78, 0x74, 0x72, 0x65,
		0x6d, 0x65, 0x20, 0x75, 0x70, 0x78, 0x20, 0x75, 0x29, 0x2c, 0x04, 0x05,
		0x37, 0x33, 0x3a, 0x39, 0x32, 0x3a, 0x62, 0x62, 0x2a, 0x4d, 0x01, 0x33,
		0x74, 0x04, 0x3b, 0xb9, 0x00, 0x63, 0x28, 0x24, 0x07, 0x07, 0x38, 0x36,
		0x2e, 0x37, 0x30, 0x20, 0x7a, 0x65, 0x72, 0x6f, 0x27, 0x08, 0x01, 0x00,
		0x0c, 0x38, 0x36, 0x2e, 0x38, 0x36, 0x20, 0x78, 0x32, 0x33, 0x30, 0x20,
		0x63, 0x6f, 0x72, 0x65, 0x62, 0x6f, 0x6f, 0x74, 0x74, 0x68, 0x69, 0x6e,
		0x6b, 0x70, 0x61, 0x64, 0x20, 0x74, 0x70, 0x28, 0xe8, 0x00, 0x0f, 0x30,
		0x2e, 0x31, 0x30, 0x30, 0x20, 0x64, 0x6c, 0x70, 0x6f, 0x77, 0x65, 0x72,
		0x20, 0x64, 0x6c, 0x0a, 0x0a, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
)

// TestDecompFromLzopCommand verifies that this package can decompress data compressed with lzop(1)
func TestDecompFromLzopCommand(t *testing.T) {
	Debug = t.Logf
	Verbose = true
	d, err := DecompressLZOP(bytes.NewReader(etchosts1X))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(d, etchosts) {
		t.Fatalf("Got:\n%s\n want \n%s\n", hex.Dump(d), hex.Dump(etchosts))
	}
}

// TestDecompFromLzopCommandShort tests a bogus magic number (too short)
func TestDecompFromLzopCommandShort(t *testing.T) {
	Debug = t.Logf
	Verbose = true
	_, err := DecompressLZOP(bytes.NewReader(etchosts1X[:8]))
	if err == nil {
		t.Fatal("Want err, got nil")
	}
}
