package main

import (
	"fmt"
	"testing"
)

func TestOpenCoolerFull(t *testing.T) {
	path, err := findCoolerPath(0xE2B7, 0x7001)
	fmt.Printf("findCoolerPath -> %q err=%v\n", path, err)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := openConn(0xE2B7, 0x7001)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Println("openConn OK, reading one report...")
	buf := make([]byte, 64)
	n, rerr := conn.Read(buf)
	fmt.Printf("Read -> n=%d err=%v data=% x\n", n, rerr, buf[:min(n, 16)])
	if n < 3 || buf[0] != 0xA5 {
		t.Fatalf("unexpected report")
	}
	fmt.Println("SUCCESS: full roundtrip")
}
