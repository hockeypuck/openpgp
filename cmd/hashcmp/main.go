package main

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"gopkg.in/hockeypuck/openpgp.v0"
)

func main() {
	var matches, misses int
	for opkr := range openpgp.ReadOpaqueKeyrings(os.Stdin) {
		var buf bytes.Buffer
		for _, op := range opkr.Packets {
			err := op.Serialize(&buf)
			if err != nil {
				panic(err)
			}
		}
		pk, err := opkr.Parse()
		if err != nil {
			panic(err)
		}
		err = openpgp.DropDuplicates(pk)
		if err != nil {
			panic(err)
		}
		digest, err := openpgp.SksDigest(pk, md5.New())
		if err != nil {
			panic(err)
		}
		cmd := exec.Command("./sks_hash")
		var out bytes.Buffer
		cmd.Stdin = bytes.NewBuffer(buf.Bytes())
		cmd.Stdout = &out
		err = cmd.Run()
		if err != nil {
			panic(err)
		}
		digest2 := strings.ToLower(strings.TrimSpace(string(out.Bytes())))
		if digest != digest2 {
			fmt.Printf("hockeypuck=%q sks=%q\n", digest, digest2)
			misses++
		} else {
			matches++
		}
	}
	fmt.Printf("matches=%d misses=%d\n", matches, misses)
}
