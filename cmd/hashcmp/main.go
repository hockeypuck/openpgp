package main

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"os"
	"os/exec"
	"strings"

	xopenpgp "golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"gopkg.in/errgo.v1"

	log "gopkg.in/hockeypuck/logrus.v0"
	"gopkg.in/hockeypuck/openpgp.v1"
)

func main() {
	var matches, misses int
	var n int
	for opkr := range openpgp.ReadOpaqueKeyrings(os.Stdin) {
		match, miss, err := testKeyring(opkr)
		if err != nil {
			log.Errorf("key#%d: %v", n, errgo.Details(err))
		}
		matches += match
		misses += miss
	}
	log.Infof("matches=%d misses=%d\n", matches, misses)
}

func testKeyring(opkr *openpgp.OpaqueKeyring) (int, int, error) {
	var buf bytes.Buffer
	for _, op := range opkr.Packets {
		err := op.Serialize(&buf)
		if err != nil {
			return 0, 0, errgo.Mask(err)
		}
	}
	pk, err := opkr.Parse()
	if err != nil {
		return 0, 0, errgo.Mask(err)
	}
	dupDigest, err := openpgp.SksDigest(pk, md5.New())
	if err != nil {
		return 0, 0, errgo.Mask(err)
	}

	err = openpgp.DropDuplicates(pk)
	if err != nil {
		return 0, 0, errgo.Mask(err)
	}
	dedupDigest, err := openpgp.SksDigest(pk, md5.New())
	if err != nil {
		return 0, 0, errgo.Mask(err)
	}
	cmd := exec.Command("./sks_hash")
	var out bytes.Buffer
	cmd.Stdin = bytes.NewBuffer(buf.Bytes())
	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil {
		return 0, 0, errgo.Mask(err)
	}
	sksDigest := strings.ToLower(strings.TrimSpace(string(out.Bytes())))
	if dedupDigest != sksDigest {
		log.Warningf("hkp=%q hkp_dedup=%q sks=%q", dupDigest, dedupDigest, sksDigest)
		var out bytes.Buffer
		armw, err := armor.Encode(&out, xopenpgp.PublicKeyType, nil)
		if err != nil {
			return 0, 1, errgo.Mask(err)
		}
		armw.Write(buf.Bytes())
		armw.Close()
		fmt.Println(out.String())
		return 0, 1, nil
	}
	return 1, 0, nil
}
