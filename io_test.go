/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2014  Casey Marshall

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published by
   the Free Software Foundation, version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package openpgp

import (
	"bytes"
	"crypto/md5"
	"io"
	"testing"

	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	gc "gopkg.in/check.v1"
)

func Test(t *testing.T) { gc.TestingT(t) }

type SamplePacketSuite struct{}

var _ = gc.Suite(&SamplePacketSuite{})

func (s *SamplePacketSuite) TestVerifyUserAttributeSig(c *gc.C) {
	key := MustInputAscKey(c, "uat.asc")
	c.Assert(key.UserAttributes, gc.HasLen, 1)
	DropDuplicates(key)
	c.Assert(key.UserAttributes, gc.HasLen, 1)
	uat := key.UserAttributes[0]
	c.Assert(uat.Images, gc.HasLen, 1)
	// TODO: check contents
}

func (s *SamplePacketSuite) TestSksDigest(c *gc.C) {
	key := MustInputAscKey(c, "sksdigest.asc")
	md5, err := SksDigest(key, md5.New())
	c.Assert(err, gc.IsNil)
	c.Assert(key.RShortID, gc.Equals, "ce353cf4")
	c.Assert(md5, gc.Equals, "da84f40d830a7be2a3c0b7f2e146bfaa")
}

func (s *SamplePacketSuite) TestUatRtt(c *gc.C) {
	f := MustInput(c, "uat.asc")
	defer f.Close()
	block, err := armor.Decode(f)
	c.Assert(err, gc.IsNil)
	var p packet.Packet
	for {
		p, err = packet.Read(block.Body)
		if err != nil {
			c.Assert(err, gc.Equals, io.EOF)
			break
		}

		uat, ok := p.(*packet.UserAttribute)
		if ok {
			var buf bytes.Buffer
			uat.Serialize(&buf)
			or := packet.NewOpaqueReader(bytes.NewBuffer(buf.Bytes()))
			op, _ := or.Next()
			c.Assert(buf.Bytes()[3:], gc.DeepEquals, op.Contents)
		}
	}
}

func (s *SamplePacketSuite) TestPacketCounts(c *gc.C) {
	testCases := []struct {
		name                                         string
		nUserID, nUserAttribute, nSubkey, nSignature int
	}{{
		"0ff16c87.asc", 9, 0, 1, 0,
	}, {
		"alice_signed.asc", 1, 0, 1, 0,
	}, {
		"uat.asc", 2, 1, 3, 0,
	}, {
		"252B8B37.dupsig.asc", 3, 0, 2, 1,
	}}
	for i, testCase := range testCases {
		c.Logf("test#%d: %s", i, testCase.name)
		f := MustInput(c, testCase.name)
		defer f.Close()
		block, err := armor.Decode(f)
		c.Assert(err, gc.IsNil)
		var key *Pubkey
		for keyRead := range ReadKeys(block.Body) {
			key = keyRead.Pubkey
		}
		c.Assert(key, gc.NotNil)
		c.Assert(key.UserIDs, gc.HasLen, testCase.nUserID)
		c.Assert(key.UserAttributes, gc.HasLen, testCase.nUserAttribute)
		c.Assert(key.Subkeys, gc.HasLen, testCase.nSubkey)
		c.Assert(key.Signatures, gc.HasLen, testCase.nSignature)
	}
}

func (s *SamplePacketSuite) TestDeduplicate(c *gc.C) {
	f := MustInput(c, "d7346e26.asc")
	defer f.Close()
	block, err := armor.Decode(f)
	if err != nil {
		c.Fatal(err)
	}

	// Parse keyring, duplicate all packet types except primary pubkey.
	kr := &OpaqueKeyring{}
	for opkr := range ReadOpaqueKeyrings(block.Body) {
		c.Assert(opkr.Error, gc.IsNil)
		for _, op := range opkr.Packets {
			kr.Packets = append(kr.Packets, op)
			switch op.Tag {
			case 2:
				kr.Packets = append(kr.Packets, op)
				fallthrough
			case 13, 14, 17:
				kr.Packets = append(kr.Packets, op)
			}
		}
	}
	key, err := kr.Parse()
	c.Assert(err, gc.IsNil)

	n := 0
	for _, node := range key.contents() {
		c.Logf("%s", node.uuid())
		n++
	}

	c.Log()
	err = CollectDuplicates(key)
	c.Assert(err, gc.IsNil)

	n2 := 0
	for _, node := range key.contents() {
		c.Logf("%s %d", node.uuid(), node.packet().Count)
		n2++
		switch node.packet().Tag {
		case 2:
			c.Check(node.packet().Count, gc.Equals, 2)
		case 13, 14, 17:
			c.Check(node.packet().Count, gc.Equals, 1)
		case 6:
			c.Check(node.packet().Count, gc.Equals, 0)
		default:
			c.Fatal("should not happen")
		}
	}
	c.Assert(n2 < n, gc.Equals, true)
}

func (s *SamplePacketSuite) TestMerge(c *gc.C) {
	key1 := MustInputAscKey(c, "lp1195901.asc")
	key2 := MustInputAscKey(c, "lp1195901_2.asc")
	err := Merge(key2, key1)
	c.Assert(err, gc.IsNil)
	var matchUID *UserID
	for _, uid := range key2.UserIDs {
		if uid.Keywords == "Phil Pennock <pdp@spodhuis.org>" {
			matchUID = uid
		}
	}
	c.Assert(matchUID, gc.NotNil)
}
