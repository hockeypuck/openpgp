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
	gc "gopkg.in/check.v1"
	log "gopkg.in/hockeypuck/logrus.v0"
)

func init() {
	log.SetLevel(log.DebugLevel)
}

type TypesSuite struct{}

var _ = gc.Suite(&TypesSuite{})

func (s *TypesSuite) TestVisitor(c *gc.C) {
	key := MustInputAscKey(c, "sksdigest.asc")
	c.Assert(key.UserIDs, gc.HasLen, 1)
	c.Assert(key.UserIDs[0].Signatures, gc.HasLen, 1)
	c.Assert(key.UserIDs[0].Signatures[0], gc.NotNil)
	c.Assert(key.Subkeys, gc.HasLen, 1)
	c.Assert(key.Subkeys[0].Signatures, gc.HasLen, 1)
	c.Assert(key.Subkeys[0].Signatures[0], gc.NotNil)
	var npub, nuid, nsub, nsig int
	contents := key.contents()
	for _, node := range contents {
		switch p := node.(type) {
		case *Pubkey:
			npub++
		case *UserID:
			nuid++
		case *Subkey:
			nsub++
		case *Signature:
			nsig++
		default:
			c.Fatalf("unexpected node type: %+v", p)
		}
	}
	c.Assert(1, gc.Equals, npub)
	c.Assert(1, gc.Equals, nuid)
	c.Assert(1, gc.Equals, nsub)
	c.Assert(2, gc.Equals, nsig)
}

func (s *TypesSuite) TestIterOpaque(c *gc.C) {
	key := MustInputAscKey(c, "sksdigest.asc")
	hits := make(map[uint8]int)
	for _, tag := range []uint8{
		2, 6, 13, 14} {
		//P.PacketTypeSignature, P.PacketTypePublicKey,
		//P.PacketTypeUserId, P.PacketTypePublicSubkey} {
		hits[tag] = 0
	}
	for _, node := range key.contents() {
		hits[node.packet().Tag]++
	}
	c.Log(hits)
	c.Assert(2, gc.Equals, hits[2 /*P.PacketTypeSignature*/])
	c.Assert(1, gc.Equals, hits[6 /*P.PacketTypePublicKey*/])
	c.Assert(1, gc.Equals, hits[13 /*P.PacketTypeUserId*/])
	c.Assert(1, gc.Equals, len(key.UserIDs))
	c.Assert(1, gc.Equals, len(key.UserIDs[0].Signatures))
	c.Assert(1, gc.Equals, hits[14 /*P.PacketTypePublicSubkey*/])
	c.Assert(1, gc.Equals, len(key.Subkeys[0].Signatures))
	c.Assert(4, gc.Equals, len(hits))
}
