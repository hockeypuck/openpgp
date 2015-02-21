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
	"encoding/binary"
	"encoding/hex"
	"time"

	"golang.org/x/crypto/openpgp/packet"
	"gopkg.in/errgo.v1"

	"github.com/hockeypuck/hockeypuck/util"
)

type Signature struct {
	Packet

	SigType      int
	RIssuerKeyID string
	Creation     time.Time
	Expiration   time.Time
	Primary      bool
}

const sigTag = "{sig}"

// contents implements the packetNode interface for default unclassified packets.
func (sig *Signature) contents() []packetNode {
	return []packetNode{sig}
}

func (sig *Signature) removeDuplicate(parent packetNode, dup packetNode) error {
	dupSig, ok := dup.(*Signature)
	if !ok {
		return errgo.Newf("invalid packet duplicate: %+v", dup)
	}
	switch ppkt := parent.(type) {
	case *Pubkey:
		ppkt.Signatures = sigSlice(ppkt.Signatures).without(dupSig)
	case *Subkey:
		ppkt.Signatures = sigSlice(ppkt.Signatures).without(dupSig)
	case *UserID:
		ppkt.Signatures = sigSlice(ppkt.Signatures).without(dupSig)
	case *UserAttribute:
		ppkt.Signatures = sigSlice(ppkt.Signatures).without(dupSig)
	}
	return nil
}

type sigSlice []*Signature

func (ss sigSlice) without(target *Signature) []*Signature {
	var result []*Signature
	for _, sig := range ss {
		if sig != target {
			result = append(result, sig)
		}
	}
	return result
}

func ParseSignature(op *packet.OpaquePacket, pubkeyUUID, scopedUUID string) (*Signature, error) {
	var buf bytes.Buffer
	var err error

	if err = op.Serialize(&buf); err != nil {
		return nil, errgo.Mask(err)
	}
	sig := &Signature{
		Packet: Packet{
			UUID:   scopedDigest([]string{pubkeyUUID, scopedUUID}, sigTag, buf.Bytes()),
			Tag:    op.Tag,
			Packet: buf.Bytes(),
		},
	}

	// Attempt to parse the opaque packet into a public key type.
	err = sig.parse(op)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	sig.Valid = true
	return sig, nil
}

func (sig *Signature) parse(op *packet.OpaquePacket) error {
	p, err := op.Parse()
	if err != nil {
		return errgo.Mask(err)
	}

	switch s := p.(type) {
	case *packet.Signature:
		return sig.setSignature(s)
	case *packet.SignatureV3:
		return sig.setSignatureV3(s)
	}
	return errgo.Mask(ErrInvalidPacketType, errgo.Any)
}

func (sig *Signature) setSignature(s *packet.Signature) error {
	if s.IssuerKeyId == nil {
		return errgo.New("missing issuer key ID")
	}
	sig.Creation = s.CreationTime
	sig.SigType = int(s.SigType)

	// Extract the issuer key id
	var issuerKeyId [8]byte
	if s.IssuerKeyId != nil {
		binary.BigEndian.PutUint64(issuerKeyId[:], *s.IssuerKeyId)
		sigKeyId := hex.EncodeToString(issuerKeyId[:])
		sig.RIssuerKeyID = util.Reverse(sigKeyId)
	}

	// Expiration time
	if s.SigLifetimeSecs != nil {
		sig.Expiration = s.CreationTime.Add(
			time.Duration(*s.SigLifetimeSecs) * time.Second)
	} else if s.KeyLifetimeSecs != nil {
		sig.Expiration = s.CreationTime.Add(
			time.Duration(*s.KeyLifetimeSecs) * time.Second)
	}

	// Primary indicator
	sig.Primary = s.IsPrimaryId != nil && *s.IsPrimaryId

	return nil
}

func (sig *Signature) setSignatureV3(s *packet.SignatureV3) error {
	sig.Creation = s.CreationTime
	// V3 packets do not have an expiration time
	sig.SigType = int(s.SigType)
	// Extract the issuer key id
	var issuerKeyId [8]byte
	binary.BigEndian.PutUint64(issuerKeyId[:], s.IssuerKeyId)
	sigKeyId := hex.EncodeToString(issuerKeyId[:])
	sig.RIssuerKeyID = util.Reverse(sigKeyId)
	return nil
}

func (sig *Signature) signaturePacket() (*packet.Signature, error) {
	op, err := sig.opaquePacket()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	p, err := op.Parse()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	s, ok := p.(*packet.Signature)
	if !ok {
		return nil, errgo.Newf("expected signature packet, got %T", p)
	}
	return s, nil
}

func (sig *Signature) signatureV3Packet() (*packet.SignatureV3, error) {
	op, err := sig.opaquePacket()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	p, err := op.Parse()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	s, ok := p.(*packet.SignatureV3)
	if !ok {
		return nil, errgo.Newf("expected signature V3 packet, got %T", p)
	}
	return s, nil
}
