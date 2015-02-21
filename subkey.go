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
	"strings"

	"golang.org/x/crypto/openpgp/packet"
	"gopkg.in/errgo.v1"
)

type Subkey struct {
	publicKeyPacket
}

// contents implements the packetNode interface for sub-keys.
func (subkey *Subkey) contents() []packetNode {
	result := []packetNode{subkey}
	for _, sig := range subkey.Signatures {
		result = append(result, sig.contents()...)
	}
	for _, p := range subkey.Others {
		result = append(result, p.contents()...)
	}
	return result
}

func ParseSubkey(op *packet.OpaquePacket) (*Subkey, error) {
	var buf bytes.Buffer
	var err error

	if err = op.Serialize(&buf); err != nil {
		return nil, errgo.Mask(err)
		panic("unable to write internal buffer")
	}
	subkey := &Subkey{
		publicKeyPacket: publicKeyPacket{
			Packet: Packet{
				Tag:    op.Tag,
				Packet: buf.Bytes(),
			},
		},
	}

	// Attempt to parse the opaque packet into a public key type.
	parseErr := subkey.parse(op, true)
	if parseErr != nil {
		subkey.setUnsupported(op)
	} else {
		subkey.Valid = true
	}

	return subkey, nil
}

func (subkey *Subkey) removeDuplicate(parent packetNode, dup packetNode) error {
	pubkey, ok := parent.(*Pubkey)
	if !ok {
		return errgo.Newf("invalid subkey parent: %+v", parent)
	}
	dupSubkey, ok := dup.(*Subkey)
	if !ok {
		return errgo.Newf("invalid subkey duplicate: %+v", dup)
	}

	subkey.Signatures = append(subkey.Signatures, dupSubkey.Signatures...)
	subkey.Others = append(subkey.Others, dupSubkey.Others...)
	pubkey.Subkeys = subkeySlice(pubkey.Subkeys).without(dupSubkey)
	return nil
}

type subkeySlice []*Subkey

func (ss subkeySlice) without(target *Subkey) []*Subkey {
	var result []*Subkey
	for _, subkey := range ss {
		if subkey != target {
			result = append(result, subkey)
		}
	}
	return result
}

func (subkey *Subkey) SelfSigs(pubkey *Pubkey) *SelfSigs {
	result := &SelfSigs{target: subkey}
	for _, sig := range subkey.Signatures {
		// Skip non-self-certifications.
		if !strings.HasPrefix(pubkey.UUID, sig.RIssuerKeyID) {
			continue
		}
		checkSig := &CheckSig{
			Pubkey:    pubkey,
			Signature: sig,
			Error:     pubkey.verifyPublicKeySelfSig(&subkey.publicKeyPacket, sig),
		}
		if checkSig.Error != nil {
			result.Errors = append(result.Errors, checkSig)
			continue
		}
		switch sig.SigType {
		case 0x28: // packet.SigTypeSubkeyRevocation
			result.Revocations = append(result.Revocations, checkSig)
		case 0x18: // packet.SigTypeSubkeyBinding
			result.Certifications = append(result.Certifications, checkSig)
			if !sig.Expiration.IsZero() {
				result.Expirations = append(result.Expirations, checkSig)
			}
		}
	}
	result.resolve()
	return result
}
