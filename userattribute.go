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

type UserAttribute struct {
	Packet

	Images [][]byte

	Signatures []*Signature
	Others     []*Packet
}

const uatTag = "{uat}"

// contents implements the packetNode interface for user attributes.
func (uat *UserAttribute) contents() []packetNode {
	result := []packetNode{uat}
	for _, sig := range uat.Signatures {
		result = append(result, sig.contents()...)
	}
	for _, p := range uat.Others {
		result = append(result, p.contents()...)
	}
	return result
}

// appendSignature implements signable.
func (uat *UserAttribute) appendSignature(sig *Signature) {
	uat.Signatures = append(uat.Signatures, sig)
}

func (uat *UserAttribute) removeDuplicate(parent packetNode, dup packetNode) error {
	pubkey, ok := parent.(*PrimaryKey)
	if !ok {
		return errgo.Newf("invalid uat parent: %+v", parent)
	}
	dupUserAttribute, ok := dup.(*UserAttribute)
	if !ok {
		return errgo.Newf("invalid uat duplicate: %+v", dup)
	}

	uat.Signatures = append(uat.Signatures, dupUserAttribute.Signatures...)
	uat.Others = append(uat.Others, dupUserAttribute.Others...)
	pubkey.UserAttributes = uatSlice(pubkey.UserAttributes).without(dupUserAttribute)
	return nil
}

type uatSlice []*UserAttribute

func (us uatSlice) without(target *UserAttribute) []*UserAttribute {
	var result []*UserAttribute
	for _, uat := range us {
		if uat != target {
			result = append(result, uat)
		}
	}
	return result
}

func ParseUserAttribute(op *packet.OpaquePacket, parentID string) (*UserAttribute, error) {
	var buf bytes.Buffer
	if err := op.Serialize(&buf); err != nil {
		return nil, errgo.Mask(err)
	}
	uat := &UserAttribute{
		Packet: Packet{
			UUID:   scopedDigest([]string{parentID}, uatTag, buf.Bytes()),
			Tag:    op.Tag,
			Packet: buf.Bytes(),
		},
	}

	u, err := uat.userAttributePacket()
	if err != nil {
		return nil, errgo.WithCausef(err, ErrInvalidPacketType, "")
	}

	uat.Images = u.ImageData()
	uat.Parsed = true
	return uat, nil
}

func (uat *UserAttribute) userAttributePacket() (*packet.UserAttribute, error) {
	op, err := uat.opaquePacket()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	p, err := op.Parse()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	u, ok := p.(*packet.UserAttribute)
	if !ok {
		return nil, errgo.Newf("expected user attribute packet, got %T", p)
	}
	return u, nil
}

func (uat *UserAttribute) SelfSigs(pubkey *PrimaryKey) *SelfSigs {
	result := &SelfSigs{target: uat}
	for _, sig := range uat.Signatures {
		// Skip non-self-certifications.
		if !strings.HasPrefix(pubkey.UUID, sig.RIssuerKeyID) {
			continue
		}
		checkSig := &CheckSig{
			PrimaryKey: pubkey,
			Signature:  sig,
			Error:      pubkey.verifyUserAttrSelfSig(uat, sig),
		}
		if checkSig.Error != nil {
			result.Errors = append(result.Errors, checkSig)
			continue
		}
		switch sig.SigType {
		case 0x30: // packet.SigTypeCertRevocation
			result.Revocations = append(result.Revocations, checkSig)
		case 0x10, 0x11, 0x12, 0x13:
			result.Certifications = append(result.Certifications, checkSig)
			if !sig.Expiration.IsZero() {
				result.Expirations = append(result.Expirations, checkSig)
			}
			if sig.Primary {
				result.Primaries = append(result.Primaries, checkSig)
			}
		}
	}
	result.resolve()
	return result
}
