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
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"sort"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"gopkg.in/errgo.v1"

	log "gopkg.in/hockeypuck/logrus.v0"
)

var ErrMissingSignature = fmt.Errorf("Key material missing an expected signature")

func WritePackets(w io.Writer, key *PrimaryKey) error {
	for _, node := range key.contents() {
		op, err := newOpaquePacket(node.packet().Packet)
		if err != nil {
			return errgo.Mask(err)
		}
		err = op.Serialize(w)
		if err != nil {
			return errgo.Mask(err)
		}
	}
	return nil
}

func WriteArmoredPackets(w io.Writer, roots []*PrimaryKey) error {
	armw, err := armor.Encode(w, openpgp.PublicKeyType, nil)
	defer armw.Close()
	if err != nil {
		return errgo.Mask(err)
	}
	for _, node := range roots {
		err = WritePackets(armw, node)
		if err != nil {
			return errgo.Mask(err)
		}
	}
	return nil
}

type OpaqueKeyring struct {
	Packets      []*packet.OpaquePacket
	RFingerprint string
	Md5          string
	Sha256       string
	Error        error
	Position     int64
}

func (okr *OpaqueKeyring) setPosition(r io.Reader) {
	f, ok := r.(*os.File)
	if ok {
		pos, err := f.Seek(0, 1)
		if err == nil {
			okr.Position = pos
			return
		}
	}
	okr.Position = -1
}

func (ok *OpaqueKeyring) Parse() (*PrimaryKey, error) {
	var err error
	var pubkey *PrimaryKey
	var signablePacket signable
	for _, opkt := range ok.Packets {
		var badPacket *packet.OpaquePacket
		if opkt.Tag == 6 { //packet.PacketTypePublicKey:
			if pubkey != nil {
				return nil, errgo.Newf("multiple public keys in keyring")
			}
			pubkey, err = ParsePrimaryKey(opkt)
			if err != nil {
				return nil, errgo.Notef(err, "invalid public key packet type")
			}
			signablePacket = pubkey
		} else if pubkey != nil {
			switch opkt.Tag {
			case 14: //packet.PacketTypePublicSubKey:
				signablePacket = nil
				subkey, err := ParseSubKey(opkt)
				if err != nil {
					log.Debugf("unreadable subkey packet: %v", err)
					badPacket = opkt
				} else {
					pubkey.SubKeys = append(pubkey.SubKeys, subkey)
					signablePacket = subkey
				}
			case 13: //packet.PacketTypeUserId:
				signablePacket = nil
				uid, err := ParseUserID(opkt, pubkey.UUID)
				if err != nil {
					log.Debugf("unreadable user id packet: %v", err)
					badPacket = opkt
				} else {
					pubkey.UserIDs = append(pubkey.UserIDs, uid)
					signablePacket = uid
				}
			case 17: //packet.PacketTypeUserAttribute:
				signablePacket = nil
				uat, err := ParseUserAttribute(opkt, pubkey.UUID)
				if err != nil {
					log.Debugf("unreadable user attribute packet: %v", err)
					badPacket = opkt
				} else {
					pubkey.UserAttributes = append(pubkey.UserAttributes, uat)
					signablePacket = uat
				}
			case 2: //packet.PacketTypeSignature:
				if signablePacket == nil {
					log.Debugf("signature out of context")
					badPacket = opkt
				} else {
					sig, err := ParseSignature(opkt, pubkey.UUID, signablePacket.uuid())
					if err != nil {
						log.Debugf("unreadable signature packet: %v", err)
						badPacket = opkt
					} else {
						signablePacket.appendSignature(sig)
					}
				}
			default:
				badPacket = opkt
			}

			if badPacket != nil {
				var badParent string
				if signablePacket != nil {
					badParent = signablePacket.uuid()
				} else {
					badParent = pubkey.uuid()
				}
				other, err := ParseOther(badPacket, badParent)
				if err != nil {
					return nil, errgo.Mask(err)
				}
				pubkey.Others = append(pubkey.Others, other)
			}
		}
	}
	if pubkey == nil {
		return nil, errgo.New("primary public key not found")
	}
	pubkey.MD5, err = SksDigest(pubkey, md5.New())
	if err != nil {
		return nil, err
	}
	return pubkey, nil
}

type OpaqueKeyringChan chan *OpaqueKeyring

func ReadOpaqueKeyrings(r io.Reader) OpaqueKeyringChan {
	c := make(OpaqueKeyringChan)
	or := packet.NewOpaqueReader(r)
	go func() {
		defer close(c)
		var op *packet.OpaquePacket
		var err error
		var current *OpaqueKeyring
		for op, err = or.Next(); err == nil; op, err = or.Next() {
			switch op.Tag {
			case 6: //packet.PacketTypePublicKey:
				if current != nil {
					c <- current
					current = nil
				}
				current = &OpaqueKeyring{}
				current.setPosition(r)
				fallthrough
			case 2, 13, 14, 17:
				//packet.PacketTypeUserId,
				//packet.PacketTypeUserAttribute,
				//packet.PacketTypePublicSubKey,
				//packet.PacketTypeSignature
				if current != nil {
					current.Packets = append(current.Packets, op)
				}
			}
		}
		if err == io.EOF && current != nil {
			c <- current
		} else if err != nil {
			if current == nil {
				current = &OpaqueKeyring{}
			}
			current.Error = errgo.Mask(err)
			c <- current
		}
	}()
	return c
}

// SksDigest calculates a cumulative message digest on all OpenPGP packets for
// a given primary public key, using the same ordering as SKS, the
// Synchronizing Key Server. Use MD5 for matching digest values with SKS.
func SksDigest(key *PrimaryKey, h hash.Hash) (string, error) {
	var fail string
	var packets opaquePacketSlice
	for _, node := range key.contents() {
		op, err := newOpaquePacket(node.packet().Packet)
		if err != nil {
			return fail, errgo.Mask(err)
		}
		packets = append(packets, op)
	}
	if len(packets) == 0 {
		return fail, errgo.New("no packets found")
	}
	return sksDigestOpaque(packets, h), nil
}

func sksDigestOpaque(packets []*packet.OpaquePacket, h hash.Hash) string {
	sort.Sort(opaquePacketSlice(packets))
	for _, opkt := range packets {
		binary.Write(h, binary.BigEndian, int32(opkt.Tag))
		binary.Write(h, binary.BigEndian, int32(len(opkt.Contents)))
		h.Write(opkt.Contents)
	}
	return hex.EncodeToString(h.Sum(nil))
}

type ReadKeyResult struct {
	*PrimaryKey
	Error error
}

type PrimaryKeyChan chan *ReadKeyResult

func (c PrimaryKeyChan) MustParse() []*PrimaryKey {
	var result []*PrimaryKey
	for readKey := range c {
		if readKey.Error != nil {
			panic(readKey.Error)
		}
		result = append(result, readKey.PrimaryKey)
	}
	return result
}

// ReadKeys reads public key material from input and sends them on a channel.
// Caller must receive all keys until the channel is closed.
func ReadKeys(r io.Reader) PrimaryKeyChan {
	c := make(PrimaryKeyChan)
	go func() {
		defer close(c)
		for keyRead := range readKeys(r) {
			c <- keyRead
		}
		if closer, ok := r.(io.Closer); ok {
			closer.Close()
		}
	}()
	return c
}

func readKeys(r io.Reader) PrimaryKeyChan {
	c := make(PrimaryKeyChan)
	go func() {
		defer close(c)
		for opkr := range ReadOpaqueKeyrings(r) {
			pubkey, err := opkr.Parse()
			if err != nil {
				c <- &ReadKeyResult{Error: err}
			} else {
				c <- &ReadKeyResult{PrimaryKey: pubkey}
			}
		}
	}()
	return c
}

func ReadArmorKeys(r io.Reader) (PrimaryKeyChan, error) {
	block, err := armor.Decode(r)
	if err != nil {
		return nil, err
	}
	return ReadKeys(block.Body), nil
}

func MustReadArmorKeys(r io.Reader) PrimaryKeyChan {
	c, err := ReadArmorKeys(r)
	if err != nil {
		panic(err)
	}
	return c
}
