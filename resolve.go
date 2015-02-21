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
	"gopkg.in/errgo.v1"
)

func DropDuplicates(root packetNode) error {
	return dedup(root, nil)
}

func CollectDuplicates(root packetNode) error {
	return dedup(root, func(primary, _ packetNode) {
		primary.packet().Count++
	})
}

func Merge(dst, src *Pubkey) error {
	dst.UserIDs = append(dst.UserIDs, src.UserIDs...)
	dst.UserAttributes = append(dst.UserAttributes, src.UserAttributes...)
	dst.Subkeys = append(dst.Subkeys, src.Subkeys...)
	dst.Others = append(dst.Others, src.Others...)
	return dedup(dst, func(primary, duplicate packetNode) {
		primaryPacket := primary.packet()
		duplicatePacket := duplicate.packet()
		if duplicatePacket.Count > primaryPacket.Count {
			primaryPacket.Count = duplicatePacket.Count
		}
	})
}

func dedup(root packetNode, handleDuplicate func(primary, duplicate packetNode)) error {
	nodes := map[string]packetNode{}

	for _, node := range root.contents() {
		primary, ok := nodes[node.uuid()]
		if ok {
			err := primary.removeDuplicate(root, node)
			if err != nil {
				return errgo.Mask(err)
			}

			err = dedup(primary, nil)
			if err != nil {
				return errgo.Mask(err)
			}

			if handleDuplicate != nil {
				handleDuplicate(primary, node)
			}
		} else {
			nodes[node.uuid()] = node
		}
	}
	return nil
}
