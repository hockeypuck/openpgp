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

	"github.com/hockeypuck/testing"
)

func MustInputAscKeys(c *gc.C, name string) []*Pubkey {
	return MustReadArmorKeys(testing.MustInput(c, name)).MustParse()
}

func MustInputAscKey(c *gc.C, name string) *Pubkey {
	keys := MustInputAscKeys(c, name)
	if len(keys) != 1 {
		c.Fatalf("expected one key, got %d", len(keys))
	}
	return keys[0]
}
