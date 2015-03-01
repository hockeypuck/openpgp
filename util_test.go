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
	"fmt"

	"github.com/hockeypuck/testing"
)

func MustInputAscKeys(name string) []*PrimaryKey {
	return MustReadArmorKeys(testing.MustInput(name)).MustParse()
}

func MustInputAscKey(name string) *PrimaryKey {
	keys := MustInputAscKeys(name)
	if len(keys) != 1 {
		panic(fmt.Errorf("expected one key, got %d", len(keys)))
	}
	return keys[0]
}
