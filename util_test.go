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
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/crypto/openpgp/armor"
	gc "gopkg.in/check.v1"
)

func MustInput(c *gc.C, name string) *os.File {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		c.Fatal("cannot locate unit test data files")
	}
	path := filepath.Join(filepath.Dir(thisFile), "testdata", name)
	f, err := os.Open(path)
	if err != nil {
		c.Fatalf("cannot open unit test data file %q: %v", path, err)
	}
	return f
}

func MustInputAscKeys(c *gc.C, name string) []*Pubkey {
	f := MustInput(c, name)
	defer f.Close()
	block, err := armor.Decode(f)
	c.Assert(err, gc.IsNil)

	var result []*Pubkey
	for keyRead := range ReadKeys(block.Body) {
		c.Assert(keyRead.Error, gc.IsNil)
		result = append(result, keyRead.Pubkey)
	}
	return result
}

func MustInputAscKey(c *gc.C, name string) *Pubkey {
	keys := MustInputAscKeys(c, name)
	if len(keys) != 1 {
		c.Fatalf("expected one key, got %d", len(keys))
	}
	return keys[0]
}
