// Copyright 2018 The go-hpb Authors
// This file is part of the go-hpb.
//
// The go-hpb is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-hpb is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-hpb. If not, see <http://www.gnu.org/licenses/>.

// bootnode runs a bootstrap node for the HPB Discovery Protocol.
package main

import (
	"crypto/ecdsa"
	"flag"
	"fmt"
	"os"

	"github.com/hpb-project/go-hpb/cmd/utils"
	"github.com/hpb-project/go-hpb/crypto"
	"github.com/hpb-project/go-hpb/log"
	"github.com/hpb-project/go-hpb/p2p/discover"
	"github.com/hpb-project/go-hpb/p2p/nat"
	"github.com/hpb-project/go-hpb/p2p/netutil"
)

func main() {
	var (
		listenAddr  = flag.String("addr", ":30301", "listen address for find light nodes")
		genKey      = flag.String("genkey", "", "generate a node key")
		Role        = flag.Uint("role", uint(discover.LightRole), "role type of node")
		writeAddr   = flag.Bool("writeaddress", false, "write out the node's pubkey hash and quit")
		nodeKeyFile = flag.String("nodekey", "", "private key filename")
		nodeKeyHex  = flag.String("nodekeyhex", "", "private key as hex (for testing)")
		natdesc     = flag.String("nat", "none", "port mapping mechanism (any|none|upnp|pmp|extip:<IP>)")
		netrestrict = flag.String("netrestrict", "", "restrict network communication to the given IP networks (CIDR masks)")
		verbosity   = flag.Int("verbosity", int(log.LvlInfo), "log verbosity (0-9)")
		vmodule     = flag.String("vmodule", "", "log verbosity pattern")

		nodeKey *ecdsa.PrivateKey
		err     error
	)
	flag.Parse()

	glogger := log.NewGlogHandler(log.StreamHandler(os.Stderr, log.TerminalFormat(false)))
	glogger.Verbosity(log.Lvl(*verbosity))
	glogger.Vmodule(*vmodule)
	log.Root().SetHandler(glogger)

	natm, err := nat.Parse(*natdesc)
	if err != nil {
		utils.Fatalf("-nat: %v", err)
	}
	switch {
	case *genKey != "":
		nodeKey, err = crypto.GenerateKey()
		if err != nil {
			utils.Fatalf("could not generate key: %v", err)
		}
		if err = crypto.SaveECDSA(*genKey, nodeKey); err != nil {
			utils.Fatalf("%v", err)
		}
		return
	case *nodeKeyFile == "" && *nodeKeyHex == "":
		utils.Fatalf("Use -nodekey or -nodekeyhex to specify a private key")
	case *nodeKeyFile != "" && *nodeKeyHex != "":
		utils.Fatalf("Options -nodekey and -nodekeyhex are mutually exclusive")
	case *nodeKeyFile != "":
		if nodeKey, err = crypto.LoadECDSA(*nodeKeyFile); err != nil {
			utils.Fatalf("-nodekey: %v", err)
		}
	case *nodeKeyHex != "":
		if nodeKey, err = crypto.HexToECDSA(*nodeKeyHex); err != nil {
			utils.Fatalf("-nodekeyhex: %v", err)
		}
	}

	if *writeAddr {
		fmt.Printf("%v\n", discover.PubkeyID(&nodeKey.PublicKey))
		os.Exit(0)
	}

	var restrictList *netutil.Netlist
	if *netrestrict != "" {
		restrictList, err = netutil.ParseNetlist(*netrestrict)
		if err != nil {
			utils.Fatalf("-netrestrict: %v", err)
		}
	}

	if ga, err := discover.ListenUDP(nodeKey, uint8(*Role), *listenAddr, natm, "", restrictList); err != nil {
		utils.Fatalf("%v", err)
	} else {// else only for test
/*
		var bootnodesTestString = []string{
			// HPB Foundation Go Bootnodes Test
			"enode://6d30b0cae23373449382e76e5a92cba8a096d0c7259cf6160b747e5cf80aa595842da75e44e650465a227ae7179382d47fbba05446c19d28b7c923ca9b3d71bc&1@127.0.0.1:10001",
			"enode://af1ee4d6883a08a040fb2417612ce67700a0729b40ac814de6a86ec713648be0ee4c033c059452f6f9d67e2129eb57b692d90212d2496939585d139771d6a169&1@127.0.0.1:10002",
		}
		var bootnodesTest []*discover.Node
		for _, url := range bootnodesTestString {
			node, err := discover.ParseNode(url)
			if err != nil {
				log.Error("Bootstrap URL invalid", "enode", url, "err", err)
				continue
			}
			bootnodesTest = append(bootnodesTest, node)
			log.Info("discover -> TABLE", "SetFallbackNodes ", node)
		}

		var commnodesTestString = []string{
			// HPB Foundation Go Commnodes Test
			"enode://8cd1606884c0f90e97f1080a11d7f395284c821b069ce20ee449acfca9187dcdefe276a57ca25928f46cb2cfc6f2b1725256106c0fe53ddfdf83f943f821278a&4@127.0.0.1:40001",
			"enode://19b7f434d3d4b78d242fc071f88629d45ea41e58ef0ac015f7603100bf5a4e268886b4629d5e8bf102504ac15e3bb02e043b16e2410e7ed55739a8e36237c727&4@127.0.0.1:40002",
		}
		var commnodesTest []*discover.Node
		for _, url := range commnodesTestString {
			node, err := discover.ParseNode(url)
			if err != nil {
				log.Error("Bootstrap URL invalid", "enode", url, "err", err)
				continue
			}
			commnodesTest = append(commnodesTest, node)
			log.Info("discover -> SLICE", "SetFallbackNodes ", node)
		}

		var precommnodesTestString = []string{
			// HPB Foundation Go PreCommnodes Test
			"enode://185540bc1099600e467bc7f71e05cd333c8109d7a16c92df2ec308b4e946bb55eba64819267b9817d272f0213eb4241ca6dcbdf68775e62d38e7c5ce8286d0a1&5@127.0.0.1:50001",
			"enode://29518f507dac57b69e74a8c41abdb4531a90b31075000ee4cd33504284b19f099d23cd1ee46a3be08e1dca2d57fc458e96fdb2182c438c62c80fa52e2392cb1b&5@127.0.0.1:50002",
		}
		var precommnodesTest []*discover.Node
		for _, url := range precommnodesTestString {
			node, err := discover.ParseNode(url)
			if err != nil {
				log.Error("Bootstrap URL invalid", "enode", url, "err", err)
				continue
			}
			precommnodesTest = append(precommnodesTest, node)
			log.Info("discover -> SLICE", "SetFallbackNodes ", node)
		}

		//if err := ga.LightTab.SetFallbackNodes(bootnodesTest); err != nil {
		//	return
		//}
		//if err := ga.AccessTab.SetFallbackNodes(bootnodesTest); err != nil {
		//	return
		//}
		if err := ga.CommSlice.SetFallbackNodes(commnodesTest); err != nil {
			return
		}
		//if err := ga.PreCommSlice.SetFallbackNodes(precommnodesTest); err != nil {
		//	return
		//}
*/
	}

	select {}
}
