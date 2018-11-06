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

package types

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/crypto"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/boe"
	"github.com/hpb-project/go-hpb/common/log"
	"encoding/hex"
	"time"
	"sync"
)

var (
	ErrInvalidChainId = errors.New("invalid chain id for signer")
	//ErrInvalidAsynsinger = errors.New("just callback Asyn Send OK for signer")
)

// SigCache is used to cache the derived sender and contains
// the signer used to derive it.
type SigCache struct {
	Casigner Signer
	Cafrom   common.Address
}



type Smap struct {
	Data  map[common.Hash]common.Address                /*验证返回结果*/
	WaitsingerTx map[common.Hash]*Transaction     /*原始交易*/
	WaitsingerTxbeats  map[common.Hash]time.Time        /*交易发送时间*/
	SendFlag map[common.Hash]bool                       /*以发送验证为True*/
	//	ChannelType map[common.Hash]int						/* 1 :synblock trans 2 :client trans 3 :验证通过 4:交易失败 5：clieng同步等待返回中 6 :交易完成 7 :验证失败*/
	L sync.RWMutex
}

var (
	//	Asynsinger = &Smap{Data:make(map[common.Hash]common.Address),WaitsingerTx:make(map[common.Hash]*types.Transaction),WaitsingerTxbeats:make(map[common.Hash]time.Time),SendFlag:make(map[common.Hash]bool),ChannelType:make(map[common.Hash]int)}
	Asynsinger = &Smap{Data:make(map[common.Hash]common.Address),WaitsingerTx:make(map[common.Hash]*Transaction),WaitsingerTxbeats:make(map[common.Hash]time.Time),SendFlag:make(map[common.Hash]bool)}
	ChanAsynsinger =  make(chan boe.RecoverPubkey)
)


// MakeSigner returns a Signer based on the given chain config and block number.
func MakeSigner(config *config.ChainConfig) Signer {
	return NewBoeSigner(config.ChainId)
}

// SignTx signs the transaction using the given signer and private key
func SignTx(tx *Transaction, s Signer, prv *ecdsa.PrivateKey) (*Transaction, error) {
	h := s.Hash(tx)
	sig, err := crypto.Sign(h[:], prv)
	if err != nil {
		return nil, err
	}
	return tx.WithSignature(s, sig)
}

// Sender returns the address derived from the signature (V, R, S) using secp256k1
// elliptic curve and an error if it failed deriving or upon an incorrect
// signature.
//
// Sender may cache the address, allowing it to be used regardless of
// signing method. The cache is invalidated if the cached signer does
// not match the signer used in the current call.
func Sender(signer Signer, tx *Transaction) (common.Address, error) {
	//if (tx.from.Load() != nil && reflect.TypeOf(tx.from.Load()) == reflect.TypeOf(common.Address{}) && tx.from.Load().(common.Address) != common.Address{}) {
	//	return tx.from.Load().(common.Address), nil
	//}
	if sc := tx.from.Load(); sc != nil {
		SigCache := sc.(SigCache)
		// If the signer used to derive from in a previous
		// call is not the same as used current, invalidate
		// the cache.2
		if SigCache.Casigner.Equal(signer) {
			return SigCache.Cafrom, nil
		}
	}
    log.Info("Sender hanxiaole 11111111111111111 send ","tx.hash",tx.Hash(),"signer.Hash(tx)",signer.Hash(tx))
	addr, err := signer.Sender(tx)
	if err != nil {
		return common.Address{}, err
	}
	tx.from.Store(SigCache{Casigner: signer, Cafrom: addr})
	return addr, nil
}
func ASynSender(signer Signer, tx *Transaction) (common.Address, error) {

	log.Info("hanxiaole test SMapGet(Asynsinger,signer.Hash(tx))","signer.Hash(tx)",signer.Hash(tx),"tx.Hash()",tx.Hash())

	asynAddress ,err:= SMapGetAddress(Asynsinger,signer.Hash(tx))
	if err == nil{
		log.Info("hanxiaole test ASynSender reASyn SMapGet()  ","common.Address",asynAddress,"signer.Hash(tx)",signer.Hash(tx),"tx.hash",tx.Hash())
		/*SMapGet success and set SigCache value*/
		tx.from.Store(SigCache{Casigner: signer, Cafrom: asynAddress})
		return asynAddress,nil
	}

	log.Info("hanxiaole tx.from.Load()","tx.Hash()",tx.Hash(),"signer.Hash(tx)",signer.Hash(tx))
	if sc := tx.from.Load(); sc != nil {
		SigCache := sc.(SigCache)
		// If the signer used to derive from in a previous
		// call is not the same as used current, invalidate
		// the cache.2
		if SigCache.Casigner.Equal(signer) {
			log.Info("hanxiaole test ASynSender reASyn tx.from.Load() OKOKOK ","SigCache.from",SigCache.Cafrom,"tx.Hash()",tx.Hash())
			return SigCache.Cafrom, nil
		}
	}
    /*先可取，无可发*/
	sendFlag, errsend := SMapGetSendFlag(Asynsinger,signer.Hash(tx))
	if sendFlag == true && errsend == nil{
		log.Info("重复发送!!!!!!!!!!!","signer.Hash(tx)",signer.Hash(tx),"tx.Hash()",tx.Hash())
		return common.Address{}, errors.New("resend tx error")
	}

	terr := SMapSetWaitsingerTx(Asynsinger,signer.Hash(tx),tx)
	if terr != nil{
		log.Info("SMapSetWaitsingerTx error ")
		return common.Address{}, errors.New("SMapSetWaitsingerTx error")
	}

	terr1 := SMapSetWaitsingerTxbeats(Asynsinger,signer.Hash(tx),time.Now())
	if terr1 != nil{
		log.Info("SMapSetWaitsingerTxbeats error ")
		return common.Address{}, errors.New("SMapSetWaitsingerTxbeats error")
	}

	sandbag := SMapSetSendFlag(Asynsinger,signer.Hash(tx),true)
	if sandbag != nil{
		log.Info("SMapSetSendFlag error ")
		return common.Address{}, errors.New("SMapSetSendFlag error")
	}

	/* save signer */
	tx.from.Store(SigCache{Casigner: signer, Cafrom: common.Address{}})
	/*
	if txpool.Asynsinger.WaitsingerTx[signer.Hash(tx)] == nil {
		txpool.Asynsinger.WaitsingerTx[signer.Hash(tx)] = tx
	}

	txpool.Asynsinger.WaitsingerTxbeats[signer.Hash(tx)] = time.Now()
	*/
	addr, err := signer.ASynSender(tx)
	if err != nil {
		return common.Address{}, err
	}
	return addr, nil
}
// Signer encapsulates transaction signature handling. Note that this interface is not a
// stable API and may change at any time to accommodate new protocol rules.
type Signer interface {
	// Sender returns the sender address of the transaction.
	Sender(tx *Transaction) (common.Address, error)
	ASynSender(tx *Transaction) (common.Address, error)
	// SignatureValues returns the raw R, S, V values corresponding to the
	// given signature.
	SignatureValues(tx *Transaction, sig []byte) (r, s, v *big.Int, err error)
	// Hash returns the hash to be signed.
	Hash(tx *Transaction) common.Hash
	// Equal returns true if the given signer is the same as the receiver.
	Equal(Signer) bool
}

// EIP155Transaction implements Signer using the EIP155 rules.
type BoeSigner struct {
	chainId, chainIdMul *big.Int
}

func NewBoeSigner(chainId *big.Int) BoeSigner {
	if chainId == nil {
		chainId = new(big.Int)
	}

	return BoeSigner{
		chainId:    chainId,
		chainIdMul: new(big.Int).Mul(chainId, big.NewInt(2)),
	}
}

func (s BoeSigner) Equal(s2 Signer) bool {
	eip155, ok := s2.(BoeSigner)
	return ok && eip155.chainId.Cmp(s.chainId) == 0
}

var big8 = big.NewInt(8)

func (s BoeSigner) Sender(tx *Transaction) (common.Address, error) {
	if !tx.Protected() {
		//return HomesteadSigner{}.Sender(tx)
		//TODO transaction can be unprotected ?
	}
	if tx.ChainId().Cmp(s.chainId) != 0 {
		return common.Address{}, ErrInvalidChainId
	}
	V := new(big.Int).Sub(tx.data.V, s.chainIdMul)
	V.Sub(V, big8)
	return recoverPlain(s.Hash(tx), tx.data.R, tx.data.S, V)
}

func (s BoeSigner) ASynSender(tx *Transaction) (common.Address, error) {
	if !tx.Protected() {
		//return HomesteadSigner{}.Sender(tx)
		log.Info("tx.Protected() hanxiaole test 111111111111111111")
		//TODO transaction can be unprotected ?
	}
	if tx.ChainId().Cmp(s.chainId) != 0 {
		log.Info("tx.Protected() hanxiaole test 2222222222222222222")
		return common.Address{}, ErrInvalidChainId
	}
	V := new(big.Int).Sub(tx.data.V, s.chainIdMul)
	V.Sub(V, big8)
	log.Info("BoeSigner ASynSender  ASynrecoverPlain hanxiaole test  send ","tx.hash",tx.Hash())
	return ASynrecoverPlain(s.Hash(tx), tx.data.R, tx.data.S, V)
}
// WithSignature returns a new transaction with the given signature. This signature
// needs to be in the [R || S || V] format where V is 0 or 1.
func (s BoeSigner) SignatureValues(tx *Transaction, sig []byte) (R, S, V *big.Int, err error) {
	if len(sig) != 65 {
		panic(fmt.Sprintf("wrong size for signature: got %d, want 65", len(sig)))
	}
	R = new(big.Int).SetBytes(sig[:32])
	S = new(big.Int).SetBytes(sig[32:64])
	V = new(big.Int).SetBytes([]byte{sig[64] + 27})
	if s.chainId.Sign() != 0 {
		V = big.NewInt(int64(sig[64] + 35))
		V.Add(V, s.chainIdMul)
	}
	return R, S, V, nil
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s BoeSigner) Hash(tx *Transaction) common.Hash {
	return rlpHash([]interface{}{
		tx.data.AccountNonce,
		tx.data.Price,
		tx.data.GasLimit,
		tx.data.Recipient,
		tx.data.Amount,
		tx.data.Payload,
		s.chainId, uint(0), uint(0),
	})
}

func recoverPlain(sighash common.Hash, R, S, Vb *big.Int) (common.Address, error) {
	//if Vb.BitLen() > 8 {
	//	return common.Address{}, ErrInvalidSig
	//}
	//V := byte(Vb.Uint64() - 27)
	////TODO replace homestead param
	//if !crypto.ValidateSignatureValues(V, R, S, true) {
	//	return common.Address{}, ErrInvalidSig
	//}
	//// encode the snature in uncompressed format
	//r, s := R.Bytes(), S.Bytes()
	//// recover the public key from the snature
	////pub, err := crypto.Ecrecover(sighash[:], sig)
	////64 bytes public key returned.
	//pub, err := boe.BoeGetInstance().ValidateSign(sighash[:], r, s, V)
	////xInt, yInt := elliptic.Unmarshal(crypto.S256(), result)
	////pub := &ecdsa.PublicKey{Curve: crypto.S256(), X: xInt, Y: yInt}
	//if err != nil {
	//	return common.Address{}, err
	//}
	//if len(pub) == 0 { //|| pub[0] != 4
	//	return common.Address{}, errors.New("invalid public key")
	//}
	//var addr common.Address
	//copy(addr[:], crypto.Keccak256(pub[0:])[12:])
	//return addr, nil
	if Vb.BitLen() > 8 {
		return common.Address{}, ErrInvalidSig
	}
	V := byte(Vb.Uint64() - 27)
	if !crypto.ValidateSignatureValues(V, R, S, true) {
		return common.Address{}, ErrInvalidSig
	}



	// encode the snature in uncompressed format
	r, s := R.Bytes(), S.Bytes()
	//sig := make([]byte, 65)
	/*copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = V*/

	pub , err := boe.BoeGetInstance().ValidateSign(sighash.Bytes(), r, s, V)
	if err != nil {
		log.Trace("boe validatesign error")
		return common.Address{}, err
	}
	// recover the public key from the snature
	/*pub, err := crypto.Ecrecover(sighash[:], sig)
	if err != nil {
		return common.Address{}, err
	}*/
	if len(pub) == 0 || pub[0] != 4 {
		return common.Address{}, errors.New("invalid public key")
	}
	var addr common.Address
	copy(addr[:], crypto.Keccak256(pub[1:])[12:])
	log.Trace("boe validatesign success")
	return addr, nil
}


func ASynrecoverPlain(sighash common.Hash, R, S, Vb *big.Int) (common.Address, error) {

	if Vb.BitLen() > 8 {
		log.Info("ASynrecoverPlain Vb.BitLen() > 8 hanxiaole test 11111111111111")
		return common.Address{}, ErrInvalidSig
	}
	V := byte(Vb.Uint64() - 27)
	if !crypto.ValidateSignatureValues(V, R, S, true) {
		log.Info("ASynrecoverPlain !crypto.ValidateSignatureValues hanxiaole test 22222222222222222222")
		return common.Address{}, ErrInvalidSig
	}
	r, s := R.Bytes(), S.Bytes()

	log.Info("ASynrecoverPlain hanxiaole test ","hash",sighash,"hash.bytes",sighash.Bytes(),"send hash",hex.EncodeToString(sighash.Bytes()))

	err := boe.BoeGetInstance().ASyncValidateSign(sighash.Bytes(), r, s, V)
	if err != nil {
		log.Info("boe validatesign error 3333333333333333333333333")
		return common.Address{}, err
	}
	log.Info("ASynrecoverPlain ASynrecoverPlain hanxiaole end 444444444444444444444444")
	return common.Address{}, nil
}

// deriveChainId derives the chain id from the given v parameter
func deriveChainId(v *big.Int) *big.Int {
	if v.BitLen() <= 64 {
		v := v.Uint64()
		if v == 27 || v == 28 {
			return new(big.Int)
		}
		return new(big.Int).SetUint64((v - 35) / 2)
	}
	v = new(big.Int).Sub(v, big.NewInt(35))
	return v.Div(v, big.NewInt(2))
}
/*
func boecallback(rs boe.RecoverPubkey,err error) {
	if err != nil {
		log.Trace("boe validatesign error")
	}
	if len(rs.Pub) == 0 || rs.Pub[0] != 4 {
		log.Trace("invalid public key")
	}

	var addr = common.Address{}
	copy(addr[:], crypto.Keccak256(rs.Pub[1:])[12:])

	var sigtmp []byte
	copy(sigtmp[:], rs.Sig[0:])

	var  comhash common.Hash
	copy(comhash[:], rs.Hash[0:])

	errSet := SMapSet(Asynsinger,comhash,addr)
    if errSet !=nil{
    	log.Info("boecallback SMapSet error!")
	}
	log.Info("boe boecallback hanxiaole Store success","hash",comhash,"rs.hash",rs.Hash,"addr",addr)

}
*/



func SMapGetAddress(m *Smap, khash common.Hash) (common.Address,error){
	m.L.RLock()
	defer m.L.RUnlock()

	kvalue,ok := m.Data[khash]
	if ok != true {
		log.Info("SMapGetAddress hash values is null","m.Data[khash]",m.Data[khash])
		return common.Address{},errors.New("SMapGetAddress hash values is null")
	}

	log.Info("hanxiaole test SMapGetAddress input hash and kvalue","khash",khash,"kvalue",kvalue)
	return kvalue,nil
}

func SMapGetTx(m *Smap, khash common.Hash) (*Transaction,error){
	m.L.RLock()
	defer m.L.RUnlock()

	kvalue,ok := m.WaitsingerTx[khash]
	if ok != true {
		log.Info("SMapGetTx hash values is null","m.WaitsingerTx[khash]",m.WaitsingerTx[khash])
		return nil,errors.New("SMapGetTx hash values is null")
	}
	log.Info("hanxiaole test SMapGetTx input hash and kvalue","khash",khash,"kvalue",kvalue)
	return kvalue,nil
}

func SMapGetSendFlag(m *Smap, khash common.Hash) (bool,error){
	m.L.RLock()
	defer m.L.RUnlock()

	kvalue,ok := m.SendFlag[khash]
	if ok != true {
		log.Info("SMapGetSendFlag hash values is null","m.WaitsingerTxbeats[khash]",m.SendFlag[khash])
		return false,errors.New("SMapGetSendFlag hash values is null")
	}
	log.Info("hanxiaole test SMapGetSendFlag input hash and kvalue","khash",khash,"kvalue",kvalue)
	return kvalue,nil
}
/*
func SMapGetTxTime(m *Smap, khash common.Hash) (time.Time,error){
	m.L.RLock()
	defer m.L.RUnlock()

	kvalue,ok := m.WaitsingerTxbeats[khash]
	if ok != true {
		log.Info("SMapGetTxTime hash values is null","m.WaitsingerTxbeats[khash]",m.WaitsingerTxbeats[khash])
		return time.Now(),errors.New("SMapGetTxTime hash values is null")
	}
	log.Info("hanxiaole test SMapGetTxTime input hash and kvalue","khash",khash,"kvalue",kvalue)
	return kvalue,nil
}

func SMapGetChannelType(m *Smap, khash common.Hash) (int,error){
	m.L.RLock()
	defer m.L.RUnlock()

	kvalue,ok := m.ChannelType[khash]
	if ok != true {
		log.Info("SMapGetChannelType hash values is null","m.ChannelType[khash]",m.ChannelType[khash])
		return 0,errors.New("SMapGetChannelType hash values is null")
	}
	log.Info("hanxiaole test SMapGetChannelType input hash and kvalue","khash",khash,"kvalue",kvalue)
	return kvalue,nil
}
*/
func SMapSetAddress(m *Smap, khash common.Hash,kaddress common.Address) error {
	m.L.Lock()
	defer m.L.Unlock()
	m.Data[khash]=kaddress
	fromAddress,ok := m.Data[khash]
	if ok != true{
		return errors.New("SMapSetAddress hash values is null")
	}
	log.Info("hanxiaole SMapSetAddress","SMapSetAddress from",fromAddress,"hash",khash)
	return nil
}

func SMapSetWaitsingerTx(m *Smap, khash common.Hash,ptx *Transaction) error {
	m.L.Lock()
	defer m.L.Unlock()
	m.WaitsingerTx[khash]=ptx
	fromTx,ok := m.WaitsingerTx[khash]
	if ok != true{
		return errors.New("SMapSetWaitsingerTx hash values is null")
	}
	log.Info("hanxiaole SMapSetWaitsingerTx","SMapSetWaitsingerTx from Tx.Hash",fromTx.Hash())
	return nil
}

func SMapSetWaitsingerTxbeats(m *Smap, khash common.Hash,ttime time.Time) error {
	m.L.Lock()
	defer m.L.Unlock()
	m.WaitsingerTxbeats[khash]=ttime
	fromTime,ok := m.WaitsingerTxbeats[khash]
	if ok != true{
		return errors.New("SMapSetWaitsingerTxbeats hash values is null")
	}
	log.Info("hanxiaole SMapSetWaitsingerTxbeats","WaitsingerTxbeats from",fromTime)
	return nil
}

func SMapSetSendFlag(m *Smap, khash common.Hash,sendflag bool) error {
	m.L.Lock()
	defer m.L.Unlock()
	m.SendFlag[khash]=sendflag
	fromFlag,ok := m.SendFlag[khash]
	if ok != true{
		return errors.New("SMapSetSendFlag hash values is null")
	}
	log.Info("hanxiaole SMapSetSendFlag","SMapSetSendFlag from",fromFlag)
	return nil
}

/*
func SMapSetChannelType(m *Smap, khash common.Hash,channeltype int) error {
	m.L.Lock()
	defer m.L.Unlock()
	m.ChannelType[khash]=channeltype
	footie,ok := m.ChannelType[khash]
	if ok != true{
		return errors.New("SMapSetChannelType hash values is null")
	}
	log.Info("hanxiaole SMapSetChannelType","SMapSetChannelType footie", footie)
	return nil
}
*/
