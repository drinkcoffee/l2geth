// Copyright 2023 Scroll / The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// This code is in large part a copy of Scroll's implementation: 
// https://github.com/scroll-tech/go-ethereum/blob/develop/core/logger_trace.go
package logger

import (
	"github.com/drinkcoffee/l2geth/common"
	"github.com/drinkcoffee/l2geth/common/hexutil"
	"github.com/drinkcoffee/l2geth/core/types"
	"github.com/drinkcoffee/l2geth/core/vm"
)

type traceFunc func(l *StructLogger, scope *vm.ScopeContext, extraData *types.ExtraData) error

var (
	// OpcodeExecs the map to load opcodes' trace funcs.
	OpcodeExecs = map[vm.OpCode][]traceFunc{
		vm.CALL:         {traceToAddressCode, traceLastNAddressCode(1), traceContractAccount, traceLastNAddressAccount(1)}, // contract account is the caller, stack.nth_last(1) is the callee's address
		vm.CALLCODE:     {traceToAddressCode, traceLastNAddressCode(1), traceContractAccount, traceLastNAddressAccount(1)}, // contract account is the caller, stack.nth_last(1) is the callee's address
		vm.DELEGATECALL: {traceToAddressCode, traceLastNAddressCode(1)},
		vm.STATICCALL:   {traceToAddressCode, traceLastNAddressCode(1), traceLastNAddressAccount(1)},
		vm.CREATE:       {}, // caller is already recorded in ExtraData.Caller, callee is recorded in CaptureEnter&CaptureExit
		vm.CREATE2:      {}, // caller is already recorded in ExtraData.Caller, callee is recorded in CaptureEnter&CaptureExit
		vm.SLOAD:        {}, // trace storage in `captureState` instead of here, to handle `l.cfg.DisableStorage` flag
		vm.SSTORE:       {}, // trace storage in `captureState` instead of here, to handle `l.cfg.DisableStorage` flag
		vm.SELFDESTRUCT: {traceContractAccount, traceLastNAddressAccount(0)},
		vm.SELFBALANCE:  {traceContractAccount},
		vm.BALANCE:      {traceLastNAddressAccount(0)},
		vm.EXTCODEHASH:  {traceLastNAddressAccount(0)},
		vm.CODESIZE:     {traceContractCode},
		vm.CODECOPY:     {traceContractCode},
		vm.EXTCODESIZE:  {traceLastNAddressCode(0)},
		vm.EXTCODECOPY:  {traceLastNAddressCode(0)},
	}
)

// traceToAddressCode gets tx.to address’s code
func traceToAddressCode(l *StructLogger, scope *vm.ScopeContext, extraData *types.ExtraData) error {
	if l.env.To == nil {
		return nil
	}
	code := l.env.StateDB.GetCode(*l.env.To)
	extraData.CodeList = append(extraData.CodeList, hexutil.Encode(code))
	return nil
}

// traceLastNAddressCode
func traceLastNAddressCode(n int) traceFunc {
	return func(l *StructLogger, scope *vm.ScopeContext, extraData *types.ExtraData) error {
		stack := scope.Stack
		if stack.Len() <= n {
			return nil
		}
		address := common.Address(stack.Data()[stack.Len()-1-n].Bytes20())
		code := l.env.StateDB.GetCode(address)
		extraData.CodeList = append(extraData.CodeList, hexutil.Encode(code))
		l.statesAffected[address] = struct{}{}
		return nil
	}
}

// traceContractCode gets the contract's code
func traceContractCode(l *StructLogger, scope *vm.ScopeContext, extraData *types.ExtraData) error {
	code := l.env.StateDB.GetCode(scope.Contract.Address())
	extraData.CodeList = append(extraData.CodeList, hexutil.Encode(code))
	return nil
}

// traceStorage get contract's storage at storage_address
func traceStorage(l *StructLogger, scope *vm.ScopeContext, extraData *types.ExtraData) error {
	if scope.Stack.Len() == 0 {
		return nil
	}
	key := common.Hash(scope.Stack.Peek().Bytes32())
	storage := getWrappedAccountForStorage(l, scope.Contract.Address(), key)
	extraData.StateList = append(extraData.StateList, storage)

	return nil
}

// traceContractAccount gets the contract's account
func traceContractAccount(l *StructLogger, scope *vm.ScopeContext, extraData *types.ExtraData) error {
	// Get account state.
	state := getWrappedAccountForAddr(l, scope.Contract.Address())
	extraData.StateList = append(extraData.StateList, state)
	l.statesAffected[scope.Contract.Address()] = struct{}{}

	return nil
}

// traceLastNAddressAccount returns func about the last N's address account.
func traceLastNAddressAccount(n int) traceFunc {
	return func(l *StructLogger, scope *vm.ScopeContext, extraData *types.ExtraData) error {
		stack := scope.Stack
		if stack.Len() <= n {
			return nil
		}

		address := common.Address(stack.Data()[stack.Len()-1-n].Bytes20())
		state := getWrappedAccountForAddr(l, address)
		extraData.StateList = append(extraData.StateList, state)
		l.statesAffected[address] = struct{}{}

		return nil
	}
}

// StorageWrapper will be empty
func getWrappedAccountForAddr(l *StructLogger, address common.Address) *types.AccountWrapper {
	return &types.AccountWrapper{
		Address:          address,
		Nonce:            l.env.StateDB.GetNonce(address),
		Balance:          (*hexutil.Big)(l.env.StateDB.GetBalance(address)),
		KeccakCodeHash:   l.env.StateDB.GetCodeHash(address),
		PoseidonCodeHash: l.env.StateDB.GetPoseidonCodeHash(address),
		CodeSize:         uint64(l.env.StateDB.GetCodeSize(address)),
	}
}

func getWrappedAccountForStorage(l *StructLogger, address common.Address, key common.Hash) *types.AccountWrapper {
	return &types.AccountWrapper{
		Address:          address,
		Nonce:            l.env.StateDB.GetNonce(address),
		Balance:          (*hexutil.Big)(l.env.StateDB.GetBalance(address)),
		KeccakCodeHash:   l.env.StateDB.GetCodeHash(address),
		PoseidonCodeHash: l.env.StateDB.GetPoseidonCodeHash(address),
		CodeSize:         uint64(l.env.StateDB.GetCodeSize(address)),
		Storage: &types.StorageWrapper{
			Key:   key.String(),
			Value: l.env.StateDB.GetState(address, key).String(),
		},
	}
}

func getCodeForAddr(l *StructLogger, address common.Address) []byte {
	return l.env.StateDB.GetCode(address)
}
