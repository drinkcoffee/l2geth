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
// https://github.com/scroll-tech/go-ethereum/blob/develop/eth/tracers/api_blocktrace.go
package tracers

import (
	"context"
	"errors"

	"github.com/drinkcoffee/l2geth/core"
	"github.com/drinkcoffee/l2geth/core/types"
	"github.com/drinkcoffee/l2geth/eth/tracers/logger"
	"github.com/drinkcoffee/l2geth/log"
	"github.com/drinkcoffee/l2geth/rpc"
)

type TraceBlock interface {
	GetBlockTraceByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash, config *TraceConfig) (trace *types.BlockTrace, err error)
}

// GetBlockTraceByNumberOrHash replays the block and returns the structured BlockTrace by hash or number.
func (api *API) GetBlockTraceByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash, config *TraceConfig) (trace *types.BlockTrace, err error) {
	var block *types.Block
	if number, ok := blockNrOrHash.Number(); ok {
		block, err = api.blockByNumber(ctx, number)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		block, err = api.blockByHash(ctx, hash)
	}
	if err != nil {
		return nil, err
	}
	if block.NumberU64() == 0 {
		return nil, errors.New("genesis is not traceable")
	}
	if config == nil {
		config = &TraceConfig{
			Config: &logger.Config{
				EnableMemory:     false,
				EnableReturnData: true,
			},
		}
	} else if config.Tracer != nil {
		config.Tracer = nil
		log.Warn("Tracer params is unsupported")
	}

	// create current execution environment.
	env, release, err := api.createTraceEnv(ctx, config, block)
	defer release()
	if err != nil {
		return nil, err
	}
	return env.GetBlockTrace(block)
}

// Make trace environment for current block.
func (api *API) createTraceEnv(ctx context.Context, config *TraceConfig, block *types.Block) (*core.TraceEnv, StateReleaseFunc, error) {
	parent, err := api.blockByNumberAndHash(ctx, rpc.BlockNumber(block.NumberU64()-1), block.ParentHash())
	if err != nil {
		return nil, nil, err
	}
	reexec := defaultTraceReexec
	if config != nil && config.Reexec != nil {
		reexec = *config.Reexec
	}
	// TODO we are ignoring the release function - this will be needed.
	statedb, release, err := api.backend.StateAtBlock(ctx, parent, reexec, nil, true, true)
	if err != nil {
		return nil, nil, err
	}
	chaindb := api.backend.ChainDb()
	traceEnv, err1 := core.CreateTraceEnv(api.backend.ChainConfig(), api.chainContext(ctx), api.backend.Engine(), chaindb, statedb, parent, block, true)
	return traceEnv, release, err1
}
