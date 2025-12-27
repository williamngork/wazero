package frontend

import (
	"testing"

	"github.com/tetratelabs/wazero/internal/engine/wazevo/ssa"
	"github.com/tetratelabs/wazero/internal/testing/require"
	"github.com/tetratelabs/wazero/internal/wasm"
)

func TestCompiler_declareSignatures__HABITAT(t *testing.T) {
	m := &wasm.Module{
		TypeSection: []wasm.FunctionType{
			{},
			{Params: []wasm.ValueType{wasm.ValueTypeI64, wasm.ValueTypeI32}},
			{Params: []wasm.ValueType{wasm.ValueTypeF64, wasm.ValueTypeI32}},
			{Results: []wasm.ValueType{wasm.ValueTypeI64, wasm.ValueTypeI32}},
		},
	}

	t.Run("listener=false", func(t *testing.T) {
		builder := ssa.NewBuilder()
		c := &Compiler{m: m, ssaBuilder: builder}
		c.declareSignatures(false)

		declaredSigs := builder.Signatures()
		expected := []*ssa.Signature{
			{ID: 0, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64}},
			{ID: 1, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64, ssa.TypeI64, ssa.TypeI32}},
			{ID: 2, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64, ssa.TypeF64, ssa.TypeI32}},
			{ID: 3, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64}, Results: []ssa.Type{ssa.TypeI64, ssa.TypeI32}},
			{ID: 4, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}},
			{ID: 5, Params: []ssa.Type{ssa.TypeI64}},
			{ID: 6, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32, ssa.TypeI32, ssa.TypeI64}, Results: []ssa.Type{ssa.TypeI32}},
			{ID: 7, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI64}},
		}

		require.Equal(t, len(expected), len(declaredSigs))
		for i := 0; i < len(expected); i++ {
			require.Equal(t, expected[i].String(), declaredSigs[i].String(), i)
		}
	})

	t.Run("listener=false", func(t *testing.T) {
		builder := ssa.NewBuilder()
		c := &Compiler{m: m, ssaBuilder: builder}
		c.declareSignatures(true)

		declaredSigs := builder.Signatures()

		expected := []*ssa.Signature{
			{ID: 0, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64}},
			{ID: 1, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64, ssa.TypeI64, ssa.TypeI32}},
			{ID: 2, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64, ssa.TypeF64, ssa.TypeI32}},
			{ID: 3, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI64}, Results: []ssa.Type{ssa.TypeI64, ssa.TypeI32}},
			// Before.
			{ID: 4, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32}},
			{ID: 5, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32, ssa.TypeI64, ssa.TypeI32}},
			{ID: 6, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32, ssa.TypeF64, ssa.TypeI32}},
			{ID: 7, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32}},
			// After.
			{ID: 8, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32}},
			{ID: 9, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32}},
			{ID: 10, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32}},
			{ID: 11, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32, ssa.TypeI64, ssa.TypeI32}},
			// Misc.
			{ID: 12, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}},
			{ID: 13, Params: []ssa.Type{ssa.TypeI64}},
			{ID: 14, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32, ssa.TypeI32, ssa.TypeI64}, Results: []ssa.Type{ssa.TypeI32}},
			{ID: 15, Params: []ssa.Type{ssa.TypeI64, ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI64}},
		}
		require.Equal(t, len(expected), len(declaredSigs))
		for i := 0; i < len(declaredSigs); i++ {
			require.Equal(t, expected[i].String(), declaredSigs[i].String(), i)
		}
	})
}
