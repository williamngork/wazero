package frontend

import (
	"fmt"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/ssa"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/testcases"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/wazevoapi"
	"github.com/tetratelabs/wazero/internal/testing/require"
	"github.com/tetratelabs/wazero/internal/wasm"
	"testing"
)

func TestLoopTermination__HABITAT(t *testing.T) {
	for _, tc := range []struct {
		name              string
		ensureTermination bool
		m                 *wasm.Module
		targetIndex       wasm.Index
		exp               string
		expAfterOpt       string
	}{
		{
			name: "loop - br / ensure termination", m: testcases.LoopBr.Module,
			ensureTermination: true,
			exp: `
signatures:
	sig2: i64_v

blk0: (exec_ctx:i64, module_ctx:i64)
	Jump blk1

blk1: () <-- (blk0,blk1)
	v2:i64 = Load exec_ctx, 0x58
	CallIndirect v2:sig2, exec_ctx
	Jump blk1

blk2: ()
`,
			expAfterOpt: `
signatures:
	sig2: i64_v

blk0: (exec_ctx:i64, module_ctx:i64)
	Jump blk1

blk1: () <-- (blk0,blk1)
	v2:i64 = Load exec_ctx, 0x58
	CallIndirect v2:sig2, exec_ctx
	Jump blk1
`,
		},
	} {

		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Just in case let's check the test module is valid.
			err := tc.m.Validate(api.CoreFeaturesV2)
			require.NoError(t, err, "invalid test case module!")

			b := ssa.NewBuilder()

			offset := wazevoapi.NewModuleContextOffsetData(tc.m)
			fc := NewFrontendCompiler(tc.m, b, &offset)
			typeIndex := tc.m.FunctionSection[tc.targetIndex]
			code := &tc.m.CodeSection[tc.targetIndex]
			fc.Init(tc.targetIndex, &tc.m.TypeSection[typeIndex], code.LocalTypes, code.Body)

			fc.LowerToSSA()

			actual := fc.formatBuilder()
			fmt.Println(actual)
			require.Equal(t, tc.exp, actual)

			b.RunPasses()
			if expAfterOpt := tc.expAfterOpt; expAfterOpt != "" {
				actualAfterOpt := fc.formatBuilder()
				fmt.Println(actualAfterOpt)
				require.Equal(t, expAfterOpt, actualAfterOpt)
			}

			// Dry-run without checking the results of LayoutBlocks function.
			b.LayoutBlocks()
		})
	}
}
