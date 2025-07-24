package fuzzing

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/crytic/medusa/logging"
	"github.com/crytic/medusa/logging/colors"

	"github.com/crytic/medusa-geth/accounts/abi"
	"github.com/crytic/medusa/fuzzing/calls"
	fuzzerTypes "github.com/crytic/medusa/fuzzing/contracts"
)

const (
	CuEVM_ASSERTION_BUG_TYPE = 0xFF
	CuEVM_INTEGER_OVERFLOW   = 0x01
	CuEVM_INTEGER_UNDERFLOW  = 0x02
	CuEVM_SELF_DESTRUCT      = 0x03
	CuEVM_LEAKING_ETHER      = 0x04
)

// bugTypeName returns a human-readable name for the bug type
func bugTypeName(bugType uint32) string {
	switch bugType {
	case CuEVM_ASSERTION_BUG_TYPE:
		return "Assertion Failure"
	case CuEVM_INTEGER_OVERFLOW:
		return "Integer Overflow"
	case CuEVM_INTEGER_UNDERFLOW:
		return "Integer Underflow"
	case CuEVM_SELF_DESTRUCT:
		return "Self Destruct"
	case CuEVM_LEAKING_ETHER:
		return "Leaking Ether"
	default:
		return "Assertion Failure"
	}
}

// AssertionTestCase describes a test being run by a AssertionTestCaseProvider.
type AssertionTestCase struct {
	// status describes the status of the test case
	status TestCaseStatus `json:"status"`
	// targetContract describes the target contract where the test case was found
	targetContract *fuzzerTypes.Contract `json:"-"`
	// targetMethod describes the target method for the test case
	targetMethod abi.Method `json:"targetMethod"`
	// callSequence describes the call sequence that broke the assertion
	callSequence *calls.CallSequence `json:"callSequence"`
	// bugPC describes the PC of the bug
	bugPC uint32 `json:"bugPC"`
	// bugType describes the type of the bug
	bugType uint32  `json:"bugType"`
	bugTime float64 `json:"bugTime"`
}

// Status describes the TestCaseStatus used to define the current state of the test.
func (t *AssertionTestCase) Status() TestCaseStatus {
	return t.status
}

// CallSequence describes the types.CallSequence of calls sent to the EVM which resulted in this TestCase result.
// This should be nil if the result is not related to the CallSequence.
func (t *AssertionTestCase) CallSequence() *calls.CallSequence {
	return t.callSequence
}

// Name describes the name of the test case.
func (t *AssertionTestCase) Name() string {
	return fmt.Sprintf("Assertion Test: %s.%s", t.targetContract.Name(), t.targetMethod.Sig)
}

// LogMessage obtains a buffer that represents the result of the AssertionTestCase. This buffer can be passed to a logger for
// console or file logging.
func (t *AssertionTestCase) LogMessage() *logging.LogBuffer {
	// If the test failed, return a failure message.
	buffer := logging.NewLogBuffer()
	if t.Status() == TestCaseStatusFailed {
		buffer.Append(colors.RedBold, fmt.Sprintf("[%s] ", t.Status()), colors.Bold, t.Name(), colors.Reset, "\n")
		buffer.Append(fmt.Sprintf("Test for method \"%s.%s\" resulted in an %s after the following call sequence:\n", t.targetContract.Name(), t.targetMethod.Sig, bugTypeName(t.bugType)))
		buffer.Append(fmt.Sprintf("Bug PC: %d\n", t.bugPC))
		buffer.Append(colors.Bold, "[Call Sequence]", colors.Reset, "\n")
		buffer.Append(t.CallSequence().Log().Elements()...)
		return buffer
	}

	buffer.Append(colors.GreenBold, fmt.Sprintf("[%s] ", t.Status()), colors.Bold, t.Name(), colors.Reset)
	return buffer
}

// Message obtains a text-based printable message which describes the result of the AssertionTestCase.
func (t *AssertionTestCase) Message() string {
	// Internally, we just call log message and convert it to a string. This can be useful for 3rd party apps
	return t.LogMessage().String()
}

// ID obtains a unique identifier for a test result.
func (t *AssertionTestCase) ID() string {
	if t.bugType != 0 {
		return strings.Replace(fmt.Sprintf("GPU_BUG-%s-%s-%d-%d", t.targetContract.Name(), t.targetMethod.Sig, t.bugType, t.bugPC), "_", "-", -1)
	} else {
		return strings.Replace(fmt.Sprintf("Assertion-%s-%s", t.targetContract.Name(), t.targetMethod.Sig), "_", "-", -1)
	}
}

// MarshalJSON provides custom JSON marshalling for the struct.
func (t *AssertionTestCase) MarshalJSON() ([]byte, error) {
	// Create a struct with exported fields for JSON marshaling
	return json.Marshal(struct {
		TargetMethod string              `json:"method"`
		CallSequence *calls.CallSequence `json:"callSequence"`
		BugPC        uint32              `json:"bugPC"`
		BugType      string              `json:"bugType"`
		BugTime      string              `json:"bugTime"`
		ID           string              `json:"id"`
	}{

		TargetMethod: t.targetMethod.Sig,
		CallSequence: t.callSequence,
		BugPC:        t.bugPC,
		BugType:      bugTypeName(t.bugType),
		BugTime:      strconv.FormatFloat(t.bugTime, 'f', 2, 64),
		ID:           t.ID(),
	})
}
