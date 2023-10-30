package main

import (
	"testing"

	types "github.com/secureworks/atomic-harness/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestFindGoArtStageRegex(t *testing.T) {
	a := []string{}

	cmdline1 := "sh /tmp/artwork-T1560.002_3-458617291/goart-T1560.002-test.bash"
	a = gRxGoArtStage.FindStringSubmatch(cmdline1)
	assert.Equal(t, 4, len(a))

	folder := a[1]
	technique := a[2]
	stageName := a[3]

	assert.Equal(t, "artwork-T1560.002_3-458617291", folder)
	assert.Equal(t, "T1560.002", technique)
	assert.Equal(t, "test", stageName)

	cmdlineBat1 := `CMD /c C:\Users\admin\AppData\Local\Temp\artwork-T1047_1-2854796409\goart-T1047-test.bat`

	a = gRxGoArtStageWin.FindStringSubmatch(cmdlineBat1)
	assert.Equal(t, 5, len(a))

	folder = a[2]
	technique = a[3]
	stageName = a[4]

	assert.Equal(t, "artwork-T1047_1-2854796409", folder)
	assert.Equal(t, "T1047", technique)
	assert.Equal(t, "test", stageName)

	cmdlinePS1 := `POWERSHELL -NoProfile C:\Users\admin\AppData\Local\Temp\artwork-T1027.002_2-3400567469\goart-T1027.002-test.ps1`

	a = gRxGoArtStageWin.FindStringSubmatch(cmdlinePS1)
	assert.Equal(t, 5, len(a))

	folder = a[2]
	technique = a[3]
	stageName = a[4]

	assert.Equal(t, "artwork-T1027.002_2-3400567469", folder)
	assert.Equal(t, "T1027.002", technique)
	assert.Equal(t, "test", stageName)
}

func TestValidateFileNamedPipe(t *testing.T) {
	my_tool := TelemTool{}
	my_tool.Suffix = ""

	my_test_run := SingleTestRun{}
	my_test_run.StartTime = 1697100000
	my_test_run.EndTime = 1697200000

	my_criteria := types.AtomicTestCriteria{}
	my_criteria.Technique = "T1134.001"
	my_criteria.TestIndex = 1
	my_criteria.TestName = "Named pipe client impersonation"

	my_test_run.criteria = &my_criteria

	dummy_expected_events := make([]*types.ExpectedEvent, 1)
	expected_event := types.ExpectedEvent{}
	expected_event.Id = "1"
	expected_event.EventType = "File"
	expected_event.SubType = "CREATE"
	dummy_expected_events[0] = &expected_event

	named_pipe_field_criteria := make([]types.FieldCriteria, 1)
	expected_event.FieldChecks = named_pipe_field_criteria
	named_pipe_field_criterion := types.FieldCriteria{}
	named_pipe_field_criterion.FieldName = "path"
	named_pipe_field_criterion.Op = "="
	named_pipe_field_criterion.Value = "\\\\.\\pipe\\TestSVC"
	named_pipe_field_criteria[0] = named_pipe_field_criterion

	my_criteria.ExpectedEvents = dummy_expected_events

	ValidateSimpleTelemetry(&my_test_run, &my_tool)
}
