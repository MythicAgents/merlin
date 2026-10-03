package commands

import (
	"encoding/json"
	"reflect"
	"testing"

	structs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/Ne0nd0g/merlin-message/jobs"
)

func TestSplitCommandLineArguments(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "quoted group name",
			input: `net group "Domain Admins" /domain`,
			want:  []string{"net", "group", "Domain Admins", "/domain"},
		},
		{
			name:  "unquoted arguments",
			input: "whoami\t/all  ",
			want:  []string{"whoami", "/all"},
		},
		{
			name:  "quoted windows path",
			input: `-o "C:\Program Files\Merlin\agent.exe"`,
			want:  []string{"-o", `C:\Program Files\Merlin\agent.exe`},
		},
		{
			name:  "escaped quote",
			input: `-Command "Write-Output \"hello world\""`,
			want:  []string{"-Command", `Write-Output "hello world"`},
		},
		{
			name:  "empty quoted argument",
			input: `cmd "" tail`,
			want:  []string{"cmd", "", "tail"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := splitCommandLineArguments(test.input)
			if err != nil {
				t.Fatalf("splitCommandLineArguments(%q) returned error: %v", test.input, err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("splitCommandLineArguments(%q) = %#v, want %#v", test.input, got, test.want)
			}
		})
	}
}

func TestSplitCommandLineArgumentsRejectsUnterminatedQuote(t *testing.T) {
	_, err := splitCommandLineArguments(`net group "Domain Admins /domain`)
	if err == nil {
		t.Fatal("splitCommandLineArguments returned nil error for unterminated quote")
	}
}

func TestShellCreateTaskPreservesQuotedArguments(t *testing.T) {
	task := newTaskWithArgs(t, shell(), "shell", map[string]interface{}{
		"arguments": `net group "Domain Admins" /domain`,
	})

	resp := shellCreateTask(task)
	if !resp.Success {
		t.Fatalf("shellCreateTask returned error: %s", resp.Error)
	}

	got := commandFromTaskArgs(t, task)
	want := jobs.Command{
		Command: "shell",
		Args:    []string{"net", "group", "Domain Admins", "/domain"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("shellCreateTask command = %#v, want %#v", got, want)
	}
}

func TestRunCreateTaskPreservesQuotedArguments(t *testing.T) {
	task := newTaskWithArgs(t, run(), "run", map[string]interface{}{
		"executable": "net",
		"arguments":  `group "Domain Admins" /domain`,
	})

	resp := runCreateTask(task)
	if !resp.Success {
		t.Fatalf("runCreateTask returned error: %s", resp.Error)
	}

	got := commandFromTaskArgs(t, task)
	want := jobs.Command{
		Command: "net",
		Args:    []string{"group", "Domain Admins", "/domain"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("runCreateTask command = %#v, want %#v", got, want)
	}
}

func TestAdditionalCreateTasksPreserveQuotedArguments(t *testing.T) {
	tests := []struct {
		name        string
		command     structs.Command
		commandName string
		input       map[string]interface{}
		create      func(*structs.PTTaskMessageAllData) structs.PTTaskCreateTaskingMessageResponse
		want        jobs.Command
	}{
		{
			name:        "runas",
			command:     runas(),
			commandName: "runas",
			input: map[string]interface{}{
				"executable": "net",
				"arguments":  `group "Domain Admins" /domain`,
				"user":       `ACME\operator`,
				"password":   "secret",
			},
			create: runasCreateTask,
			want: jobs.Command{
				Command: "runas",
				Args:    []string{`ACME\operator`, "secret", "net", "group", "Domain Admins", "/domain"},
			},
		},
		{
			name:        "env",
			command:     env(),
			commandName: "env",
			input: map[string]interface{}{
				"method":    "set",
				"arguments": `"MERLIN_HOME=C:\Program Files\Merlin"`,
			},
			create: envCreateTask,
			want: jobs.Command{
				Command: "env",
				Args:    []string{"set", `MERLIN_HOME=C:\Program Files\Merlin`},
			},
		},
		{
			name:        "ssh",
			command:     ssh(),
			commandName: "ssh",
			input: map[string]interface{}{
				"username":   "operator",
				"password":   "secret",
				"host":       "server.example:22",
				"executable": "net",
				"arguments":  `group "Domain Admins" /domain`,
			},
			create: sshCreateTask,
			want: jobs.Command{
				Command: "ssh",
				Args:    []string{"operator", "secret", "server.example:22", "net", "group", "Domain Admins", "/domain"},
			},
		},
		{
			name:        "token default",
			command:     token(),
			commandName: "token",
			input: map[string]interface{}{
				"method":    "make",
				"arguments": `"ACME\Domain Admins" password`,
			},
			create: tokenCreateTask,
			want: jobs.Command{
				Command: "token",
				Args:    []string{"make", `ACME\Domain Admins`, "password"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			task := newTaskWithArgs(t, test.command, test.commandName, test.input)

			resp := test.create(task)
			if !resp.Success {
				t.Fatalf("%s returned error: %s", test.name, resp.Error)
			}

			got := commandFromTaskArgs(t, task)
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("%s command = %#v, want %#v", test.name, got, test.want)
			}
		})
	}
}

func newTaskWithArgs(t *testing.T, command structs.Command, commandName string, input map[string]interface{}) *structs.PTTaskMessageAllData {
	t.Helper()

	task := &structs.PTTaskMessageAllData{
		Task: structs.PTTaskMessageTaskData{
			ID:                 1,
			CommandName:        commandName,
			ParameterGroupName: "Default",
		},
	}

	args, err := structs.GenerateArgsData(command.CommandParameters, *task)
	if err != nil {
		t.Fatalf("GenerateArgsData returned error: %v", err)
	}
	if err := args.LoadArgsFromDictionary(input); err != nil {
		t.Fatalf("LoadArgsFromDictionary returned error: %v", err)
	}

	task.Args = args
	return task
}

func commandFromTaskArgs(t *testing.T, task *structs.PTTaskMessageAllData) jobs.Command {
	t.Helper()

	finalArgs, err := task.Args.GetFinalArgs()
	if err != nil {
		t.Fatalf("GetFinalArgs returned error: %v", err)
	}

	var mythicJob Job
	if err := json.Unmarshal([]byte(finalArgs), &mythicJob); err != nil {
		t.Fatalf("failed to unmarshal Mythic job: %v", err)
	}

	var command jobs.Command
	if err := json.Unmarshal([]byte(mythicJob.Payload), &command); err != nil {
		t.Fatalf("failed to unmarshal Merlin command: %v", err)
	}

	return command
}
