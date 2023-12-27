/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2023  Russel Van Tuyl

Merlin is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as
published by the Free Software Foundation, either version 3 of the License, or any later version.

Merlin is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with Merlin.  If not, see <http://www.gnu.org/licenses/>.
*/

package commands

import (
	// Standard
	"fmt"
	"time"

	// Mythic
	structs "github.com/MythicMeta/MythicContainer/agent_structs"

	// Merlin Message
	"github.com/Ne0nd0g/merlin-message/jobs"
)

// sleep creates and return a Mythic Command structure that is registered with the Mythic server
func sleep() structs.Command {
	attr := structs.CommandAttribute{
		SupportedOS: []string{structs.SUPPORTED_OS_WINDOWS, structs.SUPPORTED_OS_LINUX, structs.SUPPORTED_OS_MACOS, "Debian"},
	}

	timeParam := structs.CommandParameter{
		Name:             "time",
		ModalDisplayName: "Sleep Time",
		CLIName:          "time",
		ParameterType:    structs.COMMAND_PARAMETER_TYPE_STRING,
		Description: "The amount of time for the agent to sleep between checkins. " +
			"Use Go's duration notation such as \"30s\" for thirty seconds",
		Choices:                                 nil,
		DefaultValue:                            "30s",
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

	params := []structs.CommandParameter{timeParam}
	command := structs.Command{
		Name:                           "sleep",
		NeedsAdminPermissions:          false,
		HelpString:                     "sleep <time>",
		Description:                    "Change the amount of time the agent will sleep between checkins",
		Version:                        0,
		SupportedUIFeatures:            nil,
		Author:                         "@Ne0nd0g",
		MitreAttackMappings:            []string{},
		ScriptOnlyCommand:              false,
		CommandAttributes:              attr,
		CommandParameters:              params,
		AssociatedBrowserScript:        nil,
		TaskFunctionOPSECPre:           nil,
		TaskFunctionCreateTasking:      sleepCreateTask,
		TaskFunctionProcessResponse:    nil,
		TaskFunctionOPSECPost:          nil,
		TaskFunctionParseArgString:     taskFunctionParseArgString,
		TaskFunctionParseArgDictionary: taskFunctionParseArgDictionary,
		TaskCompletionFunctions:        nil,
	}

	return command
}

// sleepCreateTask takes a Mythic Task and converts into a Merlin Job that is encoded into JSON and subsequently sent to the Merlin Agent
func sleepCreateTask(task *structs.PTTaskMessageAllData) (resp structs.PTTaskCreateTaskingMessageResponse) {
	pkg := "mythic/container/commands/sleep/sleepCreateTask()"
	resp.TaskID = task.Task.ID

	duration, err := task.Args.GetStringArg("time")
	if err != nil {
		resp.Error = fmt.Sprintf("%s: %s", pkg, err)
		resp.Success = false
		return
	}

	// Validate the duration
	_, err = time.ParseDuration(duration)
	if err != nil {
		resp.Error = fmt.Sprintf("%s: there was an error parsing the duration \"%s\": %s", pkg, duration, err)
		resp.Success = false
		return
	}

	job := jobs.Command{
		Command: task.Task.CommandName,
		Args:    []string{duration},
	}

	mythicJob, err := ConvertMerlinJobToMythicTask(job, jobs.CONTROL)
	if err != nil {
		resp.Error = fmt.Sprintf("%s: %s", pkg, err)
		resp.Success = false
		return
	}

	task.Args.SetManualArgs(mythicJob)

	disp := fmt.Sprintf("%s", duration)
	resp.DisplayParams = &disp
	resp.Success = true

	return
}
