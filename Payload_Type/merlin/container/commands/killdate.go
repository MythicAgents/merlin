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
	"strconv"
	"time"

	// Mythic
	structs "github.com/MythicMeta/MythicContainer/agent_structs"

	// Merlin Message
	"github.com/Ne0nd0g/merlin-message/jobs"
)

// killdate returns a Mythic Command structure that is registered with the Mythic server that subsequently instructs the
// Merlin Agent to the exact date and time, as an epoch timestamp, it should stop running
func killdate() structs.Command {
	attr := structs.CommandAttribute{
		SupportedOS: []string{structs.SUPPORTED_OS_WINDOWS, structs.SUPPORTED_OS_LINUX, structs.SUPPORTED_OS_MACOS, "freebsd", "openbsd", "solaris"},
	}
	date := structs.CommandParameter{
		Name:                                    "date",
		ModalDisplayName:                        "Kill Date",
		CLIName:                                 "date",
		ParameterType:                           structs.COMMAND_PARAMETER_TYPE_STRING,
		Description:                             "The date, as a Unix epoch timestamp, that the agent should quit running",
		Choices:                                 nil,
		DefaultValue:                            nil,
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

	command := structs.Command{
		Name:                           "killdate",
		NeedsAdminPermissions:          false,
		HelpString:                     "killdate <epoch date/time>",
		Description:                    "The date, as a Unix epoch timestamp, that the agent should quit running.\nVisit: https://www.epochconverter.com/",
		Version:                        0,
		SupportedUIFeatures:            nil,
		Author:                         "@Ne0nd0g",
		MitreAttackMappings:            nil,
		ScriptOnlyCommand:              false,
		CommandAttributes:              attr,
		CommandParameters:              []structs.CommandParameter{date},
		AssociatedBrowserScript:        nil,
		TaskFunctionOPSECPre:           nil,
		TaskFunctionCreateTasking:      killdateCreateTasking,
		TaskFunctionProcessResponse:    nil,
		TaskFunctionOPSECPost:          nil,
		TaskFunctionParseArgString:     taskFunctionParseArgString,
		TaskFunctionParseArgDictionary: taskFunctionParseArgDictionary,
		TaskCompletionFunctions:        nil,
	}

	return command
}

// killdateCreateTasking takes a Mythic Task and converts into a Merlin Job that is encoded into JSON and subsequently sent to the Merlin Agent
func killdateCreateTasking(task *structs.PTTaskMessageAllData) (resp structs.PTTaskCreateTaskingMessageResponse) {
	resp.TaskID = task.Task.ID

	v, err := task.Args.GetArg("date")
	if err != nil {
		resp.Error = fmt.Sprintf("there was an error getting the \"date\" argument's value for the \"killdate\" command: %s", err)
		resp.Success = false
		return
	}
	date := v.(string)

	job := jobs.Command{
		Command: task.Task.CommandName,
		Args:    []string{date},
	}

	mythicJob, err := ConvertMerlinJobToMythicTask(job, jobs.CONTROL)
	if err != nil {
		resp.Error = fmt.Sprintf("mythic/container/commands/killdate/killdateCreateTasking(): %s", err)
		resp.Success = false
		return
	}
	task.Args.SetManualArgs(mythicJob)

	// Convert to human-readable format
	var epoch string
	d, err := strconv.Atoi(date)
	if err == nil {
		epoch = time.Unix(int64(d), 0).UTC().Format(time.RFC3339)
	}

	disp := fmt.Sprintf("%s %s", date, epoch)
	resp.DisplayParams = &disp
	resp.Success = true

	return
}
