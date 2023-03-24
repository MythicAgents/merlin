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
	"encoding/json"
	"fmt"
	structs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/Ne0nd0g/merlin/pkg/jobs"
)

func download() structs.Command {
	command := structs.Command{
		Name:                           "download",
		NeedsAdminPermissions:          false,
		HelpString:                     "download <file path>",
		Description:                    "Downloads a file from the host where the agent is running",
		Version:                        0,
		SupportedUIFeatures:            []string{"file_browser:download"},
		Author:                         "@Ne0nd0g",
		MitreAttackMappings:            []string{"T1560", "T1041"},
		ScriptOnlyCommand:              false,
		CommandAttributes:              structs.CommandAttribute{},
		CommandParameters:              nil,
		AssociatedBrowserScript:        nil,
		TaskFunctionOPSECPre:           nil,
		TaskFunctionCreateTasking:      downloadCreateTasking,
		TaskFunctionProcessResponse:    nil,
		TaskFunctionOPSECPost:          nil,
		TaskFunctionParseArgString:     taskFunctionParseArgString,
		TaskFunctionParseArgDictionary: taskFunctionParseArgDictionary,
		TaskCompletionFunctions:        nil,
	}

	return command
}

func downloadCreateTasking(task *structs.PTTaskMessageAllData) (resp structs.PTTaskCreateTaskingMessageResponse) {
	resp.TaskID = task.Task.ID
	filepath, err := task.Args.GetArg("file")
	if err != nil {
		resp.Error = fmt.Sprintf("there was an error getting the \"file\" argument's value for the \"download\" command: %s", err)
		resp.Success = false
		return
	}

	job := jobs.FileTransfer{
		FileLocation: filepath.(string),
		IsDownload:   false,
	}

	jobBytes, err := json.Marshal(job)
	if err != nil {
		resp.Error = fmt.Sprintf("there was an error JSON marshalling the Merlin jobs.Job structure: %s", err)
		resp.Success = false
		return
	}

	mythicJob := Job{
		Type:    jobs.FILETRANSFER,
		Payload: string(jobBytes),
	}

	mythicJobBytes, err := json.Marshal(mythicJob)
	if err != nil {
		resp.Error = fmt.Sprintf("there was an error JSON marshalling the Job structure: %s", err)
		resp.Success = false
		return
	}
	task.Args.SetManualArgs(string(mythicJobBytes))

	resp.Success = true

	return
}
