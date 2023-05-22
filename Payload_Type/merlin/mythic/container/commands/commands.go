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

// Package commands holds all the Mythic command logic for issuing, receiving, and processing commands to Merlin
package commands

import (
	// Standard
	"encoding/json"
	"fmt"
	"strings"

	// Mythic
	structs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/jobs"
)

type Command interface {
	Command() structs.Command
}

// Job structure
type Job struct {
	Type    int    `json:"type"`
	Payload string `json:"payload"`
}

// Commands returns a list of all the commands the Merlin agent payload supports
func Commands() (commands []structs.Command) {
	// TODO Fix the following commands: executePE, executeShellcode, donut
	// TODO Add the following commands: mimikatz, sharpgen, srdi
	commands = append(
		commands, cd(), createProcess(), download(), env(), executeAssembly(), executeShellcode(),
		exit(), ifconfig(), invokeAssembly(), ja3(), killdate(), killProcess(), loadAssembly(), listAssembly(), ls(),
		makeToken(), maxRetry(), memfd(), memory(), netstat(), nslookup(), parrot(), pipes(), ps(), pwd(), rev2Self(),
		rm(), run(), runas(), sdelete(), shell(), skew(), socks(), ssh(), stealToken(), timeStomp(), token(), upload(),
		uptime(),
	)
	return
}

// taskFunctionCreateTasking is a generic function to transform a Mythic Task into a format the Merlin Agent can understand
/*
	What Merlin gets from Mythic
	{
		"action":"get_tasking",
		"padding":"Sb",
		"tasks":[
			{
				"timestamp":1678920007,
				"command":"cd",
				"parameters":"/home/rastley/Downloads",
				"id":"28c242ef-97fe-4074-84de-4d5e40056f4f"
			}
		]
	}

	// The JSON object above is unmarshalled into this structure only used by the Mythic client in Merlin
	// through the convertToMerlinMessage() function
	// Merlin Agent ignores the Command field except for SOCKS messages
	type Task struct {
		ID      string  `json:"id"`
		Command string  `json:"command"`
		Params  string  `json:"parameters"`
		Time    float64 `json:"timestamp"`
	}

	The task params needs to be a JSON object that matches this Job structure
		The Job.Type directly relates to Merlin job types like CMD, CONTROL, or NATIVE
		The Job.Payload needs to be a JSON object that unmarshalled in to corresponding Merlin structure


	// The Task structure's Params field from above is JSON unmarshalled into this Job structure in the convertTasksToJobs() function
	// Job is a structure used only by the Mythic client in Merlin
	type Job struct {
		Type    int    `json:"type"`
		Payload string `json:"payload"`
	}

	// The Job structure's Payload field from above is JSON unmarshalled into this Command structure in the convertTasksToJobs() function
	// Command is the structure to send a task for the agent to execute
	type Command struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}
*/
func taskFunctionCreateTasking(task *structs.PTTaskMessageAllData) (resp structs.PTTaskCreateTaskingMessageResponse) {
	return structs.PTTaskCreateTaskingMessageResponse{
		TaskID:                 task.Task.ID,
		Success:                true,
		Error:                  "",
		CommandName:            nil,
		TaskStatus:             nil,
		DisplayParams:          nil,
		Stdout:                 nil,
		Stderr:                 nil,
		Completed:              nil,
		TokenID:                nil,
		CompletionFunctionName: nil,
		ParameterGroupName:     "",
	}
}

func taskFunctionParseArgDictionary(args *structs.PTTaskMessageArgsData, input map[string]interface{}) error {
	// Nothing ot parse
	if len(input) == 0 {
		return nil
	}
	return args.LoadArgsFromDictionary(input)
}

func taskFunctionParseArgString(args *structs.PTTaskMessageArgsData, input string) error {
	// Nothing to parse
	if input == "" {
		return nil
	}
	return args.LoadArgsFromJSONString(input)
}

// GetFile processes a Mythic task to retrieve a file and return its contents, filename, and any errors.
// The Mythic task must have a "filename" and "file" command arguments.
// The "filename" command argument references a file that has already been uploaded to Mythic.
// The "file" command argument reference is used when a new file was uploaded as part of the Mythic task.
func GetFile(task *structs.PTTaskMessageAllData) (data []byte, filename string, err error) {
	pkg := "merlin/Payload_Type/merlin/mythic/container/commands/commands.go/GetFile():"
	// Determine if a "filename" or "file" Mythic command argument was provided
	switch strings.ToLower(task.Task.ParameterGroupName) {
	case "default":
		filename, err = task.Args.GetStringArg("filename")
		if err != nil {
			err = fmt.Errorf("%s there was an error getting the \"filename\" command argument for task %d: %s", pkg, task.Task.ID, err)
			return
		}
		data, err = GetFileByName(filename, task.Callback.ID)
		if err != nil {
			err = fmt.Errorf("%s there was an error getting the file by its name \"%s\" for task %d: %s", pkg, filename, task.Task.ID, err)
			return
		}
	case "new file":
		var fileID string
		fileID, err = task.Args.GetStringArg("file")
		if err != nil {
			err = fmt.Errorf("%s there was an error getting the \"file\" command argument for task %d: %s", pkg, task.Task.ID, err)
			return
		}
		data, err = GetFileContents(fileID)
		if err != nil {
			err = fmt.Errorf("%s there was an error getting the file by its id \"%s\" for task %d: %s", pkg, fileID, task.Task.ID, err)
			return
		}
		filename, err = GetFileName(fileID)
		if err != nil {
			err = fmt.Errorf("%s there was an error getting the file name by its id \"%s\" for task %d: %s", pkg, fileID, task.Task.ID, err)
			return
		}
	default:
		err = fmt.Errorf("%s unknown parameter group: %s", pkg, task.Task.ParameterGroupName)
		return
	}
	return
}

// GetFileList queries the Mythic server for files it knows about and returns a list of those Mythic file objects
// This function is used as a DynamicQuery to populate Mythic Command Parameter dropdown lists
func GetFileList(msg structs.PTRPCDynamicQueryFunctionMessage) (files []string) {
	search := mythicrpc.MythicRPCFileSearchMessage{
		TaskID:              0,
		CallbackID:          msg.Callback,
		Filename:            "",
		LimitByCallback:     false,
		MaxResults:          -1,
		Comment:             "",
		AgentFileID:         "",
		IsPayload:           false,
		IsDownloadFromAgent: false,
		IsScreenshot:        false,
	}
	resp, err := mythicrpc.SendMythicRPCFileSearch(search)
	if err != nil {
		fmt.Printf("Payload_Type/merlin/mythic/container/commands/GetFileList(): there was an error calling the SendMythicRPCFileSearch function: %s", err)
		return
	}

	if resp.Error != "" {
		fmt.Printf("Payload_Type/merlin/mythic/container/commands/GetFileList(): the SendMythicRPCFileSearch function returned a response message that contained an error: %s", resp.Error)
		return
	}

	for _, file := range resp.Files {
		files = append(files, file.Filename)
	}
	return
}

// GetFileByName queries the Mythic server for files that match the passed in name argument and returns the contents of the first match
func GetFileByName(name string, callback int) (contents []byte, err error) {
	search := mythicrpc.MythicRPCFileSearchMessage{
		TaskID:              0,
		CallbackID:          callback,
		Filename:            name,
		LimitByCallback:     false,
		MaxResults:          -1,
		Comment:             "",
		AgentFileID:         "",
		IsPayload:           false,
		IsDownloadFromAgent: false,
		IsScreenshot:        false,
	}
	resp, err := mythicrpc.SendMythicRPCFileSearch(search)
	if err != nil {
		err = fmt.Errorf("Payload_Type/merlin/mythic/container/commands/GetFileByName(): there was an error calling the SendMythicRPCFileSearch function: %s", err)
		return
	}

	if len(resp.Files) <= 0 {
		err = fmt.Errorf("Payload_Type/merlin/mythic/container/commands/GetFileByName(): %d files were returned", len(resp.Files))
		return
	}

	for _, file := range resp.Files {
		if file.Filename == name {
			contents, err = GetFileContents(file.AgentFileId)
		}
	}
	return
}

// GetFileContents retrieves the file content as bytes for the provided fileID string
func GetFileContents(fileID string) (contents []byte, err error) {
	msg := mythicrpc.MythicRPCFileGetContentMessage{
		AgentFileID: fileID,
	}
	resp, err := mythicrpc.SendMythicRPCFileGetContent(msg)
	if err != nil {
		err = fmt.Errorf("Payload_Type/merlin/mythic/container/commands/GetFileContents(): the SendMythicRPCFileGetContent function returned an error: %s", resp.Error)
		return
	}
	contents = resp.Content
	return
}

func GetFileName(fileID string) (name string, err error) {
	search := mythicrpc.MythicRPCFileSearchMessage{
		TaskID:              0,
		CallbackID:          0,
		Filename:            "",
		LimitByCallback:     false,
		MaxResults:          -1,
		Comment:             "",
		AgentFileID:         fileID,
		IsPayload:           false,
		IsDownloadFromAgent: false,
		IsScreenshot:        false,
	}
	resp, err := mythicrpc.SendMythicRPCFileSearch(search)
	if err != nil {
		err = fmt.Errorf("Payload_Type/merlin/mythic/container/commands/GetFileName(): there was an error calling the SendMythicRPCFileSearch function: %s", err)
		return
	}

	if len(resp.Files) <= 0 {
		err = fmt.Errorf("Payload_Type/merlin/mythic/container/commands/GetFileName(): %d files were returned", len(resp.Files))
		return
	}

	for _, file := range resp.Files {
		if file.AgentFileId == fileID {
			name = file.Filename
			return
		}
	}
	return
}

func ConvertMerlinJobToMythicTask(job jobs.Command, jobType int) (bytes string, err error) {
	jobBytes, err := json.Marshal(job)
	if err != nil {
		err = fmt.Errorf("mythic/container/commands/ConvertMerlinJobToMythicTask: there was an error JSON marshalling the Merlin jobs.Job structure: %s", err)
		return
	}

	mythicJob := Job{
		Type:    jobType,
		Payload: string(jobBytes),
	}
	mythicJobBytes, err := json.Marshal(mythicJob)
	if err != nil {
		err = fmt.Errorf("mythic/container/commands/ConvertMerlinJobToMythicTask: there was an error JSON marshalling the Job structure: %s", err)
		return
	}
	return string(mythicJobBytes), nil
}
