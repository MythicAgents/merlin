
from CommandBase import *
import os
import json
import subprocess

from MythicResponseRPC import *

# Set to enable debug output to Mythic
debug = False


class CreateProcessArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "shellcode": CommandParameter(
                name="shellcode",
                type=ParameterType.File,
                description="The shellcode file you want to execute in the spawnto process",
                required=True,
            ),
            "spawnto": CommandParameter(
                name="spawnto",
                type=ParameterType.String,
                description="the child process that will be started to execute the assembly in",
                default_value="C:\\Windows\\System32\\WerFault.exe",
                required=True
            ),
            "spawntoargs": CommandParameter(
                name="spawnto arguments",
                type=ParameterType.String,
                description="argument to create the spawnto process with, if any",
                required=False,
            ),
        }

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)


class CreateProcessCommand(CommandBase):
    cmd = "create-process"
    needs_admin = False
    help_cmd = "create-process"
    description = "This command will create a process from the spawnto argument and inject/execute the provided " \
                  "shellcode and uses anonymous pipes to collect STDOUT/STDERR"
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_remove_file = False
    is_upload_file = False
    author = "@Ne0nd0g"
    argument_class = CreateProcessArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        # Merlin jobs.MODULE
        task.args.add_arg("type", 16, ParameterType.Number)

        # 1. Shellcode
        # 2. SpawnTo Executable
        # 3. SpawnTo Arguments
        args = [
            base64.b64encode(task.args.get_arg("shellcode")).decode("utf-8"),
            task.args.get_arg("spawnto"),
            task.args.get_arg("spawntoargs")
        ]

        # Merlin jobs.Command message type
        command = {
            "command": "createprocess",
            "args": args,
        }

        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("shellcode")
        task.args.remove_arg("spawnto")
        task.args.remove_arg("spawntoargs")

        if debug:
            await MythicResponseRPC(task).user_output(f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
