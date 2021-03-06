from CommandBase import *
import json
from MythicResponseRPC import *

# Set to enable debug output to Mythic
debug = False


class LSArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "path": CommandParameter(
                name="path",
                type=ParameterType.String,
                description="The directory path to change to",
                default_value=".",
                required=False,
            ),
        }

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                if len(str.split(self.command_line)) > 0:
                    self.add_arg("path", str.split(self.command_line)[0])
                else:
                    self.add_arg("path", ".")


class LSCommand(CommandBase):
    cmd = "ls"
    needs_admin = False
    help_cmd = "ls"
    description = "Use Golang native commands to list a directory's contents"
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_remove_file = False
    is_upload_file = False
    author = "@Ne0nd0g"
    argument_class = LSArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        # Merlin jobs.NATIVE
        task.args.add_arg("type", 13, ParameterType.Number)

        # Arguments
        args = []
        arguments = task.args.get_arg("path")
        if arguments:
            args.append(arguments)

        # Merlin jobs.Command message type
        command = {
            "command": self.cmd,
            "args": args,
        }

        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("path")

        if debug:
            await MythicResponseRPC(task).user_output(f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
