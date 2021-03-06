from CommandBase import *
import json
from MythicResponseRPC import *

# Set to enable debug output to Mythic
debug = False

class DownloadArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "file": CommandParameter(
                name="file",
                type=ParameterType.String,
                description="The file to download from the host where the agent is running",
                required=True,
            ),
        }

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("file", str.split(self.command_line)[0])


class DownloadCommand(CommandBase):
    cmd = "download"
    needs_admin = False
    help_cmd = "download"
    description = "Download a file from the host where the agent is running"
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = True
    is_remove_file = False
    is_upload_file = False
    author = "@Ne0nd0g"
    argument_class = DownloadArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        # Merlin jobs.CONTROL
        task.args.add_arg("type", 14, ParameterType.Number)

        # Merlin jobs.Command message type
        transfer = {
            "dest": task.args.get_arg("file"),
            "download": False,  # False when the agent is uploading a file to server
        }

        task.args.add_arg("payload", json.dumps(transfer), ParameterType.String)
        task.args.remove_arg("file")

        if debug:
            await MythicResponseRPC(task).user_output(f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
