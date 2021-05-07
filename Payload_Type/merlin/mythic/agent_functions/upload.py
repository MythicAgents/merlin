from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicResponseRPC import *
import json

# Set to enable debug output to Mythic
debug = False


class UploadArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "path": CommandParameter(
                name="path",
                type=ParameterType.String,
                description="The file path on the host where the agent is running that the file will be written to",
                ui_position=1,
                required=True,
            ),
            "file": CommandParameter(
                name="file",
                type=ParameterType.File,
                description="The file to upload to the host where the agent is running",
                ui_position=0,
                required=True,
            )
        }

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("path", str.split(self.command_line)[0])


class UploadCommand(CommandBase):
    cmd = "upload"
    needs_admin = False
    help_cmd = "upload"
    description = "Upload a file to the host where the agent is running"
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_remove_file = False
    is_upload_file = True
    author = "@Ne0nd0g"
    argument_class = UploadArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        # Merlin jobs.CONTROL
        task.args.add_arg("type", 14, ParameterType.Number)

        # Merlin jobs.Command message type
        transfer = {
            "dest": task.args.get_arg("path"),
            "blob": base64.b64encode(task.args.get_arg("file")).decode("utf-8"),
            "download": True,  # False when the agent is uploading a file to server
        }

        task.display_params = f'{json.loads(task.original_params)["file"]}\nDestination: {task.args.get_arg("path")}'

        task.args.add_arg("payload", json.dumps(transfer), ParameterType.String)
        task.args.remove_arg("file")
        task.args.remove_arg("path")

        if debug:
            await MythicResponseRPC(task).user_output(f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
