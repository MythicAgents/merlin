
from merlin import MerlinJob, get_or_register_file
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
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
                required=False,
            )
        }

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                # This allows an operator to specify the name of an a file that was previously registered with Mythic
                # in place of providing the actual file
                args = str.split(self.command_line)
                if len(args) > 0:
                    self.add_arg("file_name", args[0], ParameterType.String)
                if len(args) > 1:
                    self.add_arg("path", args[1], ParameterType.String)
                else:
                    raise Exception('A file path was not provided as the second argument')


class UploadCommand(CommandBase):
    cmd = "upload"
    needs_admin = False
    help_cmd = "upload"
    description = "Upload a file to the host where the agent is running"
    version = 1
    supported_ui_features = ["file_browser:upload"]
    author = "@Ne0nd0g"
    argument_class = UploadArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        # Determine if a file or a file name was provided
        if task.args.get_arg("file") is None:
            # A file WAS NOT provided
            if task.args.has_arg("file_name"):
                file_name = task.args.get_arg("file_name")
                file_bytes = None
            else:
                raise Exception(f'A file or the name of a file was not provided')
        else:
            file_name = json.loads(task.original_params)["file"]
            file_bytes = task.args.get_arg("file")

        file = await get_or_register_file(task, file_name, file_bytes)

        # Merlin jobs.Command message type
        transfer = {
            "dest": task.args.get_arg("path"),
            "blob": base64.b64encode(file).decode("utf-8"),
            "download": True,  # False when the agent is uploading a file to C2 server
        }

        task.display_params = f'{file_name}\nDestination: {task.args.get_arg("path")}'

        task.args.add_arg("type", MerlinJob.FILE_TRANSFER, ParameterType.Number)
        task.args.add_arg("payload", json.dumps(transfer), ParameterType.String)
        task.args.remove_arg("file")
        task.args.remove_arg("path")

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
