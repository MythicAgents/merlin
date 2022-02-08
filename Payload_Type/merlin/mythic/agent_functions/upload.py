
from merlin import *
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import json

# Set to enable debug output to Mythic
debug = False


class UploadArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                display_name="Source File",
                type=ParameterType.File,
                description="The file to upload to the host where the agent is running",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="New File",
                    ui_position=0,
                    required=True,
                )],
            ),
            CommandParameter(
                name="filename",
                cli_name="filename",
                display_name="Source File",
                type=ParameterType.ChooseOne,
                dynamic_query_function=get_file_list,
                description="The file to upload to the host where the agent is running",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default",
                    ui_position=0,
                    required=True,
                )],
            ),
            CommandParameter(
                name="path",
                type=ParameterType.String,
                description="The file path on the host where the agent is running that the file will be written to",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Default",
                        ui_position=1,
                        required=True,
                    ),
                    ParameterGroupInfo(
                        group_name="New File",
                        ui_position=1,
                        required=True,
                    ),
                ],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = str.split(self.command_line)
                if len(args) > 0:
                    self.add_arg("filename", args[0])
                if len(args) > 1:
                    self.add_arg("path", args[1])


class UploadCommand(CommandBase):
    cmd = "upload"
    needs_admin = False
    help_cmd = "upload"
    description = "Upload a file to the host where the agent is running" \
                  "\n\nChange the Parameter Group to \"Default\" to use a file that was previously registered with " \
                  "Mythic and \"New File\" to register and use a new file from your host OS.\n"
    version = 1
    supported_ui_features = ["file_browser:upload"]
    author = "@Ne0nd0g"
    argument_class = UploadArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        if debug:
            await MythicRPC().execute(function_name="create_output", task_id=task.id, output=f'\n[DEBUG]Input task:{task}')

        file_name, file_uuid, file = await get_file_contents(task)

        task.display_params = f'{file_name} to destination {task.args.get_arg("path")}'

        # Merlin jobs.Command message type
        transfer = {
            "dest": task.args.get_arg("path"),
            "blob": file,
            "download": True,  # False when the agent is uploading a file to C2 server
        }

        task.args.add_arg("type", MerlinJob.FILE_TRANSFER, ParameterType.Number)
        task.args.add_arg("payload", json.dumps(transfer), ParameterType.String)
        task.args.remove_arg("file")
        task.args.remove_arg("filepath")
        task.args.remove_arg("path")

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
