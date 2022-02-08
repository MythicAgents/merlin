
from merlin import MerlinJob
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import json

# Set to enable debug output to Mythic
debug = False


class StompArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="source",
                cli_name="source",
                display_name="Source File",
                type=ParameterType.String,
                description="The source file's date/time to copy",
                parameter_group_info=[ParameterGroupInfo(
                    required=True,
                    group_name="Default",
                    ui_position=0,
                )],
            ),
            CommandParameter(
                name="destination",
                cli_name="destination",
                display_name="Destination File",
                type=ParameterType.String,
                description="The destination filepath to apply the date/time stamp",
                parameter_group_info=[ParameterGroupInfo(
                    required=True,
                    ui_position=1,
                )],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = str.split(self.command_line)
                if len(args) > 0:
                    self.add_arg("source", args[0])
                if len(args) > 1:
                    self.add_arg("destination", args[1])


class StompCommand(CommandBase):
    cmd = "timestomp"
    needs_admin = False
    help_cmd = "timestomp"
    description = "Copy a file's creation date/time stamp to another file"
    version = 1
    author = "@Ne0nd0g"
    argument_class = StompArguments
    attackmapping = []
    attributes = CommandAttributes(
        spawn_and_injectable=False,
        supported_os=[SupportedOS.Windows, SupportedOS.Linux, SupportedOS.MacOS]
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = f'{task.args.get_arg("source")} {task.args.get_arg("destination")}'

        command = {
            "command": "touch",
            "args": ["touch", task.args.get_arg("source"), task.args.get_arg("destination")],
        }

        task.args.add_arg("type", MerlinJob.NATIVE, ParameterType.Number)
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("source")
        task.args.remove_arg("destination")

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
