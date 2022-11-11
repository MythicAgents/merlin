
from merlin import MerlinJob
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import json

# Set to enable debug output to Mythic
debug = False


class ParrotArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="client",
                cli_name="client",
                display_name="client",
                type=ParameterType.String,
                description="The string of TLS client to mimic or parrot from the "
                            "https://github.com/refraction-networking/utls library. Examples include HelloChrome_Auto "
                            "or HelloFirefox_55",
                value="",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default",
                    ui_position=0,
                    required=True,
                )],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("parrot", str.split(self.command_line)[0])


class ParrotCommand(CommandBase):
    cmd = "parrot"
    needs_admin = False
    help_cmd = "parrot"
    description = "Mimic or parrot a TLS client from the https://github.com/refraction-networking/utls library. " \
                  "Examples include HelloChrome_Auto or HelloFirefox_55"
    version = 1
    author = "@Ne0nd0g"
    argument_class = ParrotArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = f'{task.args.get_arg("client")}'

        # Merlin jobs.Command message type
        command = {
            "command": self.cmd,
            "args": [task.args.get_arg("client")],
        }

        task.args.add_arg("type", MerlinJob.CONTROL, ParameterType.Number)
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("client")

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
