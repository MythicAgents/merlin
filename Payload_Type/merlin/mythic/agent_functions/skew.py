
from merlin import MerlinJob
from mythic_payloadtype_container.MythicCommandBase import *
import json


class SkewArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="amount",
                cli_name="amount",
                display_name="Amount",
                type=ParameterType.String,
                description="The amount of skew, or jitter, to add to an agent callback",
                default_value="3000",
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


class SkewCommand(CommandBase):
    cmd = "skew"
    needs_admin = False
    help_cmd = "skew"
    description = "Change the amount of skew, or jitter, between agent callbacks"
    version = 1
    author = "@Ne0nd0g"
    argument_class = SkewArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = f'{task.args.get_arg("amount")}'

        # Merlin jobs.Command message type
        command = {
            "command": self.cmd,
            "args": [task.args.get_arg("amount")],
        }

        task.args.add_arg("type", MerlinJob.CONTROL, ParameterType.Number)
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("amount")

        return task

    async def process_response(self, response: AgentResponse):
        pass
