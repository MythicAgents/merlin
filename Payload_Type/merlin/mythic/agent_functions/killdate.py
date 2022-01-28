
from merlin import MerlinJob
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import json

# Set to enable debug output to Mythic
debug = False


class KillDateArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="date",
                cli_name="date",
                display_name="Kill Date",
                type=ParameterType.String,
                description="The date, as a Unix epoch timestamp, that the agent should quit running",
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


class KillDateCommand(CommandBase):
    cmd = "killdate"
    needs_admin = False
    help_cmd = "killdate"
    description = "The date, as a Unix epoch timestamp, that the agent should quit running." \
                  "\r\nVisit: https://www.epochconverter.com/"
    version = 1
    author = "@Ne0nd0g"
    argument_class = KillDateArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = f'{task.args.get_arg("date")}'

        # Merlin jobs.Command message type
        command = {
            "command": self.cmd,
            "args": [task.args.get_arg("date")],
        }

        task.args.add_arg("type", MerlinJob.CONTROL, ParameterType.Number)
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("date")

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
