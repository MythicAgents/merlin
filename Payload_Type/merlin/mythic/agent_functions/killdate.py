from CommandBase import *
import json
from MythicResponseRPC import *

# Set to enable debug output to Mythic
debug = False


class KillDateArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "date": CommandParameter(
                name="date",
                type=ParameterType.String,
                description="The date, as an Unix epoch timestamp, that the agent should quit running",
                required=True,
            ),
        }

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("date", str.split(self.command_line)[0])


class KillDateCommand(CommandBase):
    cmd = "killdate"
    needs_admin = False
    help_cmd = "killdate"
    description = "The date, as an Unix epoch timestamp, that the agent should quit running.\r\nVisit: https://www.epochconverter.com/"
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_remove_file = False
    is_upload_file = False
    author = "@Ne0nd0g"
    argument_class = KillDateArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        # Merlin jobs.CONTROL
        task.args.add_arg("type", 11, ParameterType.Number)

        # Arguments
        a = "date"
        args = []
        arguments = task.args.get_arg(a)
        if arguments:
            args.append(arguments)

        # Merlin jobs.Command message type
        command = {
            "command": self.cmd,
            "args": args,
        }

        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg(a)

        if debug:
            await MythicResponseRPC(task).user_output(f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass