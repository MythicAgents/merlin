from mythic_payloadtype_container.MythicCommandBase import *
import json


class SleepArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "time": CommandParameter(
                name="time",
                type=ParameterType.String,
                description="The amount of time for the agent to sleep between checkins."
                            "\r\n Use Go's time notation such as 30s for thirty seconds",
                value="30s",
                required=True,
            ),
        }

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("time", str.split(self.command_line)[0])


class SleepCommand(CommandBase):
    cmd = "sleep"
    needs_admin = False
    help_cmd = "sleep"
    description = "Change the amount of time the agent will sleep between checkins"
    version = 1
    author = "@Ne0nd0g"
    argument_class = SleepArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        # Merlin jobs.CONTROL
        task.args.add_arg("type", 11, ParameterType.Number)

        # Merlin jobs.Command message type
        command = {
            "command": self.cmd,
            "args": [task.args.get_arg("time")],
        }

        task.display_params = task.args.get_arg("time")

        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("time")

        return task

    async def process_response(self, response: AgentResponse):
        pass
