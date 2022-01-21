
from merlin import MerlinJob
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import json

# Set to enable debug output to Mythic
debug = False


class LSArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            CommandParameter(
                name="path",
                type=ParameterType.String,
                description="The directory path to list the contents of",
                default_value=".",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default",
                    ui_position=0,
                    required=False,
                )],
            ),
        }

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                if len(str.split(self.command_line)) > 0:
                    self.add_arg("path", str.split(self.command_line)[0])
                else:
                    self.add_arg("path", ".")


class LSCommand(CommandBase):
    cmd = "ls"
    needs_admin = False
    help_cmd = "ls"
    description = "Use Golang native commands to list a directory's contents"
    version = 1
    author = "@Ne0nd0g"
    argument_class = LSArguments
    attackmapping = ["T1083"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = f'{task.args.get_arg("path")}'

        # Arguments
        args = []
        arguments = task.args.get_arg("path")
        if arguments:
            args.append(arguments)

        # Merlin jobs.Command message type
        command = {
            "command": self.cmd,
            "args": args,
        }

        task.args.add_arg("type", MerlinJob.NATIVE, ParameterType.Number)
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("path")

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
