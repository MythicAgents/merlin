
from merlin import MerlinJob
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import json

# Set to enable debug output to Mythic
debug = False


class NetstatArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "protocol": CommandParameter(
                name="protocol",
                type=ParameterType.ChooseOne,
                description="Limit the netstat collection to the selected protocol",
                choices=["tcp", "udp"],
                ui_position=0,
                required=False,
            ),
        }

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = str.split(self.command_line)
                if len(args) > 0:
                    self.add_arg("protocol", args[0])


class NetstatCommand(CommandBase):
    cmd = "netstat"
    needs_admin = False
    help_cmd = "netstat"
    description = "List network connections (WINDOWS ONLY)"
    version = 1
    author = "@Ne0nd0g"
    argument_class = NetstatArguments
    attackmapping = []
    attributes = CommandAttributes(
        spawn_and_injectable=False,
        supported_os=[SupportedOS.Windows]
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = f'{task.args.get_arg("protocol")}'

        command = {
            "command": self.cmd,
        }

        if task.args.get_arg("protocol") is not None:
            if task.args.get_arg("protocol").lower() == "tcp":
                command["args"] = ["tcp"]
            elif task.args.get_arg("protocol").lower() == "udp":
                command["args"] = ["udp"]

        task.args.add_arg("type", MerlinJob.MODULE, ParameterType.Number)
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("protocol")

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
