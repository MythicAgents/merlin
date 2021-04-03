from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicResponseRPC import *
import json

# Set to enable debug output to Mythic
debug = False


class RunArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "arguments": CommandParameter(
                name="arguments",
                type=ParameterType.String,
                description="Arguments to start the executable with",
                required=False,
            ),
            "executable": CommandParameter(
                name="executable",
                type=ParameterType.String,
                description="The executable program to start",
                value="whoami",
                required=True,
            ),
        }

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = str.split(self.command_line)
                self.add_arg("executable", args[0])
                self.add_arg("arguments", " ".join(args[1:]))


class RunCommand(CommandBase):
    cmd = "run"
    needs_admin = False
    help_cmd = "run"
    description = "Run the executable with the provided arguments and return the results"
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_remove_file = False
    is_upload_file = False
    author = "@Ne0nd0g"
    argument_class = RunArguments
    attackmapping = ["T1106"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:

        # Executable Arguments
        args = []
        # TODO Handle argument parsing when quotes and escapes are used
        arguments = task.args.get_arg("arguments").split()
        if len(arguments) == 1:
            args.append(arguments[0])
        elif len(arguments) > 1:
            for arg in arguments:
                args.append(arg)

        # Merlin jobs.Command message type
        command = {
            "command": task.args.get_arg("executable"),
            "args": args,
        }

        task.args.add_arg("type", 10, ParameterType.Number)  # jobs.CMD = 10
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        
        # Remove everything except the Merlin data
        task.args.remove_arg("executable")
        task.args.remove_arg("arguments")

        if debug:
            await MythicResponseRPC(task).user_output(f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
