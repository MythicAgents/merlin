
from merlin import MerlinJob, get_or_register_file
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import json
import shlex

# Set to enable debug output to Mythic
debug = False


class MemfdArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "executable": CommandParameter(
                name="executable",
                type=ParameterType.File,
                description="The Linux executable (PE file) you want to run",
                ui_position=0,
                required=False,
            ),
            "arguments": CommandParameter(
                name="arguments",
                type=ParameterType.String,
                description="Arguments to start the executable with",
                ui_position=1,
                required=False,
            ),
        }

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                # This allows an operator to specify the name of an a file that was previously registered with Mythic
                # in place of providing the actual file
                args = shlex.split(self.command_line)
                if len(args) > 0:
                    self.add_arg("executable_name", args[0], ParameterType.String)
                if len(args) > 1:
                    self.add_arg("arguments", " ".join(args[1:]), ParameterType.String)


class MemfdCommand(CommandBase):
    cmd = "memfd"
    needs_admin = False
    help_cmd = "memfd"
    description = "Load a Linux executable file into memory (RAM) as an anonymous file using the memfd_create API " \
                  "call, execute it, and returns the results."
    version = 1
    author = "@Ne0nd0g"
    argument_class = MemfdArguments
    attackmapping = ["T1055"]
    attributes = CommandAttributes(
        spawn_and_injectable=False,
        supported_os=[SupportedOS.Linux]
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        # Determine if a file or a file name was provided
        if task.args.get_arg("executable") is None:
            # A file WAS NOT provided
            if task.args.has_arg("executable_name"):
                executable_name = task.args.get_arg("executable_name")
                executable_bytes = None
            else:
                raise Exception(f'A file or the name of a file was not provided')
        else:
            executable_name = json.loads(task.original_params)["executable"]
            executable_bytes = task.args.get_arg("executable")

        if task.args.get_arg("arguments") is not None:
            task.display_params = f'{executable_name} {task.args.get_arg("arguments")}'
        else:
            task.display_params = f'{executable_name}'

        executable = await get_or_register_file(task, executable_name, executable_bytes)

        # Arguments
        # 1. Base64 of Executable
        # 2+ Executable Arguments
        args = [
            base64.b64encode(executable).decode("utf-8"),
        ]

        if task.args.get_arg("arguments") is not None:
            for arg in task.args.get_arg("arguments").split():
                args.append(arg)

        # Merlin jobs.Command message type
        command = {
            "command": self.cmd,
            "args": args,
        }

        task.args.add_arg("type", MerlinJob.MODULE, ParameterType.Number)
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("executable")
        task.args.remove_arg("arguments")

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
