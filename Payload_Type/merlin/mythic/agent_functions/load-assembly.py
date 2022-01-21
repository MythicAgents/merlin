
from merlin import MerlinJob, get_or_register_file
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import json

# Set to enable debug output to Mythic
debug = False


class LoadAssemblyArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            CommandParameter(
                name="assembly",
                type=ParameterType.File,
                description="The .NET assembly to load into the default AppDomain",
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
                self.add_arg("assembly_name", str.split(self.command_line)[0], ParameterType.String)


class LoadAssemblyCommand(CommandBase):
    cmd = "load-assembly"
    needs_admin = False
    help_cmd = "load-assembly"
    description = "Load a .NET assembly into the Agent's process that can be executed multiple times without having " \
                  "to transfer the assembly over the network each time"
    version = 1
    author = "@Ne0nd0g"
    argument_class = LoadAssemblyArguments
    attackmapping = []
    attributes = CommandAttributes(
        spawn_and_injectable=False,
        supported_os=[SupportedOS.Windows]
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
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

        task.display_params = assembly_name

        assembly = await get_or_register_file(task, assembly_name, assembly_bytes)

        # Arguments
        # 1. CLR command: load-assembly
        # 2. Base64 of .Net Assembly
        # 3. Assembly Name
        args = [
            self.cmd,
            base64.b64encode(assembly).decode("utf-8"),
            assembly_name,
        ]

    # Merlin jobs.Command message type
        command = {
            "command": "clr",
            "args": args,
        }

        task.args.add_arg("type", MerlinJob.MODULE, ParameterType.Number)
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("assembly")

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Filename: {len(args)}')
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass
