
from merlin import *
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import os
import json
import subprocess

# Set to enable debug output to Mythic
debug = False


class SRDIArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                display_name="DLL File",
                type=ParameterType.File,
                description="DLL to convert to shellcode",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="New File",
                    ui_position=0,
                    required=True,
                )],
            ),
            CommandParameter(
                name="filename",
                cli_name="input_dll",
                display_name="DLL File",
                type=ParameterType.ChooseOne,
                dynamic_query_function=get_file_list,
                description="DLL to convert to shellcode",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default",
                    ui_position=0,
                    required=True,
                )],
            ),
            CommandParameter(
                name="function-name",
                cli_name="f",
                display_name="Function Name",
                type=ParameterType.String,
                description="The function to call after DllMain",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Default",
                        ui_position=1,
                        required=False,
                    ),
                    ParameterGroupInfo(
                        group_name="New File",
                        ui_position=1,
                        required=False,
                    ),
                ],
            ),
            CommandParameter(
                name="user-data",
                cli_name="u",
                display_name="User Data",
                type=ParameterType.String,
                description="Data to pass to the target function",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Default",
                        ui_position=2,
                        required=False,
                    ),
                    ParameterGroupInfo(
                        group_name="New File",
                        ui_position=2,
                        required=False,
                    ),
                ],
            ),
            CommandParameter(
                name="clear-header",
                cli_name="c",
                display_name="Clear Header",
                type=ParameterType.Boolean,
                description="Clear the PE header on load",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Default",
                        ui_position=3,
                        required=False,
                    ),
                    ParameterGroupInfo(
                        group_name="New File",
                        ui_position=3,
                        required=False,
                    ),
                ],
            ),
            CommandParameter(
                name="obfuscate-imports",
                cli_name="i",
                display_name="Obfuscate Imports",
                description="Randomize import dependency load order",
                type=ParameterType.Boolean,
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Default",
                        ui_position=4,
                        required=False,
                    ),
                    ParameterGroupInfo(
                        group_name="New File",
                        ui_position=4,
                        required=False,
                    ),
                ],
            ),
            CommandParameter(
                name="import-delay",
                cli_name="d",
                display_name="Import Delay",
                description="Number of seconds to pause between loading imports",
                type=ParameterType.Number,
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Default",
                        ui_position=5,
                        required=False,
                    ),
                    ParameterGroupInfo(
                        group_name="New File",
                        ui_position=5,
                        required=False,
                    ),
                ],
            ),
            CommandParameter(
                name="method",
                cli_name="method",
                display_name="Execution Method",
                type=ParameterType.ChooseOne,
                choices=["createprocess", "self", "remote", "RtlCreateUserThread", "userapc"],
                description="The shellcode injection method to use. Use createprocess if you want output back",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Default",
                        ui_position=7,
                        required=False,
                    ),
                    ParameterGroupInfo(
                        group_name="New File",
                        ui_position=7,
                        required=False,
                    ),
                ],
            ),
            CommandParameter(
                name="pid",
                cli_name="pid",
                display_name="Process ID",
                type=ParameterType.Number,
                description="The Process ID (PID) to inject the shellcode into. Not used with the 'self' method",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Default",
                        ui_position=8,
                        required=False,
                    ),
                    ParameterGroupInfo(
                        group_name="New File",
                        ui_position=8,
                        required=False,
                    ),
                ],
            ),
            CommandParameter(
                name="spawnto",
                cli_name="spawnto",
                display_name="SpawnTo Program",
                type=ParameterType.String,
                description="The child process that will be started to execute the shellcode in. "
                            "Only used with the \"createprocess\" method",
                default_value="C:\\Windows\\System32\\WerFault.exe",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Default",
                        ui_position=9,
                        required=False,
                    ),
                    ParameterGroupInfo(
                        group_name="New File",
                        ui_position=9,
                        required=False,
                    ),
                ],
            ),
            CommandParameter(
                name="spawntoargs",
                cli_name="spawnto-args",
                display_name="SpawnTo Program Arguments",
                type=ParameterType.String,
                description="Argument to create the spawnto process with, if any. "
                            "Only used with the \"createprocess\" method",
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Default",
                        ui_position=10,
                        required=False,
                    ),
                    ParameterGroupInfo(
                        group_name="New File",
                        ui_position=10,
                        required=False,
                    ),
                ],
            ),
            CommandParameter(
                name="verbose",
                cli_name="v",
                display_name="Verbose",
                description="Show verbose output from Donut",
                type=ParameterType.Boolean,
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="Default",
                        ui_position=11,
                        required=False,
                    ),
                    ParameterGroupInfo(
                        group_name="New File",
                        ui_position=11,
                        required=False,
                    ),
                ],
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)


class SRDICommand(CommandBase):
    cmd = "srdi"
    needs_admin = False
    help_cmd = "srdi"
    description = "sRDI allows for the conversion of DLL files to position independent shellcode. " \
                  "It attempts to be a fully functional PE loader supporting proper section permissions, " \
                  "TLS callbacks, and sanity checks. It can be thought of as a shellcode PE loader strapped to a " \
                  "packed DLL. https://github.com/monoxgas/sRDI.\n" \
                  "Change the Parameter Group to \"Default\" to use a file that was previously registered with " \
                  "Mythic and \"New File\" to register and use a new file from your host OS.\n"
    version = 1
    author = "@Ne0nd0g"
    argument_class = SRDIArguments
    attackmapping = ["T1055"]
    attributes = CommandAttributes(
        spawn_and_injectable=False,
        supported_os=[SupportedOS.Windows]
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        if debug:
            await MythicRPC().execute(function_name="create_output", task_id=task.id, output=f'\n[DEBUG]Input task:{task}\n')

        dll_name, dll_uuid, dll = await get_file_contents(task)

        srdi_args = []
        if task.args.get_arg("function-name"):
            srdi_args.append("--function-name")
            srdi_args.append(task.args.get_arg("function-name"))
        if task.args.get_arg("user-data"):
            srdi_args.append("--user-data")
            srdi_args.append(task.args.get_arg("user-data"))
        if task.args.get_arg("clear-header"):
            srdi_args.append("--clear-header")
        if task.args.get_arg("obfuscate-imports"):
            srdi_args.append("--obfuscate-imports")
        if task.args.get_arg("import-delay"):
            srdi_args.append("--import-delay")
            srdi_args.append(f'{task.args.get_arg("import-delay")}')

        display = f'{dll_name} {srdi_args} Injection Method: {task.args.get_arg("method")} '
        if task.args.get_arg("method") == "createprocess":
            display += f'SpawnTo: {task.args.get_arg("spawnto")} ' \
                       f'SpawnTo Arguments: {task.args.get_arg("spawntoargs")} '
        elif task.args.get_arg("method") != "self":
            display += f'PID: {task.args.get_arg("pid")}'
        task.display_params = display

        if debug:
            await MythicRPC().execute(
                function_name="create_output",
                task_id=task.id,
                output=f'[DEBUG]Calling srdi() with args: {srdi_args}\n'
            )

        srdi_shellcode, srdi_result = srdi(base64.b64decode(dll), srdi_args)
        task.stdout += f'\n{srdi_result}'
        if task.args.get_arg("verbose"):
            await MythicRPC().execute(
                function_name="create_output",
                task_id=task.id,
                output=f'{srdi_result}'
            )

        command = {}
        if task.args.get_arg("method") == "createprocess":
            task.args.add_arg("type", MerlinJob.MODULE, ParameterType.Number)

            # 1. Shellcode
            # 2. SpawnTo Executable
            # 3. SpawnTo Arguments (must include even if empty string)

            # Merlin jobs.Command message type
            command = {
                "command": "createprocess",
                "args": [srdi_shellcode, task.args.get_arg("spawnto"), task.args.get_arg("spawntoargs")],
            }
            task.display_params += f'SpawnTo: {task.args.get_arg("spawnto")} {task.args.get_arg("spawntoargs")}'
        else:
            task.args.add_arg("type", MerlinJob.SHELLCODE, ParameterType.Number)

            # Merlin jobs.Command message type
            command = {
                "method": task.args.get_arg("method").lower(),
                "bytes": srdi_shellcode,
            }
            if task.args.get_arg("method") != "self":
                command["pid"] = task.args.get_arg("pid")

        task.args.add_arg("payload", json.dumps(command), ParameterType.String)
        task.args.remove_arg("file")
        task.args.remove_arg("filename")
        task.args.remove_arg("function-name")
        task.args.remove_arg("user-data")
        task.args.remove_arg("clear-header")
        task.args.remove_arg("obfuscate-imports")
        task.args.remove_arg("import-delay")
        task.args.remove_arg("method")
        task.args.remove_arg("verbose")
        task.args.remove_arg("pid")
        task.args.remove_arg("spawnto")
        task.args.remove_arg("spawntoargs")

        if debug:
            await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]Returned task:\r\n{task}\r\n')
        return task

    async def process_response(self, response: AgentResponse):
        pass


def srdi(dll, arguments):
    """Leverages the sRDI project to convert a Windows DLL into a reflective DLL as shellcode.

    The sRDI Python script must be previously installed at the fixed locations used in this function.
    sRDI Project: https://github.com/monoxgas/sRDI

    Parameters
    ----------
    dll : bytes
        The input Windows DLL that will be convert into shellcode
    arguments : list
        A list of arguments that will be passed to the Windows DLL

    Returns
    -------
    str
        The sRDI reflective DLL shellcode bytes as a Base64 string
    str
        The executed sRDI command line string followed by sRDI's STDOUT/STDERR text
    """
    srdi_args = ['python3', '/opt/merlin/data/src/sRDI/Python/ConvertToShellcode.py', '/tmp/srdi.dll'] + arguments

    # Write file to location in container
    with open('/tmp/srdi.dll', 'wb') as w:
        w.write(dll)

    result = subprocess.getoutput(" ".join(srdi_args))

    # Read sRDI output
    with open('/tmp/srdi.bin', 'rb') as output:
        srdi_bytes = output.read()

    # Close files
    w.close()
    output.close()

    # Remove files
    os.remove("/tmp/srdi.dll")
    os.remove("/tmp/srdi.bin")

    return base64.b64encode(srdi_bytes).decode("utf-8"), f'\n[sRDI]Commandline: {" ".join(srdi_args)}\n{result}'
