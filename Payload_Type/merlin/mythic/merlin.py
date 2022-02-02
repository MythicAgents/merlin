
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import base64
import os
import shlex
import subprocess

# Set to enable debug output to Mythic
debug = False


class MerlinJob:
    """Merlin message job types from https://github.com/Ne0nd0g/merlin/blob/master/pkg/jobs/jobs.go"""
    CMD = 10
    CONTROL = 11
    SHELLCODE = 12
    NATIVE = 13
    FILE_TRANSFER = 14
    MODULE = 16


def donut(pe, arguments):
    """Leverages the https://github.com/Binject/go-donut project to convert a Windows PE into shellcode

    This function requires that the "go-donut" compiled executable is available in the PATH environment variable.

    Parameters
    ----------
    pe : bytes
        The input Windows PE, as bytes, that donut will convert to shellcode. Used with the donut "--in" argument
    arguments : dict
        The go-donut specific arguments.

    Returns
    -------
    str
        Base64 encoded go-donut output shellcode
    str
        The executed go-donut command line string followed by go-donut's STDOUT/STDERR text
    """
    donut_args = ['go-donut']

    for arg, value in arguments.items():
        if value:
            if arg.lower() in ["verbose", "thread", "unicode"]:
                donut_args.append("--"+arg)
            elif arg.lower() == "params":
                donut_args.append('--params')
                if value.startswith("-"):
                    # Removed shlex.quote() because it was not quoting arguments like: -group=system
                    # go-donut was interpreting it as an argument for itself
                    donut_args.append(f'"{value}"')
                else:
                    donut_args.append(shlex.quote(value))
            else:
                donut_args.append("--" + arg)
                donut_args.append(value)

    # Clear any old files
    if os.path.exists('input.exe'):
        os.remove("input.exe")
    if os.path.exists('loader.bin'):
        os.remove("loader.bin")

    # Write file to location in container
    if 'in' not in arguments and len(pe) > 0:
        with open('input.exe', 'wb') as w:
            w.write(pe)
        w.close()
        donut_args.append('--in')
        donut_args.append('input.exe')
    elif 'in' not in arguments and len(pe) == 0:
        raise Exception(f'A PE files a bytes OR the "--in" argument was not provided.')

    result = subprocess.getoutput(" ".join(donut_args))

    # Read Donut output
    with open('loader.bin', 'rb') as output:
        donut_bytes = output.read()
    output.close()

    # Remove files
    if os.path.exists('input.exe'):
        os.remove("input.exe")
    os.remove("loader.bin")

    # Return Donut shellcode Base64 encoded
    return [base64.b64encode(donut_bytes).decode("utf-8"), f'[DONUT]\nCommandline: {" ".join(donut_args)}\r\n{result}']


async def get_or_register_file(task, filename, file_bytes):
    """Registers an unregistered file with Mythic or returns the file if it was previously registered.

    Parameters
    ----------
    task : Mythic
        The Mythic task calling the function
    filename : str
        The name of a file to register or to see if it is registered
    file_bytes : bytes
        The input file, as bytes, to register with Mythic

    Returns
    -------
    bytes
        The registered file as bytes
    """

    # Check to see if the assembly was previously registered. If not, register it
    if filename is not None:
        # Check to see if this file name was previously registered to Mythic
        resp = await MythicRPC().execute(
            "get_file",
            task_id=task.id,
            filename=filename,
            limit_by_callback=False,
            get_contents=True,
        )

        if resp.status != MythicStatus.Success:
            raise Exception(f'Unhandled MythicRPC response for "get_file": {resp.status}')

        if len(resp.response) > 0:
            # The file WAS previously registered with Mythic
            if debug:
                await MythicRPC().execute(
                    "create_output",
                    task_id=task.id,
                    output=f'\n[DEBUG]Response:\n{resp}, Content length: {len(resp.response[0]["contents"])}',
                )

            # TODO Check the file hash to make sure it matches
            meta = resp.response[0]

            await MythicRPC().execute("create_output", task_id=task.id,
                                      output=f'Using previously registered file: {meta["filename"]}, '
                                             f'Agent File ID: {meta["agent_file_id"]}, '
                                             f'SHA1: {meta["sha1"]}')

            task.stdout += f'\nUsing previously registered file {meta["filename"]} SHA1: {meta["sha1"]}\n'
            return base64.b64decode(meta["contents"])
        else:
            # The file WAS NOT previously registered
            if file_bytes is not None:
                # Register the file with Mythic
                file_resp = await MythicRPC().execute("create_file",
                                                      task_id=task.id,
                                                      file=base64.b64encode(file_bytes).decode("utf-8"),
                                                      saved_file_name=filename,
                                                      delete_after_fetch=False,
                                                      )
                if debug:
                    await MythicRPC().execute(
                        "create_output",
                        task_id=task.id,
                        output=f'\n[DEBUG]RPC "create_file" response:\n{file_resp}',
                    )

                if file_resp.status != MythicStatus.Success:
                    raise Exception(f'Failed to register "{filename}" file with Mythic: {file_resp.error}')

                # File was successfully registered
                meta = file_resp.response
                await MythicRPC().execute("create_output", task_id=task.id,
                                          output=f'Registered {meta["filename"]} '
                                                 f'Agent File ID: {meta["agent_file_id"]} '
                                                 f'SHA1: {meta["sha1"]} with Mythic')
                task.stdout += f'\nRegistered {meta["filename"]}, SHA1: {meta["sha1"]} with Mythic\n'
                return file_bytes
            else:
                raise Exception(
                    f'The "{filename}" is not registered with Mythic and a file was not provided'
                )
    else:
        raise Exception(f'A required filename was not provided')


async def get_file_list(callback: dict) -> [str]:
    """
    Get a unique list of file names that have been previously registered with Mythic.
    This function is typically used to populate dropdown menus for agent commands

    :param callback:
    :return:
    """
    resp = await MythicRPC().execute(
        function_name="get_file",
        callback_id=callback["id"],
        limit_by_callback=False,
        get_contents=False,
        filename="",  # Return all filenames
        max_results=-1  # Return all results
    )
    if resp.status == MythicRPCStatus.Success:
        file_names = []
        for f in resp.response:
            if f["filename"] not in file_names:
                file_names.append(f["filename"])
        file_names.sort()
        return file_names
    else:
        return []


async def get_file_contents(task: MythicTask) -> (str, str, str):
    """
    Parse a MythicTask to determine if a new file or previously registered file was selected and return its contents.
    The task MUST include either a file or filename argument where file is a UUID and filename is just a string
    Returns Filename, File UUID, and File contents as a Base64 string

    :param task:
    :return:
    """

    # Determine if a file or a file name was provided
    if task.args.get_arg("filename") is not None:
        pre = await MythicRPC().execute(
            function_name="get_file",
            task_id=task.id,
            filename=task.args.get_arg("filename"),
            get_contents=False,
            max_results=-1,
            limit_by_callback=False,
        )

        if len(pre.response) > 1:
            await MythicRPC().execute(
                function_name="create_output",
                task_id=task.id,
                output=f'Mythic returned {len(pre.response)} files. Only the first one will be used.\n'
            )

        resp = await MythicRPC().execute(
            function_name="get_file",
            task_id=task.id,
            filename=task.args.get_arg("filename"),
            get_contents=True,
            max_results=1,
            limit_by_callback=False,
        )
    elif task.args.get_arg("file") is not None:
        resp = await MythicRPC().execute(
            function_name="get_file",
            task_id=task.id,
            file_id=task.args.get_arg("file"),
            get_contents=True,
            limit_by_callback=False,
        )
    else:
        raise Exception("A file, or the name of a previously registered file name with Mythic, was not provided")

    if resp.status != MythicRPCStatus.Success:
        raise Exception(f'there was an error making the Mythic \"get_file\" RPC:\n{resp}')

    if len(resp.response) <= 0 and task.args.get_arg("file") is not None:
        raise Exception(f'The Mythic \"get_file\" RPC for file UUID {task.args.get_arg("file")} returned 0 results')
    elif len(resp.response) <= 0 and task.args.get_arg("filename") is not None:
        await MythicRPC().execute("create_output", task_id=task.id, output=f'[DEBUG]RPC Response: {resp}\n')
        raise Exception(f'The Mythic \"get_file\" RPC for the \"{task.args.get_arg("filename")}\" file returned 0 results.')

    filename = resp.response[0]["filename"]
    file_uuid = resp.response[0]["agent_file_id"]
    contents = resp.response[0]["contents"]
    sha = resp.response[0]["sha1"]

    if task.args.get_arg("filename") is not None:
        await MythicRPC().execute(
            function_name="create_output",
            task_id=task.id,
            output=f'Using previously registered file {filename} with ID {file_uuid} and SHA1: {sha}\n'
        )
    elif task.args.get_arg("file") is not None:
        await MythicRPC().execute(
            function_name="create_output",
            task_id=task.id,
            output=f'Registered new file \"{filename}\" with ID {file_uuid} and SHA1: {sha}\n'
        )

    return filename, file_uuid, contents
