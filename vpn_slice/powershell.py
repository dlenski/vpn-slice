
# %%import os
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, IPv6Address, IPv6Interface, IPv6Network
from subprocess import Popen
import subprocess
import json
import sys
from typing import Any, List, Tuple, Union

from .util import get_executable

IP4or6Address = Union[IPv4Address, IPv6Address]

# %%

class Address:
    InterfaceAlias : str
    InterfaceIndex : int
    AddressFamily : str
    IPAddress : str
    PrefixLength : int
    Type : str


class Route:
    InterfaceAlias : str
    InterfaceIndex : int
    InterfaceMetric : int
    AddressFamily : str
    DestinationPrefix : str
    NextHop : str
    RouteMetric : int


class Adapter:
    InterfaceAlias : str
    InterfaceIndex : int
    Status : str
    MacAddress : str
    MtuSize : int
    InterfaceDescription : str
    DriverDescription : str


class DnsClientNrptRule:
    Name : str
    Namespace : str
    NameServers : str

def hasNetmask(address):
    return isinstance(address, IPv4Interface) \
            or isinstance(address, IPv6Interface) \
            or isinstance(address, IPv4Network) \
            or isinstance(address, IPv6Network)

# %%
class PowerShellProvider:
    ps : str
    proc : Union[Popen, None] = None
    breakingLine = "\x00\n"
    logMode : bool = True

    def __init__(self):
        self.ps = get_executable("powershell.exe")

    def setLogMode(self, mode: bool) -> None:
        self.logMode = mode;

    def runOneCommand(self, command: str) -> dict:
        if self.logMode:
            print(f"[one-off PS command] {command}", file=sys.stderr)
        proc = subprocess.Popen([self.ps, '-NoProfile', '-Command', '&{' + command + '}'], stdout=subprocess.PIPE)
        return json.loads(proc.stdout.read())

    def startPs(self) -> Any:
        self.proc = subprocess.Popen([self.ps, '-NoProfile', '-NoLogo', '-NonInteractive', '-Command', '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None, text=True)

    def executeCommand(self, command: str) -> None:
        if not self.proc or not self.proc.stdin:
            self.startPs()

        if self.logMode:
            print(f"[command] {command}", file=sys.stderr)
        # use double new-line, because some special commands (like command blocks & { ... })
        # need two empty (spaces are fine) to commit the commands
        self.proc.stdin.write(command + '; echo `0\n\n')
        self.proc.stdin.flush()
        return

    def readCommandRawOutput(self) -> str:
        output = ""
        for line in iter(self.proc.stdout.readline, ""):
            if self.logMode:
                print(line, file=sys.stderr)
            if (line == self.breakingLine):
                break
            output += line
        return output

    def executeAndReadRawCommandOutput(self, command) -> str:
        self.executeCommand(command)
        return self.readCommandRawOutput()

    def executeAndReadCommandOutput(self, command) -> dict or list:
        self.executeCommand(command)
        return json.loads(self.readCommandRawOutput())

    def readCommandOutput(self) -> dict:
        return json.loads(self.readCommandRawOutput())

    def Get_NetAdapter(self, InterfaceAlias: str) -> Adapter:
        if not InterfaceAlias:
            raise TypeError("InterfaceAlias can not be None")
        lead = "Get-NetAdapter -InterfaceAlias \"" + str(InterfaceAlias) + "\" | Select-Object "
        end = " | ConvertTo-Json -depth 1"
        cmd = lead + str.join(", ", Adapter().__annotations__.keys()) + end
        data = self.executeAndReadCommandOutput(cmd)
        ret = Adapter()
        ret.__dict__.update(data)
        return ret

    def Set_NetAdapterMtu(self, InterfaceAlias: str, mtu) -> str:
        if not InterfaceAlias:
            raise TypeError("InterfaceAlias can not be None")
        cmd = f"Set-NetIPInterface -InterfaceAlias \"{InterfaceAlias}\" -NlMtuBytes {mtu}"
        cmd += f" | Out-Null ; echo $?"
        data = self.executeAndReadRawCommandOutput(cmd)
        return data

    def New_NetIpAddress(self, InterfaceAlias: str, address: IP4or6Address) -> str:
        cmd = f"New-NetIPAddress -PolicyStore ActiveStore"
        if not InterfaceAlias:
            raise TypeError("InterfaceAlias can not be None")
        cmd += f" -InterfaceAlias \"{InterfaceAlias}\""
        if isinstance(address, IPv4Interface) or isinstance(address, IPv6Interface):
            cmd += f" -IPAddress {str(address.ip)} -PrefixLength {str(address.network.prefixlen)}"
        elif isinstance(address, IPv4Network) or isinstance(address, IPv6Network):
            cmd += f" -IPAddress {str(address.network_address)} -PrefixLength {str(address.prefixlen)}"
        else:
            cmd += f" -IPAddress {str(address)} -PrefixLength {str(address.max_prefixlen)}"
        cmd += f" | Out-Null ; echo $?"
        data = self.executeAndReadRawCommandOutput(cmd)
        return data
        
    def Remove_NetIpAddress(self, InterfaceAlias: str, address: IP4or6Address = None) -> str:
        cmd = f"Remove-NetIPAddress -Confirm:$false -PolicyStore ActiveStore"
        if not InterfaceAlias:
            raise TypeError("InterfaceAlias can not be None")
        cmd += f" -InterfaceAlias \"{InterfaceAlias}\""
        if address:
            if isinstance(address, IPv4Interface) or isinstance(address, IPv6Interface):
                cmd += f" -IPAddress {str(address.ip)} -PrefixLength {str(address.network.prefixlen)}"
            elif isinstance(address, IPv4Network) or isinstance(address, IPv6Network):
                cmd += f" -IPAddress {str(address.network_address)} -PrefixLength {str(address.prefixlen)}"
            else:
                cmd += f" -IPAddress {str(address)} -PrefixLength {str(address.max_prefixlen)}"
        cmd += f" | Out-Null ; echo $?"
        data = self.executeAndReadRawCommandOutput(cmd)
        return data

    def Remove_NetRoute(self,
            DestinationPrefix: IP4or6Address = None,
            InterfaceAlias: str = None,
            NextHop: IP4or6Address = None, # defaults to 0.0.0.0 (=> GW for that IF)
            ) -> str:
        cmd = f"Remove-NetRoute -Confirm:$false"
        if not DestinationPrefix:
            raise TypeError("DestinationPrefix can not be None")
        if hasNetmask(DestinationPrefix):
            cmd += f" -DestinationPrefix {str(DestinationPrefix)}"
        else:
            cmd += f" -DestinationPrefix {str(DestinationPrefix)}/{DestinationPrefix.max_prefixlen}"
        if InterfaceAlias:
            cmd += f" -InterfaceAlias \"{InterfaceAlias}\""
        if NextHop:
            cmd += f" -NextHop {str(NextHop)}"
        cmd += f" | Out-Null ; echo $?"
        data = self.executeAndReadRawCommandOutput(cmd)
        return data

    def Get_RouteToTarget(self, address) -> Tuple[Address, Route]:
        cmd = """& {
$src,$route = Find-NetRoute -RemoteIPAddress """ + str(address) + """;
$src | Select-Object """ + str.join(", ", Address().__annotations__.keys()) + """ | ConvertTo-Json -depth 1
echo `0
$route | Select-Object """ + str.join(", ", Route().__annotations__.keys()) + """ | ConvertTo-Json -depth 1
}"""
        addr = Address()
        route = Route()
        if True:
            data = self.executeAndReadCommandOutput(cmd)
            addr.__dict__.update(data)
        if True:
            data = self.readCommandOutput()
            route.__dict__.update(data)

        return (addr, route)

    def New_NetRoute(self, *,
            InterfaceAlias: str,
            DestinationPrefix: IP4or6Address,
            NextHop: IP4or6Address = None, # defaults to 0.0.0.0 (=> GW for that IF)
            RouteMetric: Union[int, None] = None
            ) -> str:
        # set these route to non-persistent
        cmd = f"New-NetRoute -PolicyStore ActiveStore"
        if not InterfaceAlias:
            raise TypeError("InterfaceAlias can not be None")
        cmd += f" -InterfaceAlias \"{InterfaceAlias}\""
        if NextHop:
            cmd += f" -NextHop {str(NextHop)}"
        if not DestinationPrefix:
            raise TypeError("DestinationPrefix can not be None")
        # joined together
        if hasNetmask(DestinationPrefix):
            cmd += f" -DestinationPrefix {str(DestinationPrefix)}"
        else:
            cmd += f" -DestinationPrefix {str(DestinationPrefix)}/{DestinationPrefix.max_prefixlen}"
        if RouteMetric:
            cmd += f" -RouteMetric {RouteMetric}"
        cmd += f" | Out-Null ; echo $?"
        # AddressFamily -> left to auto
        data = self.executeAndReadRawCommandOutput(cmd)
        return data

    def Add_DnsClientNrptRule(self, *,
            Namespace: str,
            NameServers: List[IP4or6Address or str]
            ) -> str:
        # set these route to non-persistent
        cmd = f"Add-DnsClientNrptRule "
        if not Namespace:
            raise TypeError("Namespace can not be None")
        cmd += f" -Namespace {Namespace}"
        if not NameServers or len(NameServers) == 0:
            raise TypeError("NameServers can not be None")
        addrstrs : List[str] = []
        for addr in NameServers:
                addrstrs.append(str(addr))
        cmd += f" -NameServers {str.join(', ', addrstrs)}"

        cmd += f" | Out-Null ; echo $?"
        # AddressFamily -> left to auto
        data = self.executeAndReadRawCommandOutput(cmd)
        return data

    def Get_DnsClientNrptRule(self, *,
            Name: str = None,
            ) -> List[DnsClientNrptRule]:
        # set these route to non-persistent
        cmd = f"Get-DnsClientNrptRule "
        if Name:
            cmd += f" -Name {Name}"
        cmd += f" | ConvertTo-Json -depth 1"
        # AddressFamily -> left to auto
        data = self.executeAndReadCommandOutput(cmd)
        # if it's single item
        if isinstance(data, dict):
            data = [data]
        ret = []
        for record in data:
            if record["NameServers"]:
                record["NameServers"] = record["NameServers"]["value"]
                if not isinstance(record["NameServers"], list):
                    record["NameServers"] = str.split(record["NameServers"], " ")
            retE = DnsClientNrptRule()
            retE.__dict__.update(record)
            ret.append(retE)
        return ret

    def Remove_DnsClientNrptRule(self, *,
            Name: str,
            ) -> str:
        # set these route to non-persistent
        cmd = f"Remove-DnsClientNrptRule -Force"
        if not Name:
            raise TypeError("Name can not be None")
        cmd += f" -Name \"{Name}\""
        cmd += f" | Out-Null ; echo $?"
        # AddressFamily -> left to auto
        data = self.executeAndReadRawCommandOutput(cmd)
        return data

