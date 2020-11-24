
# %%import os
from ipaddress import IPv4Address, IPv6Address
from subprocess import Popen
import subprocess
import json
from typing import Any, Tuple, Union

from .util import get_executable

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

# %%
class PowerShellProvider:
    ps : str
    proc : Union[Popen, None] = None
    breakingLine = "\x00\n"

    def __init__(self):
        self.ps = get_executable("powershell.exe")
        
    def runOneCommand(self, command) -> dict:
        proc = subprocess.Popen([self.ps, '-NoProfile', '-Command', '&{' + command + '}'], stdout=subprocess.PIPE)
        return json.loads(proc.stdout.read())
       
    def startPs(self) -> Any:
        self.proc = subprocess.Popen([self.ps, '-NoProfile', '-NoLogo', '-NonInteractive', '-Command', '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None, text=True)

    def executeCommand(self, command) -> None:
        if not self.proc or not self.proc.stdin:
            self.startPs()
        
        # use double new-line, because some special commands (like command blocks & { ... }) 
        # need two empty (spaces are fine) to commit the commands
        self.proc.stdin.write(command + '; echo `0\n\n')
        self.proc.stdin.flush()
        return
    
    def readCommandRawOutput(self) -> str:
        output = ""
        for line in iter(self.proc.stdout.readline, ""):
            if (line == self.breakingLine):
                break
            output += line
        return output
        
    def executeAndReadRawCommandOutput(self, command) -> str:
        self.executeCommand(command)
        return self.readCommandRawOutput()

    def executeAndReadCommandOutput(self, command) -> dict:
        self.executeCommand(command)
        return json.loads(self.readCommandRawOutput())

    def readCommandOutput(self) -> dict:
        return json.loads(self.readCommandRawOutput())

    def Get_NetAdapter(self, InterfaceAlias: str) -> Adapter:
        lead = "Get-NetAdapter -InterfaceAlias " + str(InterfaceAlias) + " | Select-Object "
        end = " | ConvertTo-Json -depth 1"
        cmd = lead + str.join(", ", Adapter().__annotations__.keys()) + end
        data = self.executeAndReadCommandOutput(cmd)
        ret = Adapter()
        ret.__dict__.update(data)
        return ret

    def Set_NetAdapterMtu(self, InterfaceAlias: str, mtu) -> str:
        cmd = f"Set-NetIPInterface -InterfaceAlias {InterfaceAlias} -NlMtuBytes {mtu}"
        cmd += f" | Out-Null ; echo $?"
        data = self.executeAndReadRawCommandOutput(cmd)
        return data

    def New_NetIpAddress(self, InterfaceAlias: str, address: Union[IPv4Address, IPv6Address]) -> str:
        cmd = f"New-NetIPAddress -InterfaceAlias {InterfaceAlias}"
        if isinstance(address, IPv4Address):
            cmd += f" -IPAddress {str(address)} -PrefixLength {str(address.max_prefixlen)}"
        if isinstance(address, IPv6Address):
            cmd += f" -IPAddress {str(address.ip)} -PrefixLength {str(address.network.prefixlen)}"
        cmd += f" | Out-Null ; echo $?"
        data = self.executeAndReadRawCommandOutput(cmd)
        return data

    def Remove_NetRoute(self, 
            DestinationPrefix: Union[IPv4Address, IPv6Address, None] = None,
            InterfaceAlias: Union[str, None] = None
            ) -> str:
        cmd = f"Remove-NetRoute"
        if DestinationPrefix:    
            if isinstance(DestinationPrefix, IPv4Address):
                cmd += f" -DestinationPrefix {str(DestinationPrefix)}/{str(DestinationPrefix.max_prefixlen)}"
            if isinstance(DestinationPrefix, IPv6Address):
                cmd += f" -DestinationPrefix {str(DestinationPrefix.ip)}/{str(DestinationPrefix.network.prefixlen)}"  
        if InterfaceAlias:
            cmd += f" -InterfaceAlias {InterfaceAlias}"
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
            DestinationPrefix: Union[IPv4Address, IPv6Address], 
            NextHop: Union[IPv4Address, IPv6Address, None] = None, # defaults to 0.0.0.0 (=> GW for that IF)
            RouteMetric: Union[int, None] = None
            ) -> str:
        # set these route to non-persistent
        cmd = f"New-NetRoute -PolicyStore ActiveStore"
        if not DestinationPrefix:
            raise TypeError("DestinationPrefix can not be None")        
        if isinstance(DestinationPrefix, IPv4Address):
            cmd += f" -DestinationPrefix {str(DestinationPrefix)}/{str(DestinationPrefix.max_prefixlen)}"
        if isinstance(DestinationPrefix, IPv6Address):
            cmd += f" -DestinationPrefix {str(DestinationPrefix.ip)}/{str(DestinationPrefix.network.prefixlen)}"  
        if not InterfaceAlias:
            raise TypeError("InterfaceAlias can not be None")
        cmd += f" -InterfaceAlias {InterfaceAlias}"
        if NextHop:
            cmd += f" -NextHop {str(NextHop)}"
        if RouteMetric:
            cmd += f" -RouteMetric {RouteMetric}"
        cmd += f" | Out-Null ; echo $?"
        # AddressFamily -> left to auto
        data = self.executeAndReadRawCommandOutput(cmd)
        return data

