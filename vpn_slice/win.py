import os
import pathlib
import portalocker
import re
import subprocess
from ipaddress import ip_network

from .posix import HostsFileProvider, PythonOsProcessProvider
from .provider import RouteProvider
from .powershell import PowerShellProvider

if not '_psp' in globals():
    global _psp
    _psp = PowerShellProvider()

# DONE
class WinProcessProvider(PythonOsProcessProvider):
    # DONE
    def __init__(self):
        self.psp = _psp

    def pid2exe(self, pid):
        cmd = str.join(" ",
            ["Get-CimInstance",
            "Win32_Process",
            "-Filter",
            "ProcessId=" + str(pid),
            "|",
            "select",
            "Path",
            "|",
            "ConvertTo-Json"])
        info = self.psp.executeAndReadCommandOutput(cmd)
        try:
            return info["Path"]
        except IndexError:
            return None

    def ppid_of(self, pid=None):
        if pid is None:
            return os.getppid()
        
        cmd = str.join(" ",
            ["Get-CimInstance",
            "Win32_Process",
            "-Filter",
            "ProcessId=" + str(pid),
            "|",
            "select",
            "ParentProcessId",
            "|",
            "ConvertTo-Json"])
        info = self.psp.executeAndReadCommandOutput(cmd)
        try:
            return int(info["ParentProcessId"])
        except IndexError:
            return None


class WinHostsFileProvider(HostsFileProvider):
    def __init__(self):
        try:
            windir = pathlib.Path(os.environ["WINDIR"])
        except KeyError:
            raise OSError("Cannot read WINDIR environment variable")
        super().__init__(
            os.path.join(windir / "System32" / "drivers" / "etc" / "hosts")
        )

    def lock_hosts_file(self, hostf):
        portalocker.lock(hostf, portalocker.LOCK_EX)

class WinRouteProvider(RouteProvider):
    def __init__(self):
        self.psp = _psp
    
    # TODO, https://superuser.com/questions/925790/what-is-the-unix-equivalent-to-windows-command-route-add
    # TODO destination can be IP or IP with mask, convert that
    def add_route(self, destination, *, via=None, dev=None, src=None, mtu=None):
        print("add", f"dest {destination}, via {via}, dev {dev}, src {src}, mtu {mtu}")
        # we ignore per-route-MTU on Windows!
        # we ignore src on Windows, as the source address is calculated automatically 
        #   as the numerically lowest IP with SkipAsSource=false
        # see for example http://www.confusedamused.com/notebook/source-ip-address-preference-with-multiple-ips-on-a-nic
        # https://social.technet.microsoft.com/wiki/contents/articles/30857.source-ip-address-preference-with-multiple-ips-on-a-nic.aspx
        
        success = bool(self.psp.New_NetRoute(InterfaceAlias=dev, NextHop=via, DestinationPrefix=destination))
        return success

    replace_route = add_route

    def remove_route(self, destination):
        print("delete route", destination)
        success = bool(self.psp.Remove_NetRoute(DestinationPrefix=destination))
        return success

    def remove_all_routes(self, device):
        print("delete routes on device", device)
        success = bool(self.psp.Remove_NetRoute(InterfaceAlias=device))
        return success

    def get_route(self, destination):
        srcAddr, route = self.psp.Get_RouteToTarget(destination)
        ret =  {
            "via" : route.NextHop,
            "dev" : route.InterfaceAlias,
            "src" : srcAddr.IPAddress,
            "mtu" : None # possibly: self.get_link_info(route.InterfaceAlias)["mtu"]
        }
        return ret

    # TODO https://stackoverflow.com/questions/9739156/how-to-flush-route-table-in-windows/17860876
    def flush_cache(self):
        pass

    def get_link_info(self, device):
        print("get_link_info", device)
        adapterInfo = self.psp.Get_NetAdapter(device)
        if not adapterInfo.InterfaceAlias:
            return None
        ret = {
            "state": "UP" if adapterInfo.Status == "Up" else "DOWN",
            "mtu": adapterInfo.MtuSize
        }
        return ret

    def set_link_info(self, device, state, mtu=None):
        print("set_link_info", device, state, mtu)
        # ignores state
        if mtu:
            success = bool(self.psp.Set_NetAdapterMtu(device, mtu))
            return success

    # TODO
    def add_address(self, device, address):
        print("add_address", device, address)
        success = bool(self.psp.New_NetIpAddress(device, address))
        return success
