from .provider import FirewallProvider


class NoFirewallProvider(FirewallProvider):
    def configure_firewall(self, device):
        pass

    def deconfigure_firewall(self, device):
        pass


class NoTunnelCheckProvider(FirewallProvider):
    def prepare_tunnel(self):
        pass
