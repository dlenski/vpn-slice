from .provider import FirewallProvider, TunnelPrepProvider


class NoFirewallProvider(FirewallProvider):
    def configure_firewall(self, device):
        pass

    def deconfigure_firewall(self, device):
        pass


class NoTunnelPrepProvider(TunnelPrepProvider):
    def create_tunnel(self):
        pass

    def prepare_tunnel(self):
        pass
