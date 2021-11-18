import re
import os


class Peer:
    def __init__(self, address, public_key):
        self.address = address
        self.public_key = public_key

    def __eq__(self, other):
        if not isinstance(other, Peer):
            return NotImplemented
        if self.address == other.address or self.public_key == other.public_key:
            return True
        return False

    def __str__(self):
        return f'[Peer]\nPublicKey={self.public_key}\nAllowedIPs={self.address}\n'


class ConfigManager:
    def __init__(self, config_path, server_address, server_port, dns):
        with open(config_path, 'r') as fd:
            data = fd.read().replace(' ', '')
            self.header = data[:data.find('[Peer]')]
            # for keep config file neat
            if self.header[-1] != '\n':
                self.header += '\n'
        self.peers = []
        self.address_range = re.search('[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}', self.header).group(0)
        self._find_peers(data)
        self.config_path = config_path
        self.address = server_address
        self.port = server_port
        self.dns = dns

    def _write2file(self):
        with open(self.config_path, 'w') as fd:
            fd.write(self.header)
            for peer in self.peers:
                fd.write(str(peer))
        self.reload_service()

    def _find_peers(self, data):
        peers = re.finditer(
            '\[Peer\]\sPublicKey=.{43}=\sAllowedIPs=[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}\/[0-9]{0,2}', data)
        for peer in peers:
            public_key = re.search('=.{43}=', peer.group(0)).group(0)[1:]
            address = re.search('[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}\/[0-9]{0,2}', peer.group(0)).group(0)
            self.peers.append(Peer(address, public_key))

    def add_peer(self, address, public_key):
        new_peer = Peer(f'{address}/32', public_key)
        if new_peer in self.peers:
            raise ValueError('Peer already exist')
        self.peers.append(new_peer)
        self._write2file()

    def remove_peer(self, public_key):
        for peer in self.peers:
            if peer.public_key == public_key:
                self.peers.remove(peer)
                break
        self._write2file()

    def generate_config(self, address, public_key, private_key):
        return f'[Interface]\nAddress = {address}/32\nPrivateKey = {private_key}\n' \
               f'DNS = {self.dns}\n\n[Peer]\nPublicKey = {public_key}\nEndpoint' \
               f'= {self.address}:{self.port}\nAllowedIPs = 0.0.0.0/0\n'

    def reload_service(self):
        os.system(f'wg-quick down {self.config_path}')
        os.system(f'wg-quick up {self.config_path}')
