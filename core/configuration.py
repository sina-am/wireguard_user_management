from .exceptions import *
from ipaddress import IPv4Address, IPv4Network
from base64 import b64decode
import os

WIREGUARD_KEY_SIZE = 32


# TODO: Check if peer address is in wireguard network range
class Peer:
    def __init__(self, address, public_key):
        self.address = IPv4Network(address)
        if len(b64decode(public_key)) != WIREGUARD_KEY_SIZE:
            raise InvalidPublicKey('Invalid public key')
        self.public_key = public_key

    def __eq__(self, other):
        if isinstance(other, Peer):
            return self.address == other.address and self.public_key == other.public_key
        elif isinstance(other, str):
            return self.public_key == other
        else:
            raise NotImplemented

    def __str__(self):
        return f'[Peer]\nPublicKey={self.public_key}\nAllowedIPs={self.address}\n'


class Interface:
    def __init__(self, listening_port, address, **kwargs):
        if not listening_port.isnumeric():
            raise WireGuardConfigFileError('Invalid port number')

        self.listening_port = listening_port
        self.address = IPv4Network(address)
        self.directives = kwargs

    def __str__(self):
        string = f'[Interface]\nAddress={self.address}\nListenPort={self.listening_port}\n'
        for key, value in self.directives.items():
            string += f'{key}={value}\n'
        return string


class ConfigManager:
    def __init__(self, config_path, public_server_address, dns):
        self.config_path = config_path
        self.public_server_address = IPv4Address(public_server_address)
        self.dns = IPv4Address(dns)
        self.peers = []

        self._row_data = self._read_file()
        self.interface = self._find_interface()
        self._find_peers()

    def _find_interface(self):
        row_interface = self._row_data[:self._row_data.find('[Peer]')]
        directives = {}
        listen_port = None
        address = None
        for line in filter(None, row_interface.splitlines()[1:]):
            if line.startswith('ListenPort') and '=' in line:
                index = line.find('=')
                listen_port = line[index+1:].strip()
            elif line.startswith('Address') and '=' in line:
                index = line.find('=')
                address = line[index+1:].strip()
            elif '=' in line:
                index = line.find('=')
                directives.setdefault(line[:index].strip(), line[index+1:].strip())
            else:
                raise WireGuardConfigFileError('Invalid syntax')
        if listen_port and address:
            return Interface(listen_port, address, **directives)
        raise WireGuardConfigFileError('Invalid syntax')

    def _find_peers(self):
        # Check if there's any peer
        if self._row_data.find('[Peer]') == -1:
            return 
        row_peers = self._row_data[self._row_data.find('[Peer]'):].split('[Peer]')
        for row_peer in filter(None, row_peers):
            public_key, address = None, None
            for line in filter(None, row_peer.splitlines()):
                if line.startswith('PublicKey') and '=' in line:
                    index = line.find('=')
                    public_key = line[index+1:].strip()
                elif line.startswith('AllowedIPs') and '=' in line:
                    index = line.find('=')
                    address = line[index+1:].strip()
                else:
                    raise WireGuardConfigFileError('Invalid syntax')
            if public_key and address:
                self.peers.append(Peer(address, public_key))

    def _read_file(self):
        if os.path.isfile(self.config_path):
            if os.access(self.config_path, os.W_OK):
                with open(self.config_path, 'r') as fd:
                    return fd.read()
            raise PermissionError
        raise FileNotFoundError('Wireguard configuration file not found')

    def _write2file(self):
        with open(self.config_path, 'w') as fd:
            fd.write(str(self.interface))
            for peer in self.peers:
                fd.write(str(peer))

    def add_peer(self, address, public_key):
        new_peer = Peer(address, public_key)
        if new_peer in self.peers:
            raise PeerAlreadyExist()
        self.peers.append(new_peer)
        self._write2file()

    def remove_peer(self, public_key):
        try:
            self.peers.remove(public_key)
            self._write2file()
        except ValueError:
            raise PeerNotFound('Peer not found')

    def generate_config(self, address, public_key, private_key):
        if public_key not in self.peers:
            raise PeerNotFound('Peer not found')

        return f'[Interface]\nAddress = {address}\nPrivateKey = {private_key}\n' \
               f'DNS = {self.dns}\n\n[Peer]\nPublicKey = {public_key}\nEndpoint' \
               f'= {self.public_server_address}:{self.interface.listening_port}\nAllowedIPs = 0.0.0.0/0\n'

    # TODO: Check for syntax error before restarting service
    def reload_service(self):
        os.system(f'wg-quick down {self.config_path}')
        os.system(f'wg-quick up {self.config_path}')
