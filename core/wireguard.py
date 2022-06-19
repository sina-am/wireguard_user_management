from operator import attrgetter

from core.encryption import generate_key_pair, generate_public_key
from core.configuration import ConfigManager
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from core.models import UserModel, Base
from core.exceptions import *
from ipaddress import IPv4Address, IPv4Network


class WireGuardManager(ConfigManager):
    def __init__(self, database_path, public_server_address, dns, *args, **kwargs):
        self.database_path = database_path
        self.session = self.initiate_database()
        self.public_server_address = IPv4Address(public_server_address)
        self.dns = IPv4Address(dns)
        super().__init__(*args, **kwargs)

    def initiate_database(self):
        engine = create_engine(f'sqlite:///{self.database_path}', echo=False)
        Base.metadata.create_all(engine)
        return sessionmaker(bind=engine)()
 
    def generate_config(self, address, peer_private_key):
        server_public_key = generate_public_key(self.interface.private_key)
        return f'[Interface]\nAddress = {address}\nPrivateKey = {peer_private_key}\n' \
               f'DNS = {self.dns}\n\n[Peer]\nPublicKey = {server_public_key}\nEndpoint' \
               f'= {self.public_server_address}:{self.interface.listening_port}\nAllowedIPs = 0.0.0.0/0\n'

    def assign_address(self):
        if self.peers:
            self.peers.sort(key=attrgetter('address'))
            last_address = self.peers[-1].address
            next_address = str(last_address.network_address+1)
        else:
            next_address = str(self.interface.address.network_address+1)
        return next_address

    def _check_if_assignable(self, address):
        for peer in self.peers:
            if peer.address == IPv4Network(address):
                return False
        return True

    def register_user(self, username, first_name, last_name, address=None):
        if address:
            if not self._check_if_assignable(address):
                raise IPAddressAlreadyExist('please assign a new address')
        else:
            address = self.assign_address()
        if self.get_user(username):
            raise UserAlreadyExist('Duplicate username')
            
        key_pair = generate_key_pair()
        self.add_peer(address, key_pair['public'])
        config_file = self.generate_config(address, key_pair['private'])
        user = UserModel(
            username=username,
            first_name=first_name,
            last_name=last_name,
            ipaddress=address,
            public_key=key_pair['public'],
            private_key=key_pair['private'],
            config_file=config_file
        )
        self.session.add(user)
        self.session.commit()

    def remove_user(self, username):
        queryset = self.session.query(UserModel).filter(UserModel.username == username)
        if not queryset.first():
            raise UserDoesNotExist()
        public_key = queryset.first().public_key
        queryset.delete()
        self.remove_peer(public_key)
        self.session.commit()

    def get_user(self, username):
        return self.session.query(UserModel).filter(UserModel.username == username).first()

    def get_users(self):
        return self.session.query(UserModel)