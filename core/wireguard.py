from operator import attrgetter
from .configuration import ConfigManager
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from .models import UserModel, Base
from .exceptions import *
from ipaddress import IPv4Network
import os


class WireGuardManager(ConfigManager):
    def __init__(self, database_path, *args, **kwargs):
        self.database_path = database_path
        self.session = self.initiate_database()
        super().__init__(*args, **kwargs)

    def initiate_database(self):
        engine = create_engine(f'sqlite:///{self.database_path}', echo=False)
        Base.metadata.create_all(engine)
        return sessionmaker(bind=engine)()

    # TODO: Not using wg
    @staticmethod
    def generate_key_pair():
        private_key = os.popen('wg genkey', 'r').read().replace('\n', '')
        with open('/tmp/private.key', 'w') as fd:
            fd.write(private_key)
        public_key = os.popen('wg pubkey < /tmp/private.key', 'r').read().replace('\n', '')
        os.remove('/tmp/private.key')
        return {'private': private_key, 'public': public_key}

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
            
        key_pair = self.generate_key_pair()
        self.add_peer(address, key_pair['public'])
        config_file = self.generate_config(address, key_pair['public'], key_pair['private'])
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