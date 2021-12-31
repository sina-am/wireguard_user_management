from configuration import ConfigManager
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from models import UserModel, Base
from exceptions import *
from ipaddress import IPv4Address
import os


class WireGuardManager:
    def __init__(self, database_path, wireguard_config_path, public_server_address, dns):
        self.database_path = database_path
        self.wireguard_config_path = wireguard_config_path
        self.public_server_address = public_server_address
        self.cm = ConfigManager(wireguard_config_path, public_server_address, dns)
        self.session = self.initiate_database()

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

    # TODO: Automatically assign ip address
    def assign_address(self):
        pass

    def _check_if_assignable(self, address):
        for peer in self.cm.peers:
            if peer.address == address:
                return False
        return True

    def register_user(self, username, first_name, last_name, address):
        if not self._check_if_assignable(IPv4Address(address)):
            raise IPAddressAlreadyExist('please assign a new address')

        key_pair = self.generate_key_pair()
        self.cm.add_peer(address, key_pair['public'])
        config_file = self.cm.generate_config(address, key_pair['public'], key_pair['private'])
        user = UserModel(username=username,
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
        queryset = self.session.query(UserModel.public_key).filter(UserModel.username == username)
        if not queryset.first():
            raise UserDoesNotExist()
        public_key = queryset.first()[0]
        self.cm.remove_peer(public_key)
        queryset.delete()
        self.session.commit()
