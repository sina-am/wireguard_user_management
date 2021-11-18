from database import DataBase
from configuration import ConfigManager
from ipaddress import IPv4Address
import os


class WireGuardManager:
    def __init__(self, db_path, table_name, config_path, server_address, server_port, dns):
        self.db = DataBase(db_path)
        self.table = table_name
        self.db.execute(f'CREATE TABLE IF NOT EXISTS {self.table} ('
                        'username varchar(20),'
                        'first_name varchar(50),'
                        'last_name varchar(50),'
                        'ip_address varchar(15),'
                        'private_key varchar(44),'
                        'public_key varchar(44),'
                        'config_file text'
                        ');')
        self.cm = ConfigManager(config_path, server_address, server_port, dns)

    @staticmethod
    def generate_key_pair():
        private_key = os.popen('wg genkey', 'r').read().replace('\n', '')
        with open('/tmp/private.key', 'w') as fd:
            fd.write(private_key)
        public_key = os.popen('wg pubkey < /tmp/private.key', 'r').read().replace('\n', '')
        os.remove('/tmp/private.key')
        return {'private': private_key, 'public': public_key}

    def assign_address(self):
        last_address = self.db.execute(f'SELECT ip_address FROM {self.table} ORDER BY ip_address DESC LIMIT 1')
        if last_address:
            return str(IPv4Address(last_address[0][0]) + 1)
        else:
            return str(IPv4Address(self.cm.address_range) + 1)

    def register_user(self, username, first_name, last_name):
        key_pair = self.generate_key_pair()
        address = self.assign_address()
        self.cm.add_peer(address, key_pair['public'])
        config_file = self.cm.generate_config(address, key_pair['public'], key_pair['private'])
        self.db.execute(f'INSERT INTO {self.table} VALUES("{username}", "{first_name}",'
                        f'"{last_name}", "{address}", "{key_pair["private"]}",'
                        f'"{key_pair["public"]}", "{config_file}");')

    def remove_user(self, username):
        result = self.db.execute(f'SELECT public_key FROM {self.table} WHERE username="{username}";')
        if not result:
            raise ValueError('User does\'t exits')
        public_key = result[0][0]
        self.cm.remove_peer(public_key)
        self.db.execute(f'DELETE FROM {self.table} WHERE username="{username}";')

