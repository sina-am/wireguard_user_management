import argparse
from config import DATABASE_PATH, WIREGUARD_PATH, PUBLIC_SERVER_ADDRESS, DNS_ADDRESS
from core.wireguard import WireGuardManager
from core.exceptions import UserAlreadyExist, UserDoesNotExist


wg = WireGuardManager(
    database_path=DATABASE_PATH, 
    config_path=WIREGUARD_PATH, 
    public_server_address=PUBLIC_SERVER_ADDRESS, 
    dns=DNS_ADDRESS
)

class AddNewUserAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        try:
            wg.register_user(*values)
        except UserAlreadyExist:
            print('Duplicate username')
        
class RemoveUserAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        try:
            wg.remove_user(*values)
        except UserDoesNotExist:
            print('User does\'nt exist')

        
class ListUsersAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        for user in wg.get_users():
            print(
                f'Username: {user.username}\n'
                f'\tFirst Name: {user.first_name}\n'
                f'\tLast Name: {user.last_name}\n'
                f'\tIP address: {user.ipaddress}\n'
            ) 

class GenerateConfigurationAction(argparse.Action):  
    def __call__(self, parser, namespace, values, option_string=None):
        user = wg.get_user(*values)
        if user:
            print(user.config_file)
        else:
            print("User does\'nt exist.")

def main():
    parser = argparse.ArgumentParser(description='Wireguard user manager')
    parser.add_argument(
        '--add', nargs=3,
        metavar=('username', 'firstname', 'lastname'),
        help='add a new user',
        action=AddNewUserAction
    )
    parser.add_argument(
        '--remove', nargs=1,
        metavar=('username'),
        help='remove a user',
        action=RemoveUserAction
    )
    parser.add_argument(
        '--list', nargs=0,
        help='list users',
        action=ListUsersAction
    )
    parser.add_argument(
        '--get-config', nargs=1,
        metavar=('username'),
        help='get user configuration file',
        action=GenerateConfigurationAction
    )
    parser.parse_args()


if __name__ == '__main__':
    main()
