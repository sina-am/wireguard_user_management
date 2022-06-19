# A simple python interface for wireguard.

You can use this app to keep track of wireguard's peers as indivisual users.


## Installation:
obtaining code:
```
$ git clone https://github.com/sina-am/wireguard_user_management.git
```
setting up virtual environment:
```
$ cd wireguard_user_management/
$ python -m venv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
```
edit `config.py ` to add your custom setting.
there're a few variables to change:

`WIREGUARD_PATH`: configuration file that wireguard service already uses.

`DATABASE_PATH`: database path uses by app (default current path)

`PUBLIC_SERVER_ADDRESS`: server public ip address is used by wireguard to generate peer's configuration files.

`DNS_ADDRESS`: DNS in use for peers


## Usage:
Add a new user(peer):
```
$ wgm.py --add <username> <first name> <last name>
```
Get a list of active users
```
$ wgm.py --list
```
Remove a user
```
$ wgm.py --remove <username>
```