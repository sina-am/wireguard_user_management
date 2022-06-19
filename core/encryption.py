import subprocess


# TODO: Generate keys using python code

# stolen from https://techoverflow.net/2021/05/16/how-to-generate-wireguard-key-private-public-in-python-without-dependencies/
# Sorry, couldn't find the original source 


def generate_private_key():
    return subprocess.check_output("wg genkey", shell=True).decode("utf-8").strip()


def generate_public_key(private_key):
    return subprocess.check_output(f"echo '{private_key}' | wg pubkey", shell=True).decode("utf-8").strip()


def generate_key_pair():
    private_key = generate_private_key()
    public_key = generate_public_key(private_key)
    return {'private': private_key, 'public': public_key}
