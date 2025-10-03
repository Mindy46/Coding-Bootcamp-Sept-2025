# src/generator.py 
import secrets
import string
from pathlib import Path
import random

def generate_random(length=16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_+="
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def generator_passphrase(wordlist_path: str, words=4 , separator='-') -> str:
    words_list = Path(wordlist_path).read_text().split()
    chosen = [secrets.choice(words_list) for _ in range(words)]
    return separator.join(chosen)