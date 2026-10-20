import sys

# Si la terminal soporta secuencias ANSI o no es Windows antiguo
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
RESET = "\033[0m"

def print_success(msg: str):
    """Mensajes de éxito en VERDE"""
    print(f"{GREEN}[+] {msg}{RESET}")

def print_error(msg: str):
    """Mensajes de error en ROJO"""
    print(f"{RED}[-] {msg}{RESET}")

def print_info(msg: str):
    """Mensajes informativos en CIAN"""
    print(f"{CYAN}[*] {msg}{RESET}")

def print_warning(msg: str):
    """Mensajes de advertencia en AMARILLO"""
    print(f"{YELLOW}[!] {msg}{RESET}")

def print_header(title: str):
    """Títulos de comandos en MAGENTA y NEGRITA"""
    print(f"\n{MAGENTA}{BOLD}=== {title} ==={RESET}\n")