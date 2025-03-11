import sys
import os
import subprocess
import ipaddress
import logging

# Определение пути к лог-файлу
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(SCRIPT_DIR, "ufw_block.log")

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - IP: %(ip)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# функция вывода в лог
def log_message(level, message, ip):
    extra = {'ip': ip}
    if level == "info":
        logger.info(message, extra=extra)
    elif level == "warning":
        logger.warning(message, extra=extra)
    elif level == "error":
        logger.error(message, extra=extra)

# функция определения прав пользователя от имени которого запущен скрипт нужны права админа
def check_root():
    if os.getuid() != 0:
        log_message("error", "Этот скрипт требует прав root. Запустите через sudo.", "N/A")
        sys.exit(1)

# проверка адреса на корректное написание
def validate_ip(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        log_message("error", f"Неверный формат IPv4 адреса: {ip}")
        return False

# функция для установки пакетов linux
def install_package(pkg):
    log_message("info", f"Установка {pkg}...")
    try:
        subprocess.run(
            ["apt-get", "install", pkg],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        log_message("info", f"{pkg} успешно установлен.")
    except subprocess.CalledProcessError as e:
        log_message("error", f"Ошибка установки {pkg}: {e}")
        sys.exit(1)

# получение cidr диапазона адресов
def get_cidr(ip):
    try:
        result = subprocess.run(
            ["whois", ip],
            capture_output=True,
            text=True,
            check=True
        )
    except subprocess.CalledProcessError:
        log_message("warning", f"Не удалось выполнить whois для {ip}. Используем /32.")
        return f"{ip}/32"
    
    for line in result.stdout.split('\n'):
        line_lower = line.lower()
        if 'cidr:' in line_lower or 'route:' in line_lower:
            parts = line.strip().split()
            if len(parts) >= 2:
                cidr = parts[1].split(',')[0]
                if '/' in cidr and validate_ip(cidr.split('/')[0]):
                    log_message("info", f"Найден CIDR: {cidr}", ip)
                    return cidr
    log_message("warning", f"CIDR для {ip} не найден. Используем /32.")
    return f"{ip}/32"

# добавляем в список ufw cidr 
def ufw_rule_exists(cidr):
    try:
        result = subprocess.run(
            ["ufw", "status", "numbered"],
            capture_output=True,
            text=True,
            check=True
        )
        return f"deny from {cidr}" in result.stdout
    except subprocess.CalledProcessError:
        log_message("error", "Ошибка при проверке статуса UFW.")
        return False

def main():
    check_root()
    
    if len(sys.argv) != 2:
        log_message("error", f"Использование: {sys.argv[0]} <IP-ADDRESS>", "N/A")
        sys.exit(1)
    
    ip = sys.argv[1]
    
    if not validate_ip(ip):
        sys.exit(1)
    
    # Проверка и установка whois
    try:
        subprocess.run(
            ["which", "whois"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except subprocess.CalledProcessError:
        install_package("whois", ip)
    
    # Получение CIDR
    cidr = get_cidr(ip)
    log_message("info", f"Блокируемый диапазон: {cidr}", ip)
    
    # Проверка и установка ufw
    try:
        subprocess.run(
            ["which", "ufw"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except subprocess.CalledProcessError:
        install_package("ufw", ip)
    
    # Добавление правила в начало списка
    try:
        subprocess.run(
            ["ufw", "insert", "1", "deny", "from", cidr],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        log_message("info", f"Добавлено правило в начало списка: deny from {cidr}", ip)
    except subprocess.CalledProcessError as e:
        log_message("error", f"Ошибка добавления правила: {e}", ip)
        sys.exit(1)
    
    # Применение изменений
    subprocess.run(["ufw", "reload"])
    log_message("info", "UFW перезагружен.", ip)
    
    # Вывод статуса
    log_message("info", "Текущие правила UFW:", ip)
    subprocess.run(["ufw", "status", "numbered"])

if __name__ == "__main__":
    main()