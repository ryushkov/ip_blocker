Скрипт для добавления запрещающих правил для firewall.
В список добавляется не сам адрес а CIDR.
Что в свою очередь экономит место в списке UFW.
Добавление производится в начало списка чтобы запрещающее правило имело приоритет.
IP адрес передаётся  в виде аргумента при запуске скрипта:


`root@bothost:~# python3 main.py 35.203.210.83`
`2025-03-11 12:50:48,345 - INFO - IP: 35.203.210.83 - Найден CIDR: 35.192.0.0/12`
`2025-03-11 12:50:48,345 - INFO - IP: 35.203.210.83 - Блокируемый диапазон: 35.192.0.0/12`
`2025-03-11 12:50:48,644 - INFO - IP: 35.203.210.83 - Добавлено правило в начало списка: deny from 35.192.0.0/12`
`Firewall reloaded`
`2025-03-11 12:50:49,916 - INFO - IP: 35.203.210.83 - UFW перезагружен.`
`2025-03-11 12:50:49,916 - INFO - IP: 35.203.210.83 - Текущие правила UFW:`