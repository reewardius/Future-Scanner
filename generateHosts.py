with open('alive', 'r') as f:
    hosts = [line.strip() for line in f.readlines()]

with open('ports2.txt', 'r') as f:
    ports = [line.strip() for line in f.readlines()]

combinations = []
for host in hosts:
    for port in ports:
        combinations.append(f"{host}:{port}")

with open('output.txt', 'w') as f:
    for combination in combinations:
        f.write(combination + '\n')