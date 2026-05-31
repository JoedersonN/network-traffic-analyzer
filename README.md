# network-traffic-analyzer

Ferramenta Python para análise de capturas de tráfego de rede (`.pcap`) com detecção automática de padrões suspeitos.

Desenvolvida como parte do meu portfólio em Blue Team / SOC.

---

## O que faz

Lê um arquivo `.pcap` (captura de rede do Wireshark/tcpdump) e gera um relatório com:

- Distribuição de protocolos (TCP, UDP, ICMP)
- Top IPs de origem e destino
- Portas mais utilizadas (com flag para portas suspeitas)
- Queries DNS detectadas
- **Alertas automáticos** para padrões suspeitos:
  - Portas associadas a backdoors e C2 (4444, 1337, 6667...)
  - Possível port scan (IP conectando em muitas portas distintas)
  - Possível SYN flood (alto volume de SYN sem handshake completo)
  - Possível beacon C2 (comunicação repetitiva com o mesmo destino)
  - Possível DNS tunneling (volume anômalo de queries DNS)

---

## Instalação

```bash
# Clone o repositório
git clone https://github.com/JoedersonN/network-traffic-analyzer
cd network-traffic-analyzer

# Instale a dependência
pip install scapy
```

---

## Uso

```bash
# Análise básica — imprime relatório no terminal
python3 analyzer.py captura.pcap

# Salvar relatório em arquivo
python3 analyzer.py captura.pcap -o relatorio.txt
```

---

## Exemplo de output

```
============================================================
  NETWORK TRAFFIC ANALYZER — RELATÓRIO
============================================================
  Arquivo : captura.pcap
  Data    : 2025-06-10 14:32:01
  Total   : 4821 pacotes analisados
============================================================

[PROTOCOLOS]
------------------------------------------------------------
  TCP          3201 pacotes  (66.4%)
  UDP           980 pacotes  (20.3%)
  ICMP          640 pacotes  (13.3%)

[TOP 5 — IPs ORIGEM]
------------------------------------------------------------
  192.168.1.105       1842 pacotes
  10.0.0.1             620 pacotes
  ...

[ALERTAS — 2 encontrado(s)]
------------------------------------------------------------
  [ALTO] Porta suspeita
         Porta 4444/tcp (Metasploit default) — 37 pacote(s)
  [MÉDIO] Possível port scan
         192.168.1.200 conectou em 22 portas distintas
```

---

## Arquivos .pcap para testar

Você pode usar capturas de exemplo dos seguintes recursos:

- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures)
- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/)
- Labs do TryHackMe (rooms de análise de tráfego geram capturas)
- `tcpdump -i eth0 -w captura.pcap` na sua própria rede

---

## Estrutura

```
network-traffic-analyzer/
├── analyzer.py     # Script principal
└── README.md
```

---

## Tecnologias

- Python 3.8+
- [Scapy](https://scapy.net/) — manipulação e leitura de pacotes de rede

---

## Autor

**Joederson Neves** — Blue Team | SOC | Segurança da Informação  
[GitHub](https://github.com/JoedersonN) · [LinkedIn](https://linkedin.com/in/joederson-neves-araujo) · [TryHackMe](https://tryhackme.com/p/Joe.Sk)
