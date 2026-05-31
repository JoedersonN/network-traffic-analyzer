#!/usr/bin/env python3
"""
Network Traffic Analyzer
Analisa arquivos .pcap e gera relatório de tráfego com detecção de padrões suspeitos.
Autor: Joederson Neves | github.com/JoedersonN
"""

import sys
import argparse
from collections import defaultdict, Counter
from datetime import datetime

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, DNSQR
except ImportError:
    print("[ERRO] Scapy não instalado. Execute: pip install scapy")
    sys.exit(1)


# ─── Configurações de detecção ────────────────────────────────────────────────

SUSPICIOUS_PORTS = {
    4444: "Metasploit default",
    1337: "Common backdoor",
    31337: "Elite/backdoor",
    6666: "IRC/botnet",
    6667: "IRC/botnet",
    9001: "Tor relay",
    9050: "Tor SOCKS proxy",
}

SCAN_THRESHOLD       = 15   # conexões para IPs distintos → possível port scan
SYN_FLOOD_THRESHOLD  = 100  # pacotes SYN sem ACK → possível SYN flood
BEACON_THRESHOLD     = 10   # requisições repetidas ao mesmo destino → possível beacon C2
DNS_THRESHOLD        = 50   # queries DNS de um mesmo IP → possível DNS tunneling


# ─── Análise principal ────────────────────────────────────────────────────────

def analyze(pcap_path: str) -> dict:
    print(f"\n[*] Carregando captura: {pcap_path}")
    try:
        packets = rdpcap(pcap_path)
    except FileNotFoundError:
        print(f"[ERRO] Arquivo não encontrado: {pcap_path}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERRO] Falha ao ler o arquivo: {e}")
        sys.exit(1)

    print(f"[*] {len(packets)} pacotes carregados. Analisando...\n")

    # Contadores
    ip_src_counter    = Counter()
    ip_dst_counter    = Counter()
    proto_counter     = Counter()
    port_dst_counter  = Counter()
    dns_queries       = defaultdict(list)
    syn_counter       = Counter()         # SYN por IP origem
    connections       = defaultdict(set)  # IP origem → conjunto de portas destino
    pair_counter      = Counter()         # (src, dst) → contagem (beacon detection)
    alerts            = []

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto

        ip_src_counter[src] += 1
        ip_dst_counter[dst] += 1
        pair_counter[(src, dst)] += 1

        # Protocolo
        if pkt.haslayer(TCP):
            proto_counter["TCP"] += 1
            dport = pkt[TCP].dport
            port_dst_counter[dport] += 1
            connections[src].add(dport)

            # SYN sem ACK
            flags = pkt[TCP].flags
            if flags == 0x02:  # SYN puro
                syn_counter[src] += 1

        elif pkt.haslayer(UDP):
            proto_counter["UDP"] += 1
            dport = pkt[UDP].dport
            port_dst_counter[dport] += 1

        elif pkt.haslayer(ICMP):
            proto_counter["ICMP"] += 1

        else:
            proto_counter["Outro"] += 1

        # DNS
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            query = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            dns_queries[src].append(query)

    # ─── Geração de alertas ───────────────────────────────────────────────────

    # Portas suspeitas
    for port, descricao in SUSPICIOUS_PORTS.items():
        if port_dst_counter[port] > 0:
            alerts.append({
                "nivel": "ALTO",
                "tipo": "Porta suspeita",
                "detalhe": f"Porta {port}/tcp ({descricao}) — {port_dst_counter[port]} pacote(s)"
            })

    # Port scan
    for ip, portas in connections.items():
        if len(portas) >= SCAN_THRESHOLD:
            alerts.append({
                "nivel": "MÉDIO",
                "tipo": "Possível port scan",
                "detalhe": f"{ip} conectou em {len(portas)} portas distintas"
            })

    # SYN flood
    for ip, count in syn_counter.items():
        if count >= SYN_FLOOD_THRESHOLD:
            alerts.append({
                "nivel": "ALTO",
                "tipo": "Possível SYN flood",
                "detalhe": f"{ip} enviou {count} pacotes SYN sem completar handshake"
            })

    # Beacon C2
    for (src, dst), count in pair_counter.items():
        if count >= BEACON_THRESHOLD:
            alerts.append({
                "nivel": "MÉDIO",
                "tipo": "Possível beacon C2",
                "detalhe": f"{src} → {dst} repetido {count} vezes"
            })

    # DNS tunneling
    for ip, queries in dns_queries.items():
        if len(queries) >= DNS_THRESHOLD:
            alerts.append({
                "nivel": "MÉDIO",
                "tipo": "Possível DNS tunneling",
                "detalhe": f"{ip} realizou {len(queries)} queries DNS"
            })

    return {
        "total_packets":   len(packets),
        "ip_src":          ip_src_counter,
        "ip_dst":          ip_dst_counter,
        "protocols":       proto_counter,
        "top_ports":       port_dst_counter,
        "dns_queries":     dns_queries,
        "alerts":          alerts,
    }


# ─── Relatório ────────────────────────────────────────────────────────────────

def print_report(data: dict, pcap_path: str):
    sep  = "=" * 60
    sep2 = "-" * 60
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(sep)
    print("  NETWORK TRAFFIC ANALYZER — RELATÓRIO")
    print(sep)
    print(f"  Arquivo : {pcap_path}")
    print(f"  Data    : {ts}")
    print(f"  Total   : {data['total_packets']} pacotes analisados")
    print(sep)

    # Protocolos
    print("\n[PROTOCOLOS]")
    print(sep2)
    for proto, count in sorted(data["protocols"].items(), key=lambda x: -x[1]):
        pct = count / data["total_packets"] * 100
        print(f"  {proto:<10} {count:>6} pacotes  ({pct:.1f}%)")

    # Top IPs origem
    print("\n[TOP 5 — IPs ORIGEM]")
    print(sep2)
    for ip, count in data["ip_src"].most_common(5):
        print(f"  {ip:<20} {count:>6} pacotes")

    # Top IPs destino
    print("\n[TOP 5 — IPs DESTINO]")
    print(sep2)
    for ip, count in data["ip_dst"].most_common(5):
        print(f"  {ip:<20} {count:>6} pacotes")

    # Top portas
    print("\n[TOP 10 — PORTAS DESTINO]")
    print(sep2)
    for port, count in data["top_ports"].most_common(10):
        flag = f"  ← {SUSPICIOUS_PORTS[port]}" if port in SUSPICIOUS_PORTS else ""
        print(f"  {port:<8} {count:>6} pacotes{flag}")

    # DNS
    total_dns = sum(len(q) for q in data["dns_queries"].values())
    if total_dns:
        print(f"\n[DNS — {total_dns} queries detectadas]")
        print(sep2)
        for ip, queries in list(data["dns_queries"].items())[:5]:
            dominios = list(set(queries))[:3]
            print(f"  {ip:<20} → {', '.join(dominios)}")
        if len(data["dns_queries"]) > 5:
            print(f"  ... e mais {len(data['dns_queries']) - 5} IPs com queries DNS")

    # Alertas
    print(f"\n[ALERTAS — {len(data['alerts'])} encontrado(s)]")
    print(sep2)
    if not data["alerts"]:
        print("  Nenhum padrão suspeito detectado.")
    else:
        for alerta in sorted(data["alerts"], key=lambda x: x["nivel"]):
            print(f"  [{alerta['nivel']}] {alerta['tipo']}")
            print(f"         {alerta['detalhe']}")

    print(f"\n{sep}")
    print("  Análise concluída.")
    print(sep)


def save_report(data: dict, pcap_path: str, output_path: str):
    """Salva o relatório em arquivo .txt"""
    import io, contextlib
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        print_report(data, pcap_path)
    with open(output_path, "w") as f:
        f.write(buffer.getvalue())
    print(f"\n[*] Relatório salvo em: {output_path}")


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Analisa arquivos .pcap e detecta padrões suspeitos de tráfego."
    )
    parser.add_argument("pcap", help="Caminho para o arquivo .pcap")
    parser.add_argument(
        "-o", "--output",
        help="Salvar relatório em arquivo .txt (opcional)",
        default=None
    )
    args = parser.parse_args()

    data = analyze(args.pcap)
    print_report(data, args.pcap)

    if args.output:
        save_report(data, args.pcap, args.output)


if __name__ == "__main__":
    main()
