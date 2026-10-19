# -*- coding: utf-8 -*-
import os
import csv
import re
from typing import List, Dict, Any
from scapy.all import rdpcap, IP, TCP, UDP, Raw

# Padrões de Regex para sinalizar a presença de PII no payload
REGEX_PATTERNS = {
    "CPF": r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b|\b\d{11}\b",
    "EMAIL": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    "TELEFONE": r"\b(?:\+55\s?)?(?:\(?\d{2}\)?\s?)?(?:9\d{4}|\d{4})[-\s]?\d{4}\b"
}


def contem_pii(payload_text: str) -> int:
    """Retorna 1 se o payload contiver alguma PII estruturada, caso contrário 0."""
    for pattern in REGEX_PATTERNS.values():
        if re.search(pattern, payload_text):
            return 1
    return 0


def extrair_features_pcap(caminho_pcap: str) -> List[Dict[str, Any]]:
    """
    Lê um ficheiro .pcap e extrai métricas numéricas por pacote para o Autoencoder.
    """
    if not os.path.exists(caminho_pcap):
        raise FileNotFoundError(f"Ficheiro não encontrado: {caminho_pcap}")

    print(f"[*] A extrair métricas (features) de: {caminho_pcap}...")
    pacotes = rdpcap(caminho_pcap)
    features_list = []
    
    tempo_anterior = None

    for i, pkt in enumerate(pacotes):
        # 1. Métrica de Tempo (Delta Time entre pacotes)
        tempo_atual = float(pkt.time)
        delta_time = (tempo_atual - tempo_anterior) if tempo_anterior is not None else 0.0
        tempo_anterior = tempo_atual

        # 2. Tamanho total do pacote em bytes
        frame_len = len(pkt)

        # 3. Camada de Rede (IP)
        protocolo = 0
        if pkt.haslayer(IP):
            protocolo = pkt[IP].proto  # TCP=6, UDP=17, ICMP=1

        # 4. Camada de Transporte (TCP / UDP)
        src_port = 0
        dst_port = 0
        tcp_flags = 0

        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            tcp_flags = int(pkt[TCP].flags)
        elif pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

        # 5. Camada de Aplicação / Payload
        payload_len = 0
        has_pii = 0

        if pkt.haslayer(Raw):
            raw_bytes = pkt[Raw].load
            payload_len = len(raw_bytes)
            try:
                payload_text = raw_bytes.decode("utf-8", errors="ignore")
                has_pii = contem_pii(payload_text)
            except Exception:
                has_pii = 0

        # Estrutura numérica do pacote (Vetor de Entrada para o Autoencoder)
        features_list.append({
            "packet_id": i + 1,
            "timestamp": round(tempo_atual, 4),
            "delta_time": round(delta_time, 6),
            "frame_len": frame_len,
            "protocol": protocolo,
            "src_port": src_port,
            "dst_port": dst_port,
            "tcp_flags": tcp_flags,
            "payload_len": payload_len,
            "has_pii": has_pii
        })

    print(f"[+] Processamento concluído! {len(features_list)} pacotes vetorizados.")
    return features_list


def salvar_features_csv(features: List[Dict[str, Any]], caminho_csv: str) -> None:
    """Guarda a lista de dicionários num ficheiro CSV estruturado."""
    if not features:
        print("[-] Nenhuma métrica para guardar.")
        return

    os.makedirs(os.path.dirname(caminho_csv), exist_ok=True)
    colunas = features[0].keys()

    with open(caminho_csv, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=colunas)
        writer.writeheader()
        writer.writerows(features)

    print(f"[+] Dataset numericamente estruturado guardado em: {caminho_csv}")


if __name__ == "__main__":
    pasta_raw = os.path.join("data", "raw")
    pasta_processed = os.path.join("data", "processed")

    arquivos_pcap = [f for f in os.listdir(pasta_raw) if f.endswith(".pcap")]

    if arquivos_pcap:
        pcap_entrada = os.path.join(pasta_raw, arquivos_pcap[0])
        csv_saida = os.path.join(pasta_processed, "dataset_features.csv")

        dados_features = extrair_features_pcap(pcap_entrada)
        salvar_features_csv(dados_features, csv_saida)
    else:
        print("[-] Nenhum ficheiro .pcap encontrado em 'data/raw/' para processar.")
