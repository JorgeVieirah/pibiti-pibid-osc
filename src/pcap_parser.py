# -*- coding: utf-8 -*-
import os
import re
from typing import List, Dict, Any
from scapy.all import rdpcap, Raw, IP

# Padrões de Regex para PII (CPFs, E-mails e Telefones)
REGEX_PATTERNS = {
    "CPF": r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b|\b\d{11}\b",
    "EMAIL": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    "TELEFONE": r"\b(?:\+55\s?)?(?:\(?\d{2}\)?\s?)?(?:9\d{4}|\d{4})[-\s]?\d{4}\b"
}

def anonimizar_payload_texto(payload_str: str) -> str:
    """Substitui PIIs encontradas no texto pelas tags de mascaramento."""
    texto_anonimizado = payload_str
    for tipo_pii, pattern in REGEX_PATTERNS.items():
        texto_anonimizado = re.sub(pattern, f"[MASCARADO: {tipo_pii}]", texto_anonimizado)
    return texto_anonimizado


def extrair_e_anonimizar_pcap(caminho_pcap: str) -> List[Dict[str, Any]]:
    """Lê o arquivo .pcap, extrai os payloads dos pacotes e aplica a anonimização."""
    if not os.path.exists(caminho_pcap):
        raise FileNotFoundError(f"Arquivo não encontrado: {caminho_pcap}")

    print(f"[*] Lendo arquivo: {caminho_pcap}...")
    pacotes = rdpcap(caminho_pcap)
    resultados = []

    for i, pkt in enumerate(pacotes):
        # Inspeciona apenas pacotes que possuem carga útil (Raw)
        if pkt.haslayer(Raw):
            try:
                # Decodifica os bytes do payload para texto UTF-8
                raw_bytes = pkt[Raw].load
                payload_text = raw_bytes.decode("utf-8", errors="ignore").strip()
                
                if payload_text:
                    payload_sanitizado = anonimizar_payload_texto(payload_text)
                    
                    # Extrai IP de origem e destino se a camada IP existir
                    ip_src = pkt[IP].src if pkt.haslayer(IP) else "N/A"
                    ip_dst = pkt[IP].dst if pkt.haslayer(IP) else "N/A"
                    
                    resultados.append({
                        "pacote_num": i + 1,
                        "ip_origem": ip_src,
                        "ip_destino": ip_dst,
                        "payload_original": payload_text,
                        "payload_anonimizado": payload_sanitizado
                    })
            except Exception:
                continue

    print(f"[+] Concluído! {len(resultados)} pacotes com payload útil identificados.")
    return resultados


if __name__ == "__main__":
    pasta_raw = os.path.join("data", "raw")
    if not os.path.exists(pasta_raw):
        os.makedirs(pasta_raw, exist_ok=True)
        
    arquivos_pcap = [f for f in os.listdir(pasta_raw) if f.endswith(".pcap")]

    if arquivos_pcap:
        pcap_teste = os.path.join(pasta_raw, arquivos_pcap[0])
        dados = extrair_e_anonimizar_pcap(pcap_teste)
        
        # Exibe os 3 primeiros pacotes para validação
        for item in dados[:3]:
            print(f"\n--- Pacote #{item['pacote_num']} [{item['ip_origem']} -> {item['ip_destino']}] ---")
            print(f"Original:   {item['payload_original'][:100]}")
            print(f"Sanitizado: {item['payload_anonimizado'][:100]}")
    else:
        print("[-] Nenhum arquivo .pcap encontrado em 'data/raw/' para teste.")
