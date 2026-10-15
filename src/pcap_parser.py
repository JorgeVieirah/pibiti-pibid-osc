# -*- coding: utf-8 -*-
import os
import re
from typing import List, Dict, Any
from scapy.all import rdpcap, Raw, IP
from transformers import pipeline

# 1. Padrões de Regex para PII Estruturadas
REGEX_PATTERNS = {
    "CPF": r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b|\b\d{11}\b",
    "EMAIL": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    "TELEFONE": r"\b(?:\+55\s?)?(?:\(?\d{2}\)?\s?)?(?:9\d{4}|\d{4})[-\s]?\d{4}\b"
}

# 2. Inicialização do modelo BERTimbau NER (Carregado apenas uma vez)
print("[*] Carregando modelo BERTimbau NER...")
ner_pipeline = pipeline(
    "ner",
    model="neuralmind/bert-base-portuguese-cased"
)


def unificar_subtokens(ner_results: List[Dict]) -> List[Dict]:
    """Agrupa sub-tokens do BERTimbau (iniciados por '##') mantendo o rótulo da entidade."""
    entidades_processadas = []
    entidade_atual = None

    for item in ner_results:
        palavra = item.get('word', '')
        entity_group = item.get('entity_group', item.get('entity', 'O'))
        score = item.get('score', 0.0)

        if entity_group == 'O':
            continue

        if palavra.startswith("##"):
            if entidade_atual:
                entidade_atual["valor"] += palavra.replace("##", "")
                entidade_atual["score"] = min(entidade_atual["score"], score)
        else:
            if entidade_atual:
                entidades_processadas.append(entidade_atual)
            
            entidade_atual = {
                "valor": palavra,
                "tipo": entity_group,
                "score": score
            }

    if entidade_atual:
        entidades_processadas.append(entidade_atual)

    return entidades_processadas


def anonimizar_payload_texto(payload_str: str) -> str:
    """Aplica o pipeline híbrido LGPD (Regex + BERTimbau NER)."""
    texto_anonimizado = payload_str

    # Passo A: Mascaramento por Regex (Padrões Estruturados)
    for tipo_pii, pattern in REGEX_PATTERNS.items():
        texto_anonimizado = re.sub(pattern, f"[MASCARADO: {tipo_pii}]", texto_anonimizado)

    # Passo B: Mascaramento por BERTimbau NER (Pessoas, Locais, Organizações)
    try:
        ner_results = ner_pipeline(texto_anonimizado)
        entidades_recompostas = unificar_subtokens(ner_results)

        ENTIDADES_VALIDAS = {"PER", "LOC", "ORG", "PESSOA", "LOCAL", "ORGANIZACAO"}
        tags_ignoradas = ["[MASCARADO:", "CPF", "EMAIL", "TELEFONE"]

        for ent in entidades_recompostas:
            valor = ent["valor"]
            tipo = ent["tipo"]

            if tipo in ENTIDADES_VALIDAS and len(valor) > 2:
                if not any(tag in valor for tag in tags_ignoradas):
                    texto_anonimizado = re.sub(rf"\b{re.escape(valor)}\b", f"[MASCARADO: {tipo}]", texto_anonimizado)
    except Exception:
        pass

    return texto_anonimizado


def extrair_e_anonimizar_pcap(caminho_pcap: str) -> List[Dict[str, Any]]:
    """Lê o arquivo .pcap, extrai os payloads dos pacotes e aplica a anonimização."""
    if not os.path.exists(caminho_pcap):
        raise FileNotFoundError(f"Arquivo não encontrado: {caminho_pcap}")

    print(f"[*] Lendo e processando arquivo: {caminho_pcap}...")
    pacotes = rdpcap(caminho_pcap)
    resultados = []

    for i, pkt in enumerate(pacotes):
        if pkt.haslayer(Raw):
            try:
                raw_bytes = pkt[Raw].load
                payload_text = raw_bytes.decode("utf-8", errors="ignore").strip()

                if payload_text:
                    payload_sanitizado = anonimizar_payload_texto(payload_text)

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

        for item in dados[:3]:
            print(f"\n--- Pacote #{item['pacote_num']} [{item['ip_origem']} -> {item['ip_destino']}] ---")
            print(f"Original:   {item['payload_original'][:100]}")
            print(f"Sanitizado: {item['payload_anonimizado'][:100]}")
    else:
        print("[-] Nenhum arquivo .pcap encontrado em 'data/raw/' para teste.")
