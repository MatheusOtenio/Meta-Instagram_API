"""
Programa para capturar cupons via API do Instagram com tratamento completo de erros
"""
import os
import re
import logging
import hmac
import hashlib
import requests
import pandas as pd
from datetime import datetime
from flask import Flask, request, jsonify
from dotenv import load_dotenv

# Configuração inicial
load_dotenv()
app = Flask(__name__)

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Constantes
ACCESS_TOKEN = os.getenv('ACCESS_TOKEN')
VERIFY_TOKEN = os.getenv('VERIFY_TOKEN')
USER_ID = os.getenv('USER_ID')
APP_SECRET = os.getenv('APP_SECRET').encode()
CSV_FILE = 'cupons.csv'
COUPON_PATTERN = re.compile(r'\b(cupom|código|code)[:\s]*([A-Z0-9]{4,})\b', re.IGNORECASE)

def get_user_name(user_id):
    """Obtém o nome do usuário via API"""
    url = f'https://graph.facebook.com/v19.0/{user_id}'
    params = {
        'fields': 'name',
        'access_token': ACCESS_TOKEN
    }
    
    try:
        response = requests.get(url, params=params)
        if response.ok:
            return response.json().get('name', 'Desconhecido')
        logger.error(f"Erro ao buscar usuário: {response.status_code} - {response.text}")
    except Exception as e:
        logger.error(f"Falha na API: {str(e)}")
    
    return 'Desconhecido'

def verify_signature(req):
    """Valida assinatura do webhook com HMAC"""
    signature = req.headers.get('X-Hub-Signature', '').split('sha1=')[-1]
    calculated = hmac.new(APP_SECRET, req.data, hashlib.sha1).hexdigest()
    return hmac.compare_digest(signature, calculated)

def contains_coupon(text):
    """Verifica se o texto contém um cupom"""
    return bool(COUPON_PATTERN.search(text))

def format_timestamp(iso_timestamp):
    """Converte timestamp ISO 8601 para formato desejado"""
    try:
        dt = datetime.fromisoformat(iso_timestamp.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception as e:
        logger.error(f"Erro ao converter timestamp: {str(e)}")
        return iso_timestamp

def save_to_csv(data):
    """Salva dados no arquivo CSV"""
    try:
        df = pd.DataFrame([data])
        header = not os.path.exists(CSV_FILE)
        df.to_csv(CSV_FILE, mode='a', header=header, index=False)
        logger.info(f"Dados salvos: {data}")
    except Exception as e:
        logger.error(f"Erro ao salvar CSV: {str(e)}")

def process_mention(sender_id, text, timestamp):
    """Processa uma menção válida"""
    try:
        if contains_coupon(text):
            user_name = get_user_name(sender_id)
            save_to_csv({
                'nome': user_name,
                'texto': text,
                'data_hora': format_timestamp(timestamp)
            })
    except Exception as e:
        logger.error(f"Erro ao processar menção: {str(e)}")

def fetch_mentions():
    """Busca menções históricas via API"""
    url = f'https://graph.facebook.com/v19.0/{USER_ID}/mentions'
    params = {
        'access_token': ACCESS_TOKEN,
        'fields': 'from,message,created_time'
    }
    
    try:
        response = requests.get(url, params=params)
        if response.ok:
            for mention in response.json().get('data', []):
                process_mention(
                    mention.get('from', {}).get('id'),
                    mention.get('message', ''),
                    mention.get('created_time', '')
                )
        else:
            logger.error(f"Erro na API: {response.status_code} - {response.text}")
    except Exception as e:
        logger.error(f"Falha ao buscar menções: {str(e)}")

@app.route('/webhook', methods=['GET'])
def webhook_verify():
    """Validação inicial do webhook"""
    if request.args.get('hub.verify_token') == VERIFY_TOKEN:
        logger.info("Webhook verificado com sucesso")
        return request.args.get('hub.challenge', '')
    logger.warning("Token de verificação inválido")
    return 'Token de verificação inválido', 403

@app.route('/webhook', methods=['POST'])
def webhook_receiver():
    """Recebe eventos do webhook"""
    if not verify_signature(request):
        logger.warning("Assinatura HMAC inválida")
        return 'Assinatura inválida', 403
    
    try:
        data = request.json
        logger.debug(f"Payload recebido: {data}")
        
        for entry in data.get('entry', []):
            for change in entry.get('changes', []):
                value = change.get('value', {})
                message = value.get('message', {})
                
                if message:
                    process_mention(
                        message.get('from', {}).get('id'),
                        message.get('text', ''),
                        value.get('timestamp', '')
                    )
        
        return jsonify({'status': 'success'}), 200
    
    except Exception as e:
        logger.error(f"Erro no webhook: {str(e)}")
        return jsonify({'status': 'error'}), 500

if __name__ == '__main__':
    logger.info("Iniciando serviço...")
    fetch_mentions()
    app.run(host='0.0.0.0', port=5000, debug=False)