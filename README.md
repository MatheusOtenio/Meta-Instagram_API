# Captura de Cupons via API do Instagram

Este projeto captura cupons mencionados em postagens e mensagens no Instagram usando a API da Meta, Webhooks e requisições diretas.

## Configuração Manual para Uso da API da Meta

### 1. Criar um App na Meta for Developers

- Acesse Meta for Developers.
- Faça login com sua conta do Facebook.
- Crie um novo aplicativo e selecione o tipo adequado (Facebook/Instagram).
- Ative a API de Menções e Mensagens para receber notificações quando alguém mencionar o usuário.

### 2. Gerar Access Token

- No painel do aplicativo, vá para Configurações > Básico e copie o App ID e App Secret.
- Vá até Ferramentas > Graph API Explorer.
- Selecione o app criado e gere um Access Token de Longa Duração com as seguintes permissões:
  - pages_read_engagement
  - instagram_basic (se for Instagram)
  - instagram_manage_messages
- Salve o token gerado em um local seguro.

### 3. Configurar Webhook

- No painel do app, vá para Webhooks e adicione um novo endpoint.
- Defina a URL do servidor onde o webhook será recebido. Para testes locais, utilize o ngrok:
  ```sh
  ngrok http 5000
  ```
- Copie o URL gerado pelo ngrok e insira no Webhook da Meta.
- Adicione os seguintes eventos para monitoramento:
  - mention (menções ao usuário)
  - messages (mensagens diretas)
- Verifique se o webhook está validado corretamente.

### 4. Testar a Integração

- Faça uma menção ao usuário no Facebook ou Instagram.
- Verifique se a mensagem chega ao servidor.
- Confirme se o CSV está sendo gerado corretamente.

## Configuração Inicial:

✔ Carrega variáveis de ambiente usando dotenv.
✔ Define constantes e expressão regular para detecção de cupons.

## Validação de Segurança:

✔ Verificação de assinatura HMAC para webhooks.
✔ Validação do token durante a verificação inicial.

## Fluxo de Dados:

✔ Busca histórica de menções ao iniciar (`fetch_mentions()`).
✔ Webhook para receber eventos em tempo real.
✔ Processamento unificado para ambas as fontes de dados.

## Armazenamento:

✔ Usa pandas para salvar em CSV de forma eficiente.
✔ Mantém o formato especificado no projeto.

## Tratamento de Dados:

✔ Formatação adequada de datas.
✔ Extração de informações relevantes das mensagens.

## Instruções de Uso:

Criar o arquivo `.env` com:

```ini
ACCESS_TOKEN="seu_token_de_acesso"
VERIFY_TOKEN="seu_token_de_verificacao"
USER_ID="id_do_usuario"
APP_SECRET="sua_chave_secreta"
```

Instalar as dependências:

```sh
pip install requests flask pandas python-dotenv
```

Executar o servidor:

```sh
python seu_arquivo.py
```

## Recursos do Projeto:

✔ Segurança adequada.
✔ Processamento em tempo real e histórico.
✔ Armazenamento em CSV.
✔ Modularização para fácil manutenção.
