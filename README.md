# Serpent Chat Encryption

Um sistema de chat seguro desenvolvido com foco nos 4 pilares da Segurança da Informação: **Confidencialidade**, **Integridade**, **Disponibilidade** e **Autenticidade**.

## 🛡️ Pilares de Segurança Implementados

1.  **Confidencialidade**: Todas as mensagens são criptografadas usando o algoritmo **Serpent** (256-bit) em modo CBC. O servidor não tem acesso ao conteúdo das mensagens. Cada sala possui sua própria chave exclusiva.
2.  **Integridade**: As mensagens são assinadas digitalmente (HMAC-SHA256) para garantir que não foram alteradas durante o trânsito.
3.  **Autenticidade**:
    - **Login Seguro**: Senhas protegidas com **bcrypt**.
    - **2FA (Autenticação de Dois Fatores)**: Uso obrigatório de tokens TOTP (Time-based One-Time Password) com suporte a QR Code.
    - **Assinatura de Origem**: Garante que a mensagem veio de quem diz ser.
4.  **Disponibilidade**: Arquitetura robusta baseada em `asyncio` para múltiplas conexões simultâneas e persistência de dados em banco SQLite.

## 🚀 Funcionalidades

- **Interface Gráfica (GUI)**: Interface moderna usando Tkinter com suporte a múltiplas salas de chat.
- **Chats Individuais e em Grupo**: Crie conversas individuais ou grupos com múltiplos participantes.
- **Criptografia Ponta-a-Ponta**: Cada sala possui chave Serpent exclusiva, distribuída via RSA.
- **QR Code para 2FA**: Registro simplificado com QR Code escaneável para configurar o TOTP.
- **Histórico Persistente**: Mensagens salvas criptografadas no banco de dados.
- **Lista de Usuários Online**: Visualização em tempo real de usuários conectados com indicadores de status (🟢 online / ⚫ offline).
- **Isolamento de Chaves por Sala**: Cada sala possui criptografia independente.
- **Menu de Contexto**: Clique direito nas salas para ver participantes ou sair da sala.
- **Seleção Intuitiva de Membros**: Sistema de checkboxes para criar grupos facilmente.
- **Visualização de Membros**: Veja quem está em cada sala com status de online/offline.

## 📦 Instalação

1.  Clone o repositório:
    ```bash
    git clone https://github.com/seu-usuario/serpent-chat-encryption
    cd serpent-chat-encryption
    ```
2.  Crie um ambiente virtual (recomendado):
    ```bash
    python -m venv .venv
    .venv\Scripts\activate  # Windows
    # source .venv/bin/activate # Linux/Mac
    ```
3.  Instale as dependências:
    ```bash
    pip install -r requirements.txt
    ```

## 🏃 Como Executar

Consulte o [MANUAL.md](MANUAL.md) para instruções detalhadas de uso.

### Servidor

```bash
python server.py
```

_O servidor escuta na porta 8888 por padrão._

### Cliente

```bash
python -m client.main
```

## 🛠️ Tecnologias

- **Python 3.9+**
- **Criptografia**: `pyserpent`, `pycryptodome` (RSA)
- **Interface Gráfica**: `tkinter`
- **Autenticação**: `pyotp`, `bcrypt`
- **QR Code**: `qrcode`, `Pillow`
- **Banco de Dados**: `sqlite3`
- **Rede Assíncrona**: `asyncio`

## 📁 Estrutura do Projeto

```
serpent-chat-encryption/
├── server.py              # Servidor de chat
├── client/                # Cliente modular
│   ├── main.py           # Ponto de entrada do cliente
│   ├── gui_manager.py    # Gerenciamento da GUI
│   ├── networking.py     # Comunicação com servidor
│   ├── message_handler.py # Processamento de mensagens
│   ├── validation.py     # Validações de entrada
│   └── ui/               # Componentes da interface
│       ├── auth_screens.py   # Telas de login/registro
│       ├── main_screen.py    # Tela principal do chat
│       ├── dialogs.py        # Diálogos diversos
│       └── qr_dialog.py      # Diálogo de QR Code
├── database.py         # Gerenciamento do banco de dados
├── auth.py             # Autenticação e 2FA
├── crypto_utils.py     # Utilidades de criptografia
├── logger_config.py    # Configuração de logging
├── requirements.txt    # Dependências do projeto
├── README.md           # Este arquivo
└── MANUAL.md           # Manual do usuário
```

## 🔒 Segurança

Este projeto foi desenvolvido com foco educacional em Segurança da Informação. As implementações seguem boas práticas de criptografia e autenticação, incluindo:

- Chaves RSA de 2048 bits
- Criptografia Serpent 256-bit em modo CBC
- HMAC-SHA256 para integridade
- bcrypt para hash de senhas
- TOTP para autenticação de dois fatores
