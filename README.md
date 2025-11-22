# Serpent Chat Encryption

Um sistema de chat seguro desenvolvido com foco nos 4 pilares da Segurança da Informação: **Confidencialidade**, **Integridade**, **Disponibilidade** e **Autenticidade**.

## 🛡️ Pilares de Segurança Implementados

1.  **Confidencialidade**: Todas as mensagens são criptografadas usando o algoritmo **Serpent** (256-bit) em modo CBC. O servidor não tem acesso ao conteúdo das mensagens.
2.  **Integridade**: As mensagens são assinadas digitalmente (HMAC-SHA256) para garantir que não foram alteradas durante o trânsito.
3.  **Autenticidade**:
    - **Login Seguro**: Senhas protegidas com **bcrypt**.
    - **2FA (Autenticação de Dois Fatores)**: Uso obrigatório de tokens TOTP (Time-based One-Time Password).
    - **Assinatura de Origem**: Garante que a mensagem veio de quem diz ser.
4.  **Disponibilidade**: Arquitetura robusta baseada em `asyncio` para múltiplas conexões simultâneas e persistência de dados em banco SQLite.

## 🚀 Funcionalidades

- **Criptografia Ponta-a-Ponta (Simulada)**: Chaves de sala distribuídas via RSA.
- **Histórico Persistente**: Mensagens salvas criptografadas no banco de dados.
- **Interface TUI**: Interface de terminal amigável e interativa.
- **Lista de Usuários Online**: Visualização em tempo real.
- **Troca de Chaves Dinâmica**: Chaves de criptografia são rotacionadas automaticamente quando usuários entram ou saem (Forward Secrecy).

## 📦 Instalação

1.  Clone o repositório.
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

### Cliente

```bash
python client.py
```

## 🛠️ Tecnologias

- **Python 3.9+**
- **Criptografia**: `pyserpent`, `pycryptodome` (RSA)
- **Interface**: `prompt_toolkit`
- **Autenticação**: `pyotp`, `bcrypt`
- **Banco de Dados**: `sqlite3`
