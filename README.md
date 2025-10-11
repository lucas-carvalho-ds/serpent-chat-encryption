# Serpent Chat Encryption

Este projeto é uma implementação de um sistema de chat em grupo seguro, construído em Python. Ele utiliza um esquema de **criptografia híbrida** para garantir que as mensagens trocadas entre os clientes sejam confidenciais e autênticas, mesmo que o servidor que as retransmite seja comprometido.

O servidor atua como um orquestrador, gerenciando conexões e a distribuição de chaves, mas é incapaz de ler o conteúdo das mensagens.

## Funcionalidades Principais

- **Criptografia Híbrida**:
  - **RSA-2048**: Utilizado para a troca segura da chave de sessão. Cada cliente possui um par de chaves assimétricas, e o servidor usa a chave pública do cliente para entregar a chave de sessão de forma segura.
  - **Serpent-256 + HMAC-SHA256**: A criptografia simétrica Serpent é usada para a cifragem das mensagens do chat, garantindo alta performance. O HMAC-SHA256 (na abordagem *Encrypt-then-MAC*) é usado para garantir a integridade e autenticidade das mensagens, prevenindo adulterações.
- **Segurança de Grupo Dinâmica (Rekeying)**: Uma nova chave de sessão é gerada e distribuída para todos os membros sempre que um novo usuário entra ou sai do grupo. Isso garante a segurança contínua da sessão (conhecido como *Forward and Backward Secrecy* dentro do contexto da sessão).
- **Protocolo Customizado sobre TCP**: O sistema opera diretamente sobre sockets TCP, não dependendo da segurança de protocolos de aplicação como HTTP/TLS, dando controle total sobre a camada de comunicação.
- **Logging Detalhado**: Todas as ações críticas no servidor e nos clientes são registradas para facilitar a depuração e o monitoramento.

## Como Funciona o Fluxo de Criptografia

1.  **Conexão do Cliente**: Ao iniciar, o cliente gera um par de chaves RSA (pública e privada) e se conecta ao servidor.
2.  **Envio da Chave Pública**: O cliente envia sua chave pública RSA para o servidor. A chave privada nunca sai do cliente.
3.  **Geração da Chave de Grupo**: Ao receber um novo cliente (ou quando um cliente sai), o servidor gera uma nova **chave de sessão** simétrica (64 bytes: 32 para Serpent e 32 para HMAC).
4.  **Distribuição Segura da Chave**: O servidor criptografa a nova chave de sessão com a chave pública RSA de **cada cliente** e a envia individualmente para eles.
5.  **Descriptografia no Cliente**: Cada cliente usa sua **chave privada RSA** para descriptografar a chave de sessão recebida. Agora, todos os membros do grupo compartilham a mesma chave simétrica.
6.  **Troca de Mensagens**:
    - **Envio**: O cliente remetente criptografa a mensagem com a chave Serpent e gera um código de autenticação (MAC) com a chave HMAC. O pacote (`iv`, `ciphertext`, `mac`) é enviado ao servidor.
    - **Retransmissão**: O servidor recebe o pacote criptografado e o retransmite para todos os outros clientes **sem poder ler seu conteúdo**.
    - **Recebimento**: O cliente destinatário primeiro verifica a autenticidade da mensagem usando o MAC. Se for válido, ele descriptografa a mensagem com a chave Serpent.

## Estrutura do Projeto

```
serpent-chat-encryption/
├── servidor.py         # Lógica do servidor central
├── cliente.py          # Lógica do cliente do chat
├── cripto.py           # Módulos de criptografia (RSA e Serpent+HMAC)
├── logger_config.py    # Configuração do logger padronizado
├── utils.py            # (Opcional) Funções utilitárias de rede
└── README.md           # Este arquivo
```

## Tecnologias Utilizadas

- **Linguagem**: Python 3
- **Criptografia**:
  - `pyserpent`: Para a cifra de bloco simétrica Serpent.
  - `pycryptodome`: Para a criptografia assimétrica RSA (PKCS#1 OAEP) e primitivas criptográficas.
- **Rede**: Módulo `socket` da biblioteca padrão.
- **Concorrência**: Módulo `threading` da biblioteca padrão.

## Como Executar

### 1. Pré-requisitos

- Python 3.x

### 2. Instalação de Dependências

Abra seu terminal e instale as bibliotecas necessárias:

```bash
pip install pyserpent pycryptodome
```

### 3. Iniciar o Servidor

Em um terminal, execute o servidor. Ele ficará aguardando por conexões.

```bash
python servidor.py
```

### 4. Iniciar os Clientes

Abra um **novo terminal para cada cliente** que você deseja conectar ao chat.

```bash
python cliente.py
```

Ao iniciar, o cliente pedirá um nome de usuário. Após isso, você poderá enviar e receber mensagens criptografadas no grupo. Para sair, digite `sair`.