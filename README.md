# Serpent Chat Encryption

Este projeto é uma implementação de um sistema de chat em grupo seguro, construído em Python. Ele utiliza um esquema de **criptografia híbrida** para garantir que as mensagens trocadas entre os clientes sejam confidenciais, mesmo que o servidor que as retransmite seja comprometido.

O servidor atua como um orquestrador, gerenciando conexões e retransmitindo pacotes, mas a geração e distribuição da chave de sessão são lideradas por um dos clientes do grupo, tornando o servidor incapaz de ler o conteúdo das mensagens.

## Funcionalidades Principais

- **Criptografia Híbrida**:
  - **RSA-2048**: Utilizado para a troca segura da chave de sessão. Cada cliente possui um par de chaves assimétricas.
  - **Serpent-256**: A criptografia simétrica Serpent é usada para a cifragem das mensagens do chat, garantindo alta performance e confidencialidade.
- **Gerenciamento de Chaves Liderado pelo Cliente**: A chave de sessão de um grupo não é gerada pelo servidor. Em vez disso, um dos clientes do grupo (o "líder", determinado alfabeticamente) gera a chave e a distribui de forma segura para os outros membros usando suas chaves públicas RSA.
- **Segurança de Grupo Dinâmica (Rekeying)**: Quando um membro sai de um grupo, uma nova chave de sessão é gerada e distribuída para os membros restantes, garantindo a segurança contínua da sessão (*Forward and Backward Secrecy* no contexto da sessão). Se um grupo for reduzido a uma única pessoa, a conversa é encerrada.
- **Protocolo Customizado sobre TCP**: O sistema opera sobre sockets TCP, utilizando `pickle` para serialização de objetos e um cabeçalho de tamanho fixo para delimitar as mensagens.
- **Logging Detalhado**: Todas as ações críticas no servidor e nos clientes são registradas para facilitar a depuração e o monitoramento.

## Como Funciona o Fluxo de Criptografia

1.  **Conexão e Identidade**: Ao iniciar, cada cliente gera um par de chaves RSA (pública e privada). Ele se conecta ao servidor e envia seu nome de usuário e sua chave pública RSA. A chave privada nunca sai do cliente.
2.  **Iniciação de Grupo**: Um cliente solicita a criação de uma conversa (seja privada ou em grupo) através de um comando (`/private` ou `/group`).
3.  **Orquestração do Servidor**: O servidor encontra todos os membros solicitados, coleta suas chaves públicas e envia um pacote de "convite de grupo" para todos os participantes.
4.  **Eleição do Líder e Geração da Chave**: Todos os clientes recebem o convite e, de forma determinística, elegem um "líder" (o cliente com o primeiro nome de usuário em ordem alfabética). O líder então gera uma nova **chave de sessão** simétrica de 32 bytes (para Serpent-256).
5.  **Distribuição Segura da Chave**: O líder criptografa a chave de sessão Serpent com a chave pública RSA de **cada um dos outros membros** do grupo e envia esses pacotes de chave criptografada para o servidor.
6.  **Retransmissão pelo Servidor**: O servidor atua como um relé, encaminhando cada pacote de chave criptografada para o seu respectivo destinatário.
7.  **Descriptografia no Cliente**: Cada cliente membro recebe a chave de sessão e usa sua **chave privada RSA** para descriptografá-la. Agora, todos no grupo compartilham a mesma chave simétrica.
8.  **Troca de Mensagens Segura**:
    - **Envio**: O cliente remetente criptografa sua mensagem com a chave Serpent compartilhada. Esse processo gera um **Vetor de Inicialização (IV)** aleatório e o **texto cifrado (ciphertext)**. Ambos são empacotados e enviados ao servidor. O IV garante que a mesma mensagem, se criptografada duas vezes, resulte em textos cifrados diferentes.
    - **Retransmissão Cega**: O servidor recebe o pacote contendo o IV e o texto cifrado e o retransmite para todos os outros membros do grupo **sem poder ler seu conteúdo**.
    - **Recebimento**: Os clientes destinatários usam a chave Serpent compartilhada e o IV recebido para descriptografar o texto cifrado e recuperar a mensagem original.

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
  - `pycryptodome`: Para a criptografia assimétrica RSA (PKCS#1 OAEP).
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