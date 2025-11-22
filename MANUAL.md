# Manual do Usuário - Serpent Chat

Este manual descreve como utilizar o sistema de chat seguro Serpent Chat.

## 1. Visão Geral

O Serpent Chat é uma ferramenta de comunicação que prioriza a segurança. Ele garante que suas mensagens sejam lidas apenas pelos destinatários autorizados, utilizando criptografia ponta-a-ponta com o algoritmo Serpent e autenticação de dois fatores (2FA).

**Interface Disponível:**

- **GUI (Interface Gráfica)**: Interface moderna e intuitiva com Tkinter.

## 2. Primeiros Passos

### Iniciando o Servidor

O servidor deve estar rodando para que os clientes possam se conectar.

```bash
python server.py
```

_O servidor escuta na porta 8888 por padrão e será indicado como "Servidor rodando em 0.0.0.0:8888"._

### Iniciando o Cliente

Para entrar no chat usando a interface gráfica:

```bash
python client_gui.py
```

## 3. Usando a Interface Gráfica (GUI)

### 3.1. Registro de Novo Usuário

1. Na tela inicial, clique no botão **"Registrar"**
2. Preencha os campos:
   - **Usuário**: Escolha um nome de usuário único
   - **Senha**: Crie uma senha segura
3. Clique em **"Registrar"**
4. **IMPORTANTE**: Uma janela com QR Code aparecerá automaticamente
   - Escaneie este QR Code com um aplicativo autenticador (Google Authenticator, Authy, Microsoft Authenticator, etc.)
   - Ou anote o código secreto exibido abaixo do QR Code para configuração manual
   - **Guarde este QR Code/segredo em local seguro!** Você precisará do aplicativo autenticador para fazer login

### 3.2. Fazer Login

1. Na tela inicial, preencha os campos:
   - **Usuário**: Seu nome de usuário
   - **Senha**: Sua senha
   - **Código 2FA**: Código de 6 dígitos gerado pelo seu aplicativo autenticador
2. Clique em **"Login"**

_Se o login for bem-sucedido, você verá a janela principal do chat._

### 3.3. Janela Principal do Chat

A janela principal é dividida em três áreas:

#### Barra Lateral Esquerda

- **Lista de Salas**: Mostra todas as suas conversas (individuais e em grupo)
- **Usuários Online**: Lista de usuários conectados atualmente
- **Botões de Ação**:
  - **"Nova Sala Individual"**: Criar conversa individual com um usuário
  - **"Nova Sala em Grupo"**: Criar sala de chat em grupo

#### Área Central

- **Área de Mensagens**: Visualização das mensagens da sala selecionada
- **Campo de Entrada**: Digite sua mensagem aqui
- **Botão "Enviar"**: Clique para enviar a mensagem (ou pressione Enter)

### 3.4. Criando uma Nova Sala Individual

1. Clique no botão **"Nova Sala Individual"**
2. Digite o nome de usuário do destinatário
3. Clique em **"Criar"**
4. A nova conversa aparecerá na lista de salas
5. Clique nela para começar a conversar

### 3.5. Criando uma Nova Sala em Grupo

1. Clique no botão **"Nova Sala em Grupo"**
2. Digite o nome do grupo
3. Selecione os membros da lista de usuários online (mantenha Ctrl pressionado para selecionar múltiplos)
4. Clique em **"Criar"**
5. O novo grupo aparecerá na lista de salas

### 3.6. Enviando Mensagens

1. Selecione uma sala/conversa na lista de salas
2. Digite sua mensagem no campo de entrada
3. Pressione **Enter** ou clique em **"Enviar"**
4. A mensagem será criptografada e enviada para todos os membros da sala

### 3.7. Visualizando Histórico

Ao selecionar uma sala, o histórico de mensagens anteriores é carregado automaticamente e descriptografado localmente no seu cliente.

## 4. Funcionalidades de Segurança Explicadas

### Criptografia Serpent

Diferente do AES padrão, utilizamos o **Serpent**, um algoritmo conhecido por sua altíssima margem de segurança (foi finalista do concurso AES). Seus dados são transformados em código ilegível usando criptografia de 256 bits antes mesmo de saírem do seu computador.

### Isolamento de Chaves por Sala

Cada sala de chat (individual ou em grupo) possui sua própria **chave Serpent exclusiva**:

- Mensagens de salas diferentes não podem ser descriptografadas com a mesma chave
- Se uma chave for comprometida, apenas aquela sala é afetada
- O servidor nunca tem acesso às chaves descriptografadas

### Troca de Chaves via RSA

Quando você entra em uma sala, o servidor envia a "Chave da Sala" para você:

1. A chave é criptografada com sua **Chave Pública RSA** (gerada localmente no seu cliente)
2. Apenas você (com sua **Chave Privada RSA**) pode descriptografar a chave da sala
3. Suas chaves RSA são geradas a cada vez que você inicia o cliente
4. No login, sua chave pública é atualizada no servidor automaticamente

### Autenticação de Dois Fatores (2FA)

Mesmo que alguém descubra sua senha, não conseguirá entrar na sua conta sem o código temporário gerado pelo seu aplicativo autenticador:

- Códigos mudam a cada 30 segundos (TOTP - Time-based One-Time Password)
- Baseado no padrão RFC 6238
- Compatível com Google Authenticator, Authy, Microsoft Authenticator, etc.
- QR Code gerado automaticamente no registro para facilitar a configuração

### Integridade das Mensagens

Cada mensagem é assinada com **HMAC-SHA256**:

- Garante que a mensagem não foi alterada durante a transmissão
- Previne ataques de modificação mesmo se a criptografia for quebrada
- Verifica a autenticidade do remetente

## 5. Solução de Problemas

### Problemas Comuns

- **"Erro ao descriptografar chave da sala"**:

  - Isso pode ocorrer se você está usando chaves RSA antigas. Feche o cliente, faça logout e login novamente.
  - O sistema agora atualiza automaticamente suas chaves RSA no servidor durante o login.

- **Janela do QR Code não aparece**:

  - Verifique se o registro foi bem-sucedido (mensagem de confirmação)
  - O código secreto TOTP também aparece na área de mensagens da interface

- **Chat não carrega mensagens**:

  - Verifique se o servidor está rodando
  - Certifique-se de que você está logado (título da janela mostra "Chat - [seu usuário]")

- **Erro "Código 2FA inválido"**:
  - O código muda a cada 30 segundos. Certifique-se de usar o código mais recente do seu aplicativo autenticador
  - Verifique se o relógio do seu computador está sincronizado

### Problemas de Conexão

- **"Não foi possível conectar ao servidor"**:

  - Verifique se o servidor está rodando (`python server.py`)
  - Confirme que a porta 8888 não está bloqueada por firewall
  - Por padrão, o servidor escuta em `127.0.0.1:8888` (localhost)

- **"Mensagens não aparecem"**:
  - Verifique a conexão de rede
  - Reinicie o cliente e faça login novamente

## 6. Dicas de Segurança

1. **Nunca compartilhe seu segredo TOTP**: O código secreto ou QR Code é equivalente à sua senha 2FA
2. **Use senhas fortes**: Combine letras, números e símbolos
3. **Mantenha backups do TOTP**: Se perder acesso ao aplicativo autenticador, você não conseguirá fazer login
4. **Feche o cliente ao sair**: Isso remove suas chaves RSA da memória
5. **Não confie cegamente**: Este é um projeto educacional - para produção, considere auditorias de segurança adicionais

## 7. Recursos Avançados

### Múltiplas Salas

Você pode participar de várias salas simultaneamente:

- Cada sala mantém sua própria chave de criptografia
- O histórico é carregado independentemente para cada sala
- Salas individuais aparecem como "usuario1-usuario2"
- Grupos aparecem com o nome definido na criação

### Persistência de Dados

- Todas as mensagens são salvas criptografadas no banco de dados SQLite (`chat.db`)
- O histórico completo é carregado ao entrar em uma sala
- Mensagens enviadas enquanto você estava offline estarão disponíveis quando você logar

## 8. Arquitetura do Sistema

### Cliente

- Gera par de chaves RSA (2048-bit) localmente
- Envia chave pública ao servidor durante login/registro
- Descriptografa chaves de sala recebidas do servidor
- Criptografa/descriptografa mensagens localmente usando Serpent
- Assina mensagens com HMAC-SHA256

### Servidor

- Gerencia conexões assíncronas (asyncio)
- Armazena chaves públicas dos usuários
- Distribui chaves de sala criptografadas com RSA
- Armazena mensagens criptografadas no banco de dados
- **Nunca tem acesso ao conteúdo das mensagens descriptografadas**

### Banco de Dados

- Tabela `users`: Credenciais, hashes bcrypt, chaves públicas RSA, segredos TOTP
- Tabela `rooms`: Salas de chat com chaves Serpent
- Tabela `room_members`: Relacionamento usuário-sala
- Tabela `messages`: Mensagens criptografadas, IVs, assinaturas HMAC
