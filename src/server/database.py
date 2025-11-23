import sqlite3
import os
from src.common.logger_config import setup_logger

log = setup_logger(__name__)

class Database:
    def __init__(self, db_path="chat.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Inicializa o banco de dados e cria as tabelas se não existirem."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Tabela de Usuários
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash BLOB NOT NULL,
                salt BLOB NOT NULL,
                totp_secret TEXT NOT NULL,
                public_key_pem BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Tabela de Salas (Rooms)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rooms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                type TEXT NOT NULL, -- 'private' ou 'group'
                serpent_key BLOB NOT NULL, -- Chave da sala persistida
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Tabela de Membros da Sala
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS room_members (
                room_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (room_id, user_id),
                FOREIGN KEY(room_id) REFERENCES rooms(id),
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        
        # Migration: Ensure joined_at exists (for existing databases)
        try:
            cursor.execute('SELECT joined_at FROM room_members LIMIT 1')
        except sqlite3.OperationalError:
            log.info("Migrando tabela room_members: adicionando coluna joined_at")
            cursor.execute('ALTER TABLE room_members ADD COLUMN joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
            # Fix: Update existing members to have access to full history
            cursor.execute("UPDATE room_members SET joined_at = '1970-01-01 00:00:00'")
            
        # Ensure we fix history for users who already migrated with the "bad" timestamp (current time)
        # This is a safe-guard for this development session
        cursor.execute("UPDATE room_members SET joined_at = '1970-01-01 00:00:00' WHERE joined_at > datetime('now', '-1 minute')")

        # Tabela de Mensagens
        # Nota: room_id agora referencia rooms(id)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                recipient_id INTEGER, -- Mantido para compatibilidade, mas uso principal será via room_id
                room_id INTEGER NOT NULL, 
                content_encrypted BLOB NOT NULL,
                iv BLOB NOT NULL,
                signature BLOB NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(sender_id) REFERENCES users(id),
                FOREIGN KEY(room_id) REFERENCES rooms(id)
            )
        ''')

        conn.commit()
        conn.close()
        log.info(f"Banco de dados inicializado em {self.db_path}")

    def get_connection(self):
        return sqlite3.connect(self.db_path)

    def add_user(self, username, password_hash, salt, totp_secret, public_key_pem):
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO users (username, password_hash, salt, totp_secret, public_key_pem)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, password_hash, salt, totp_secret, public_key_pem))
            conn.commit()
            user_id = cursor.lastrowid
            log.info(f"Usuário {username} cadastrado com ID {user_id}.")
            return user_id
        except sqlite3.IntegrityError:
            log.warning(f"Tentativa de cadastro de usuário duplicado: {username}")
            return None
        finally:
            conn.close()

    def get_user_by_username(self, username):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        return user

    def get_user_by_id(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        conn.close()
        return user

    def get_all_users(self):
        """Retorna lista de todos os usernames cadastrados."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT username FROM users')
        users = [row[0] for row in cursor.fetchall()]
        conn.close()
        return users

    def update_user_public_key(self, username, public_key_pem):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET public_key_pem = ? WHERE username = ?', (public_key_pem, username))
        conn.commit()
        conn.close()

    # --- Room Management ---

    def create_room(self, name, room_type, serpent_key):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO rooms (name, type, serpent_key) VALUES (?, ?, ?)', (name, room_type, serpent_key))
        conn.commit()
        room_id = cursor.lastrowid
        conn.close()
        return room_id

    def add_room_member(self, room_id, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO room_members (room_id, user_id) VALUES (?, ?)', (room_id, user_id))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()

    def remove_room_member(self, room_id, user_id):
        """Remove um usuário de uma sala."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM room_members WHERE room_id = ? AND user_id = ?', (room_id, user_id))
        conn.commit()
        conn.close()

    def get_user_rooms(self, user_id):
        """Retorna as salas que o usuário participa."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT r.id, r.name, r.type
            FROM rooms r
            JOIN room_members rm ON r.id = rm.room_id
            WHERE rm.user_id = ?
        ''', (user_id,))
        rooms = cursor.fetchall()
        conn.close()
        return rooms

    def get_room_members(self, room_id):
        """Retorna os IDs dos membros de uma sala."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT user_id FROM room_members WHERE room_id = ?', (room_id,))
        members = [row[0] for row in cursor.fetchall()]
        conn.close()
        return members

    def get_member_join_time(self, room_id, user_id):
        """Retorna o timestamp de quando o usuário entrou na sala."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT joined_at FROM room_members WHERE room_id = ? AND user_id = ?', (room_id, user_id))
        row = cursor.fetchone()
        conn.close()
        if row:
            return row[0]
        return None

    def get_room_type(self, room_id):
        """Retorna o tipo da sala ('private' ou 'group')."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT type FROM rooms WHERE id = ?', (room_id,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return row[0]
        return None

    def get_private_chat_id(self, user1_id, user2_id):
        """Verifica se já existe um chat individual entre dois usuários."""
        conn = self.get_connection()
        cursor = conn.cursor()
        # Busca salas do tipo 'private' que tenham ambos os usuários
        # Esta query é um pouco complexa para SQLite simples, vamos fazer em python
        # Pegar salas individuais do user1
        cursor.execute('''
            SELECT r.id
            FROM rooms r
            JOIN room_members rm ON r.id = rm.room_id
            WHERE rm.user_id = ? AND r.type = 'private'
        ''', (user1_id,))
        user1_rooms = set(row[0] for row in cursor.fetchall())
        
        # Pegar salas individuais do user2
        cursor.execute('''
            SELECT r.id
            FROM rooms r
            JOIN room_members rm ON r.id = rm.room_id
            WHERE rm.user_id = ? AND r.type = 'private'
        ''', (user2_id,))
        user2_rooms = set(row[0] for row in cursor.fetchall())
        
        common_rooms = user1_rooms.intersection(user2_rooms)
        conn.close()
        
        if common_rooms:
            return list(common_rooms)[0]
        return None

    def get_room_key(self, room_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT serpent_key FROM rooms WHERE id = ?', (room_id,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return row[0]
        return None

    # --- Messages ---

    def save_message(self, sender_id, room_id, content_encrypted, iv, signature):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO messages (sender_id, room_id, content_encrypted, iv, signature)
            VALUES (?, ?, ?, ?, ?)
        ''', (sender_id, room_id, content_encrypted, iv, signature))
        conn.commit()
        msg_id = cursor.lastrowid
        conn.close()
        log.debug(f"Mensagem salva no DB. ID: {msg_id}")
        return msg_id

    def get_messages_for_room(self, room_id, min_timestamp=None):
        """Retorna mensagens de uma sala específica, opcionalmente filtradas por timestamp."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        query = '''
            SELECT m.id, m.sender_id, m.room_id, m.content_encrypted, m.iv, m.signature, m.timestamp, u.username
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE m.room_id = ?
        '''
        params = [room_id]
        
        if min_timestamp:
            query += ' AND m.timestamp >= ?'
            params.append(min_timestamp)
            
        query += ' ORDER BY m.timestamp ASC'
        
        cursor.execute(query, params)
        messages = cursor.fetchall()
        conn.close()
        return messages

    def get_all_messages(self):
        """DEPRECATED: Retorna todas as mensagens (apenas para debug/legado)."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT m.id, m.sender_id, m.room_id, m.content_encrypted, m.iv, m.signature, m.timestamp, u.username
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            ORDER BY m.timestamp ASC
        ''')
        messages = cursor.fetchall()
        conn.close()
        return messages
