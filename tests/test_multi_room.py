import unittest
import os
import sys
import asyncio
import json

# Adicionar diretório pai ao path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import Database
from crypto_utils import CryptoUtils, SerpentCipher

class TestMultiRoom(unittest.TestCase):
    def setUp(self):
        self.db_path = "test_multi_room.db"
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        self.db = Database(self.db_path)

    def tearDown(self):
        self.db.get_connection().close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_key_isolation(self):
        # Criar usuários
        u1 = self.db.add_user("alice", b"hash", b"salt", "secret", b"pubkey")
        u2 = self.db.add_user("bob", b"hash", b"salt", "secret", b"pubkey")
        u3 = self.db.add_user("charlie", b"hash", b"salt", "secret", b"pubkey")

        # Criar sala 1 (Alice e Bob)
        key1 = os.urandom(32)
        room1 = self.db.create_room("Room1", "private", key1)
        self.db.add_room_member(room1, u1)
        self.db.add_room_member(room1, u2)

        # Criar sala 2 (Alice e Charlie)
        key2 = os.urandom(32)
        room2 = self.db.create_room("Room2", "private", key2)
        self.db.add_room_member(room2, u1)
        self.db.add_room_member(room2, u3)

        # Verificar chaves
        fetched_key1 = self.db.get_room_key(room1)
        fetched_key2 = self.db.get_room_key(room2)

        self.assertEqual(key1, fetched_key1)
        self.assertEqual(key2, fetched_key2)
        self.assertNotEqual(key1, key2)

        # Verificar membros
        members1 = self.db.get_room_members(room1)
        self.assertIn(u1, members1)
        self.assertIn(u2, members1)
        self.assertNotIn(u3, members1)

    def test_message_persistence(self):
        u1 = self.db.add_user("alice", b"hash", b"salt", "secret", b"pubkey")
        key1 = os.urandom(32)
        room1 = self.db.create_room("Room1", "group", key1)
        
        msg_content = b"encrypted_content"
        iv = b"iv"
        sig = b"sig"
        
        self.db.save_message(u1, room1, msg_content, iv, sig)
        
        msgs = self.db.get_messages_for_room(room1)
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0][3], msg_content)

if __name__ == '__main__':
    unittest.main()
