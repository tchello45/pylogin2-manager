import os
import json
import psycopg2

class db:
    def __init__(self, db_config_path:str) -> None:
        if not os.path.exists(db_config_path):
            raise FileNotFoundError(f"db_config file not found: {db_config_path}")
        with open(db_config_path, "r") as f:
            config_data = json.load(f)
        try:
            self.conn = psycopg2.connect(
                dbname=config_data["dbname"],
                user=config_data["user"],
                password=config_data["password"],
                host=config_data["host"],
                port=config_data["port"],
                sslmode="require"
            )
            self.cur = self.conn.cursor()
        except psycopg2.Error as e:
            raise Exception("Error connecting to the database")
    def __del__(self) -> None:
        self.conn.close()
    def close(self) -> None:
        self.conn.close()

class chat(db):
    def __init__(self, db_config_path:str) -> None:
        super().__init__(db_config_path)
    def setup_db(self) -> None:
        query = """
        CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY,
            sender VARCHAR(255) NOT NULL,
            receiver VARCHAR(255) NOT NULL,
            enc_message_sender TEXT NOT NULL,
            enc_message_receiver TEXT NOT NULL,
            type VARCHAR(255) NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        self.cur.execute(query)
        self.conn.commit()
    def delete_db(self) -> None:
        query = """
        DROP TABLE IF EXISTS messages;
        """
        self.cur.execute(query)
        self.conn.commit()
    
    def insert_message(self, sender:str, receiver:str, enc_message_sender:str, enc_message_receiver:str, type:str="text") -> None:
        query = f"""
        INSERT INTO messages (sender, receiver, enc_message_sender, enc_message_receiver, type)
        VALUES ('{sender}', '{receiver}', '{enc_message_sender}', '{enc_message_receiver}', '{type}');
        """
        self.cur.execute(query)
        self.conn.commit()
    def get_messages(self, sender:str, receiver:str) -> list:
        query = f"""
        SELECT * FROM messages WHERE (sender='{sender}' AND receiver='{receiver}') OR (sender='{receiver}' AND receiver='{sender}');
        """
        self.cur.execute(query)
        raw_data = self.cur.fetchall()
        if len(raw_data) == 0:
            return []
        return [
            {
                "id": row[0],
                "sender": row[1],
                "receiver": row[2],
                "enc_message_sender": row[3],
                "enc_message_receiver": row[4],
                "type": row[5],
                "timestamp": "{:%Y-%m-%d %H:%M:%S}".format(row[6])
            }
            for row in raw_data
        ]

