import sqlite3


class DataBase:
    def __init__(self, db_path):
        try:
            self.connection = sqlite3.connect(db_path)
            self.cursor = self.connection.cursor()
        except sqlite3.Error:
            raise 'Connection error'

    def execute(self, query):
        self.cursor.execute(query)
        self.connection.commit()
        return self.cursor.fetchall()

    def close(self):
        self.connection.close()
