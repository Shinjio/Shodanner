import json
import sys
import os

class Loader:
    def __init__(self, f):
        self.file = f

    def get(self, key):
        try:
            with open(self.file) as f:
                f = json.load(f)
        except Exception as e:
            print(str(e))
        
        return f[key]
