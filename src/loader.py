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
                return f[key]
        except Exception as e:
            print(str(e))
        except KeyError:
            print("{} not found!".format(key))
        
