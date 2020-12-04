import colorama
import os

from src.interactive import Interactive


if __name__ == "__main__":
    
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    os.chdir(ROOT_DIR)

    os.system('clear')
    prompt = Interactive()
    prompt.prompt =  colorama.Fore.MAGENTA + "shodanner " + "⪢ " + colorama.Fore.WHITE
    prompt.cmdloop()
 
