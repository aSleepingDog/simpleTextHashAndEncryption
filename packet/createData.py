#random-password-plaintext
import random

chars="0123456789ABCDEF";

with open("password1.txt", "w",encoding="utf-8") as file:
    for i in range(1024):
        for n in range(64):
            file.write(random.choice(chars))
        file.write("\n")

with open("exam1.txt", "w",encoding="utf-8") as file:
    for i in range(1024):
        r=random.randint(0,512)*2
        for n in range(r):
            file.write(random.choice(chars))
        file.write("\n")