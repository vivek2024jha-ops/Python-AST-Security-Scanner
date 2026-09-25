import subprocess

password = "admin123"

user_input = input("Enter expression: ")

result = eval(user_input)

exec(user_input)

subprocess.run("whoami", shell=True)

print(result)