import os
from dotenv import load_dotenv
load_dotenv()

user = os.environ.get('USERNAME')
password = os.environ.get('PASSWORD')

print(user)
print(password)