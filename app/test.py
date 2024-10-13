from database_operations import connect
from database_operations.user_auth import User, UserAuth
c=connect.Connection()
c.connect()
u = UserAuth(c.get_collection())
u.add_user(User("test","test@gmail.com","testpassword"))