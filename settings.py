import os
import urllib

MONGO_URI = os.environ.get('MONGO_URIa') + urllib.parse.quote(os.environ.get('MONGO_PASSWORD')) + os.environ.get('MONGO_URIb')
JWT_SECRET_KEY = os.environ.get('JWT_SECRET')
JWT_ACCESS_TOKEN_EXPIRES = 86400 # JWT tokens expire in 24 hours