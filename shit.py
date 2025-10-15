import os
import base64
import zlib
import pickle
import requests
from flask import Flask, request, Response

app = Flask(__name__)

@app.post("/load")
def load():
    data = request.get_data()
    obj = pickle.loads(zlib.decompress(base64.b64decode(data)))
    name = obj.get("name", "item.txt")
    path = os.path.join("data", name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    content = obj.get("content", "").encode()
    with open(path, "wb") as f:
        f.write(content)
    return Response("ok", status=200)

@app.get("/sync")
def sync():
    u = request.args.get("u", "")
    r = requests.get(u, timeout=4, allow_redirects=True)
    return Response(str(len(r.content)), status=200)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
