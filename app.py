from flask import Flask
from flask import request
import json
from ml.raw import name_flow
app = Flask(__name__)

@app.route('/class', methods = ['GET', 'POST'])
def classify():
    #http://127.0.0.1:5000/class?protocol=6&src_port=5938&dst_port=35350&src_packet=21&src_bytes=5827&dst_packet=29&dst_bytes=7240
    if request.method == 'GET':
        res = name_flow([request.args.get('protocol'), request.args.get('src_port'), request.args.get('dst_port'), request.args.get('src_packet'), request.args.get('src_bytes'), request.args.get('dst_packet'), request.args.get('dst_bytes')])
        return "Flow is " + res

if __name__ == '__main__':
    app.run(debug=True)