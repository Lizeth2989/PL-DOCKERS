from flask import Flask
from flask import request
import json
import pickle
import numpy as np
from keras.models import load_model


app = Flask(__name__)
dict_class = ['OAM', 'transaction', 'video', 'bulk', 'control', 'p2p', 'critical', 'default', 'signaling', 'VoIP']
#loaded_model = load('decisiontree_model.joblib')
loaded_model1 = pickle.load(open('decisiontree_model_7.sav', 'rb'))
loaded_model2 = pickle.load(open('randomforest_model_7.sav', 'rb'))
loaded_model3 = pickle.load(open('knn_3_model_7_video_3.sav', 'rb'))
loaded_model4 = load_model('dnn_model1_7.sav')
count = 0
'''
def name_flow(input):
    dict_class = ['OAM', 'transaction', 'video', 'bulk', 'control', 'p2p', 'critical', 'default', 'signaling', 'VoIP']
    input = np.asarray([input])#["6", "5938", "35350", "21", "5827", "29", "7240"]
    result = loaded_model.predict(np.asarray(input))
    # print(name_convert(result[0]), dict_class[result[0]])
    return dict_class[result[0]]
''''

def name_flow(input, model_name="rf"):
    dict_class = ['OAM', 'transaction', 'video', 'bulk', 'control', 'p2p', 'critical', 'default', 'signaling', 'VoIP']
    #loaded_model = load('decisiontree_model.joblib')
    input = np.asarray([input])#["6", "5938", "35350", "21", "5827", "29", "7240"]
    if model_name=="dt":
      result = loaded_model1.predict(np.asarray(input))
      result = result[0]
    elif model_name=="rf":
      result = loaded_model2.predict(np.asarray(input))
      result = result[0]
    elif model_name=="knn":
      result = loaded_model3.predict(np.asarray(input))
      result = result[0]
    elif model_name=="dnn":
      result = loaded_model1.predict(np.asarray(input))
      result = np.argmax(result)
    else:
       result = combine(input)
    # print(name_convert(result[0]), dict_class[result[0]])
    return dict_class[result]
    
    
def combine(input):
    #input = np.asarray([input])#["6", "5938", "35350", "21", "5827", "29", "7240"]
    result1 = loaded_model1.predict(input)
    result2 = loaded_model2.predict(input)
    result3 = loaded_model3.predict(input)
    result4 = loaded_model4.predict(np.asarray(input))
    # print("results: ", np.argmax(result1), result2[0], result3[0], result4[0])
    if str(dict_class[result2[0]]) in ['OAM', 'transaction', 'control','default','signaling', 'VoIP']:
        res = result4[0]
    else:
        if str(dict_class[result1[0]])in ['OAM', 'bulk', 'p2p']:
            res = result2[0]
        elif str(dict_class[result3[0]])in ['video']:
            res = result3[0]
        elif str(dict_class[np.argmax(result4)])in ['critical']:
            res = np.argmax(result4)
        else:
            res = result4[0]
    return res
@app.route('/class', methods = ['GET', 'POST'])
def classify():
    #http://127.0.0.1:5000/class?protocol=6&src_port=5938&dst_port=35350&src_packet=21&src_bytes=5827&dst_packet=29&dst_bytes=7240&model_name=rf
    global count
    if request.method == 'GET':
        res = name_flow([request.args.get('protocol'), request.args.get('src_port'), request.args.get('dst_port'), request.args.get('src_packet'), request.args.get('src_bytes'), request.args.get('dst_packet'), request.args.get('dst_bytes')], model_name=str(request.args.get('model_name')))
        print("protocol: ", request.args.get('protocol'),"src_port: ",request.args.get('src_port') ,"des_port: ",request.args.get('dst_port'),"src_packet: ",request.args.get('src_packet'),"src_bytes: ", request.args.get('src_bytes'), "dst_packet: ", request.args.get('dst_packet'), "dst_bytes: ", request.args.get('dst_bytes'), res)
        count += 1
    return res

if __name__ == '__main__':
    app.run(debug=True)
