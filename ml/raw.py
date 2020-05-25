import pickle
import numpy as np


loaded_model1 = pickle.load(open('decisiontree_model_7.sav', 'rb'))
loaded_model2 = pickle.load(open('randomforest_model_7.sav', 'rb'))
loaded_model3 = pickle.load(open('knn_3_model_7_video_3.sav', 'rb'))
loaded_model4 = load_model('dnn_model1_7.sav')

#model_name= dt,rf,dnn,knn,comb
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
#name_flow(['6', '43468', '5001', '5', '3260', '1', '60'])