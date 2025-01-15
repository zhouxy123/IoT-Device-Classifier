from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
import numpy as np
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler
from imblearn.combine import SMOTETomek
from sklearn.datasets import make_blobs
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix

tp = 0
fn = 0
fp = 0
tn = 0

def train_classifier(type):
    df = pd.read_csv('type%d.csv'%type, header = 0, index_col = 0) # 读取数据
    data = df.values.tolist()
    X = [row[:-1] for row in data]
    # print(X1)
    y = []
    '''
    for i in range (1, 541):
        y.append(np.floor((i-1)/20) + 1)
    '''
    for row in data:
        y.append(row[-1])
    # print(y1)

    # 划分数据集为训练集和测试集
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3)

    # SMOTE
    sampler = SMOTE(random_state=42)
    X_resampled, y_resampled = sampler.fit_resample(X_train, y_train)


    train_0 = 0
    train_1 = 0
    resample_0 = 0
    resample_1 = 0
    for num in y_train:
        if num == 1:
            train_1 += 1
        if num == 0:
            train_0 += 1

    for num in y_resampled:
        if num == 1:
            resample_1 += 1
        if num == 0:
            resample_0 += 1

    '''
    print("train 0 = %d" % train_0)
    print("train 1 = %d" % train_1)
    print("resample 0 = %d" % resample_0)
    print("resample 1 = %d" % resample_1)
    '''

    # 创建随机森林分类器实例
    RF = RandomForestClassifier(n_estimators=100)

    # 训练模型
    RF.fit(X_resampled, y_resampled)
    y_pred = RF.predict(X_test)
    conf_mat = confusion_matrix(y_test, y_pred)

    global tp
    global fn
    global fp
    global tn
    tp += conf_mat[0][0]
    fn += conf_mat[0][1]
    fp += conf_mat[1][0]
    tn += conf_mat[1][1]
    return RF

RFs = []
# accuracys = []


for i in range (1,28):
    RF = train_classifier(i)
    RFs.append(RF)

    # 预测测试集
    #y_pred = RF.predict(X_test)

    # 评估模型
    #accuracy = RF.score(X_test, y_test)
    # print(f"Accuracy: {accuracy}")
    # accuracys.append(accuracy)

'''
print('tp:%d'%tp)
print('fn:%d'%fn)
print('fp:%d'%fp)
print('tn:%d'%tn)

# 准确率
accuracy = (tp + tn) / (tp + tn + fp + fn)

# 精确率
precision = tp / (tp + fp)

# 召回率
recall = tp / (tp + fn)

# F1-score
f1 = 2 * (precision * recall) / (precision + recall)

print('accuracy:%f'%accuracy)
print('precision:%f'%precision)
print('recall:%f'%recall)
print('F1-score:%f'%f1)
'''
types = ['Aria',
         'D-LinkCam',
         'D-LinkDayCam',
         'D-LinkDoorSensor',
         'D-LinkHomeHub',
         'D-LinkSensor',
         'D-LinkSiren',
         'D-LinkSwitch',
         'D-LinkWaterSensor',
         'EdimaxCam',
         'EdimaxPlug1101W',
         'EdimaxPlug2101W',
         'EdnetCam',
         'EdnetGateway',
         'HomeMaticPlug',
         'HueBridge',
         'HueSwitch',
         'iKettle2',
         'Lightify',
         'MAXGateway',
         'SmarterCoffee',
         'TP-LinkPlugHS100',
         'TP-LinkPlugHS110',
         'WeMoInsightSwitch',
         'WeMoLink',
         'WeMoSwitch',
         'Withings']


'''
df = pd.read_csv('components.csv', header = 0, index_col = 0) # 读取数据
data = df.values.tolist()
X = [row[:-1] for row in data]
X1 = []
X1.append(X[234])
print(X1)
pred_results = []
for i in range(0, 27):
    y1_pred = RFs[i].predict(X1)
    pred_results.append(y1_pred[0])

result = 'none'
for i in range(0, 27):
    if pred_results[i] == 1.0:
        result = types[i]
        break
print(pred_results)
print(result)
'''


