from sklearn.decomposition import PCA
from sklearn.preprocessing import scale
import pandas as pd
import numpy as np


def principal_components(data):
    df = pd.read_csv('dataset.csv', header=0, index_col=0)  # 读取数据
    pca = PCA(n_components = 0.9) # 保留原始数据的90%
    pca.fit(df)
    '''
    print("explained variance:")
    print(pca.explained_variance_) # 输出特征根
    print("explained variance ratio:")
    print(pca.explained_variance_ratio_) # 输出解释方差比
    '''
    result = pca.transform(data)
    return result

# def get_pc(file_name):


def write_files():
    df = pd.read_csv('dataset.csv', header=0, index_col=0)  # 读取数据
    output = principal_components(df)
    df_components = pd.DataFrame(output)
    types = []
    for i in range(1, 541):
        types.append(np.floor((i - 1) / 20 + 1))
    df_components['Type'] = types
    df_components.to_csv('components.csv', index=True)
    # print(df_components)

    new_column = []
    for i in range(1, 541):
        new_column.append(0)

    output_new = []
    for row in output:
        row = np.append(row, [0])
        output_new.append(row)

    for i in range(1, 28):
        for j in range((i - 1) * 20, i * 20):
            output_new[j][-1] = 1
        df_new = pd.DataFrame(output_new)
        name = 'type%d.csv' % i
        df_new.to_csv(name, index=True)
        for j in range((i - 1) * 20, i * 20):
            output_new[j][-1] = 0


# write_files()