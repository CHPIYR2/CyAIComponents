# Other imports
from sklearn.metrics import classification_report
import numpy as np
import torch
import random

# DeepCASE Imports
from deepcase.preprocessing   import Preprocessor
from deepcase.context_builder import ContextBuilder

# 設置隨機種子
seed = 42
np.random.seed(seed)
torch.manual_seed(seed)
random.seed(seed)

# 如果使用的是 CUDA，還需要設置 CUDA 的隨機種子
if torch.cuda.is_available():
    torch.cuda.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False

if __name__ == "__main__":
    ########################################################################
    #                             Loading data                             #
    ########################################################################

    # Create preprocessor
    preprocessor = Preprocessor(
        length  = 10,    # 10 events in context
        timeout = 86400, # Ignore events older than 1 day (60*60*24 = 86400 seconds)
    )

    # Load training data from file
    context_train, events_train, labels_train, mapping_train = preprocessor.text(
        path    = './data/convertDataTraining/wazuh_training_data',
        verbose = True,
    )
    print(f"mapping_train:\n{mapping_train}\n")

    # Load test data from file
    context_test, events_test, labels_test, mapping_test = preprocessor.text(
        path    = './data/convertData/ruleID/wazuh-20240519-wazuh-2024-05-19T01:00:00+08:00-ruleID-level_7',
        verbose = True,
    )
    print(f"mapping_test:\n{mapping_test}\n")

    # In case no labels are provided, set labels to -1
    # IMPORTANT: If no labels are provided, make sure to manually set the labels
    # before calling the interpreter.score_clusters method. Otherwise, this will
    # raise an exception, because scores == NO_SCORE cannot be computed.
    if labels_train is None:
        labels_train = np.full(events_train.shape[0], -1, dtype=int)

    if labels_test is None:
        labels_test = np.full(events_test.shape[0], -1, dtype=int)

    # Cast to cuda if available
    if torch.cuda.is_available():
        events_train  = events_train .to('cuda')
        context_train = context_train.to('cuda')
        events_test   = events_test  .to('cuda')
        context_test  = context_test .to('cuda')

    ########################################################################
    #                       Training ContextBuilder                        #
    ########################################################################

    # Create ContextBuilder
    context_builder = ContextBuilder(
        input_size    =  30,   # Number of input features to expect
        output_size   =  30,   # Same as input size
        hidden_size   = 128,   # Number of nodes in hidden layer, in paper we set this to 128
        max_length    = 10,    # Length of the context, should be same as context in Preprocessor
    )

    # Cast to cuda if available
    if torch.cuda.is_available():
        context_builder = context_builder.to('cuda')

    # Train the ContextBuilder
    context_builder.fit(
        X             = context_train,               # Context to train with
        y             = events_train.reshape(-1, 1), # Events to train with, note that these should be of shape=(n_events, 1)
        epochs        = 3,                           # Number of epochs to train with
        batch_size    = 128,                         # Number of samples in each training batch, in paper this was 128
        learning_rate = 0.01,                        # Learning rate to train with, in paper this was 0.01
        verbose       = True,                        # If True, prints progress
    )

    ########################################################################
    #                  Get prediction from ContextBuilder                  #
    ########################################################################

    # Use context builder to predict confidence
    confidence, _ = context_builder.predict(
        X = context_test
    )

    # Get confidence of the next step, seq_len 0 (n_samples, seq_len, output_size)
    confidence = confidence[:, 0]
    # Get confidence from log confidence
    confidence = confidence.exp()
    # Get prediction as maximum confidence
    y_pred = confidence.argmax(dim=1)

    ########################################################################
    #                          Perform evaluation                          #
    ########################################################################

    # Reverse mapping
    #mapping_train_reverse = {v: k for k, v in mapping_train.items()}
    #mapping_test_reverse  = {v: k for k, v in mapping_test .items()}

    # Get test and prediction as numpy array
    y_test = events_test.cpu().numpy()
    y_pred = y_pred     .cpu().numpy()

    y_test = y_test.tolist()
    y_pred = y_pred.tolist()

    # 使用 mapping 進行轉換
    y_test = [mapping_test [key] for key in y_test]
    y_pred = [mapping_train[key] for key in y_pred]

    result = []
    abnormal_list = []
    for i in range(len(y_test)):
        if (int(y_test[i]) == int(y_pred[i])):
            result.append(0)
        else:
            result.append(1)
            abnormal_list.append(i)

    # Calculate abnormal rate
    num_of_one = result.count(1)
    abnormal_rate = num_of_one / len(result)

    print(f"\n異常量：{num_of_one}\n異常率：{abnormal_rate:.2f}\n")
    print(f"偵測結果：\n{result}\nsize: {len(result)}\n\n異常序列：\n{abnormal_list}\nsize: {len(abnormal_list)}\n")

    # 讀取SEID檔案內容
    SEID_file_path = './data/convertData/SEID/wazuh-20240519-wazuh-2024-05-19T01:00:00+08:00-SEID-level_7'
    with open(SEID_file_path, 'r') as file:
        data = file.read()

    # 根據空格分割數據並存儲在列表中
    SEID_list = data.split()
    
    abnormal_security_event = []
    for i in abnormal_list:
        abnormal_security_event.append(SEID_list[i])

    print(f"Abnormal security event:\n{abnormal_security_event}\nsize: {len(abnormal_security_event)}\n")



'''
    # Print classification report
    print(classification_report(
        y_true = y_test,
        y_pred = y_pred,
        digits = 4,
    ))
'''