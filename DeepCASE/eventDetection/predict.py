# Other imports
from sklearn.metrics import classification_report
import numpy as np
import torch
import random
import os
import requests
import json
from datetime import datetime, timedelta
import os
import shutil

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


def get_json_filefolder(directory):
    # 創建一個空串列來存儲JSON檔案名稱
    json_files = []

    # 遍歷資料夾中的所有文件
    for filename in os.listdir(directory):
        # 檢查文件是否為JSON檔案
        if filename.endswith('.json'):
            json_files.append(directory + "/" + filename)
    
    json_files.sort()

    return json_files

def fetch_wazuh_events_by_ip(wazuh_url, username, password, start_date, end_date, agent_name, output_dir, increment_hours=3):
    """
    Fetch Wazuh events by each IP within a specified date range and save the results as JSON files.

    Parameters:
    - wazuh_url: str, The base URL for the Wazuh API
    - username: str, The username for the Wazuh API
    - password: str, The password for the Wazuh API
    - start_date: str, The start date in "YYYY-MM-DD HH:MM:SS" format
    - end_date: str, The end date in "YYYY-MM-DD HH:MM:SS" format
    - agent_name: str, The name of the agent to filter the events
    - increment_hours: int, The number of hours for each time window increment (default: 3)
    - output_dir: str, The directory to save the output JSON files (default: current directory)
    """
    
    # 轉換為datetime對象
    start_dt = datetime.strptime(start_date, "%Y-%m-%d %H:%M:%S")
    end_dt = datetime.strptime(end_date, "%Y-%m-%d %H:%M:%S")

    # 每次增加的秒數（3小時）
    increment = timedelta(hours=increment_hours)

    # 從開始日期到結束日期循環
    current_dt = start_dt
    while current_dt < end_dt:
        # 計算當前窗口的開始時間，並手動加上時區
        gte = (current_dt).strftime("%Y-%m-%dT%H:%M:%S")+ "+08:00"
        # 計算當前窗口的結束時間，並手動加上時區
        lte = (current_dt + increment - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%S")+ "+08:00"
        
        # 輸出檔案名稱，格式為wazuh-{開始日期}.json
        output_file = f"{output_dir}/wazuh-{gte}-{agent_name}.json"

        # 構建查詢
        query = {
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                "timestamp": {
                                    "gte": gte,
                                    "lte": lte
                                }
                            }
                        },
                        {
                            "term": {
                                "agent.name": agent_name
                            }
                        }
                    ]
                }
            },
            "size": 10000
        }

        # 執行查詢
        response = requests.get(wazuh_url, auth=(username, password), headers={'Content-Type': 'application/json'}, json=query, verify=False)
        
        if response.status_code == 200:
            with open(output_file, 'w') as f:
                json.dump(response.json(), f, indent=4)
            print(f"Data saved to {output_file}")
        else:
            print(f"Failed to fetch data for {gte} to {lte}: {response.status_code} {response.text}")

        # 增加當前時間
        current_dt += increment

class EventIDExtractor:
    # 提取事件ID並寫入檔案
    def extract_event_ids(input_file_path, output_file_path):
        file_names = sorted([f for f in os.listdir(input_file_path) if f.endswith('.json')])
        with open(output_file_path, 'w', encoding='utf-8') as output_file:
            for file_name in file_names:
                file_path = os.path.join(input_file_path, file_name)
                with open(file_path, 'r', encoding='utf-8') as file:
                    data = json.load(file)
                    # 提取事件ID並寫入檔案
                    event_ids = [str(item['_source']['winlog']['event_id']) 
                                 for item in data['hits']['hits'] 
                                 if 'event_id' in item['_source']['winlog']]
                    output_file.write(' '.join(event_ids) + '\n')
        print(f'所有 Event IDs 已成功儲存到 "{output_file_path}"。')

    # 提取Rule ID並寫入檔案
    def extract_rule_ids(input_file_path, output_file_path):
        with open(input_file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
            # 提取 rule 的 id 並寫入檔案，且篩選 "rule" -> "level" >= 9
            event_ids = [
                str(item['_source']['rule']['id']) 
                for item in data['hits']['hits'] 
                if 'rule' in item['_source'] and 'id' in item['_source']['rule'] and item['_source']['rule'].get('level', 0) >= 0
            ]
        with open(output_file_path, 'w', encoding='utf-8') as output_file:
            output_file.write(' '.join(event_ids) + '\n')
        print(f'所有 Rule ID 已成功儲存到 "{output_file_path}"。')

    # 提取Security Event ID並寫入檔案
    def extract_SEIDS(input_file_path, output_file_path):
        with open(input_file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
            # 提取 rule 的 id 並寫入檔案，且篩選 "rule" -> "level" >= 9
            event_ids = [
                str(item['_source']['id']) 
                for item in data['hits']['hits'] 
                if 'id' in item['_source'] and 'rule' in item['_source'] and item['_source']['rule'].get('level', 0) >= 0
            ]
        with open(output_file_path, 'w', encoding='utf-8') as output_file:
            output_file.write(' '.join(event_ids) + '\n')
        print(f'所有 Security Event ID 已成功儲存到 "{output_file_path}"。')


    # 刪除空白檔案(多個檔案轉換合併後包含空白適用)
    def clean_and_save(output_file_path):
        with open(output_file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()
        cleaned_lines = [line for line in lines if line.strip() != '']
        with open(output_file_path, 'w', encoding='utf-8') as file:
            file.writelines(cleaned_lines)
        print(f'已整理檔案並儲存到 {output_file_path}')

    # 刪除僅包含換行符號的檔案
    def delete_empty_file(output_file_path):
        with open(output_file_path, 'r', encoding='utf-8') as file:
            content = file.read().strip()
        
        if not content:
            os.remove(output_file_path)
            print(f'空白或僅包含換行符號的檔案 "{output_file_path}" 已被刪除。')
        else:
            print(f'檔案 "{output_file_path}" 不是空白的。')

    def merge_data(directory, output_file):
        # 獲取資料夾中的所有檔案名稱，並按名稱排序
        files = sorted([f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f)) and '.' not in f])
        
        with open(output_file, 'w', encoding='utf-8') as outfile:
            for filename in files:
                file_path = os.path.join(directory, filename)
                with open(file_path, 'r', encoding='utf-8') as infile:
                    content = infile.read()
                    outfile.write(content + '\n')
                # 刪除原始檔案
                os.remove(file_path)
                print(f'已刪除檔案: {file_path}')
        
        print(f'所有檔案已成功合併到 "{output_file}" 並刪除原始檔案。')

    def delete_all_files_in_directory(directory_path):
        # 確保路徑存在且是目錄
        if os.path.exists(directory_path) and os.path.isdir(directory_path):
            # 刪除目錄下的所有文件和子目錄
            for filename in os.listdir(directory_path):
                file_path = os.path.join(directory_path, filename)
                try:
                    if os.path.isfile(file_path) or os.path.islink(file_path):
                        os.unlink(file_path)  # 刪除文件或符號連結
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)  # 刪除子目錄
                except Exception as e:
                    print(f'刪除 {file_path} 時發生錯誤: {e}')
        else:
            print(f"路徑 {directory_path} 不存在或不是一個目錄。")

if __name__ == "__main__":

    # 抓取資料
    fetch_wazuh_events_by_ip(
        wazuh_url="https://202.5.255.179:9200/wazuh-alerts-*/_search",
        username="admin",
        password="L8o22snYOVqafDILU+wBFHTNld6Vu*Ht",
        start_date="2024-05-30 09:00:00",
        end_date="2024-05-30 10:59:59",
        agent_name="chpiyr2-host",
        increment_hours=1,
        output_dir="./data/testData"
    )


    #萃取資料
    filefolder_path = "./data/testData"
    input_file_path = get_json_filefolder(filefolder_path) 
    head, sep, tail = filefolder_path.rpartition('/')
    foldername = tail
    ruleID_output_file_path = './data/convertData/ruleID/'+ foldername
    SEID_output_file_path = './data/convertData/SEID/'+ foldername

    for i in range(len(input_file_path)):
        head, sep, tail = input_file_path[i].rpartition('/')
        filename = tail[:-5]

        outputFileName = ruleID_output_file_path + "-" + filename + "-ruleID"
        EventIDExtractor.extract_rule_ids(input_file_path[i], outputFileName)
        EventIDExtractor.delete_empty_file(outputFileName)

        outputFileName = SEID_output_file_path + "-" + filename + "-SEID"
        EventIDExtractor.extract_SEIDS(input_file_path[i], outputFileName)
        EventIDExtractor.delete_empty_file(outputFileName)

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
        path    = './data/convertData/ruleID/testData-wazuh-2024-05-30T10:00:00+08:00-chpiyr2-host-ruleID',
        verbose = True,
    )
    print(f"mapping_test:\n{mapping_test}\n")

    # Load the saved model
    context_builder = ContextBuilder(
        input_size    =  40,
        output_size   =  40,
        hidden_size   = 128,
        max_length    = 10,
    )

    # Cast to cuda if available
    if torch.cuda.is_available():
        context_builder = context_builder.to('cuda')

    model_path = "./model/context_builder_model.pth"
    context_builder.load_state_dict(torch.load(model_path))
    print("Model loaded successfully")

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
    SEID_file_path = './data/convertData/SEID/testData-wazuh-2024-05-30T10:00:00+08:00-chpiyr2-host-SEID'
    with open(SEID_file_path, 'r') as file:
        data = file.read()

    # 根據空格分割數據並存儲在列表中
    SEID_list = data.split()
    
    abnormal_security_event = []
    for i in abnormal_list:
        abnormal_security_event.append(SEID_list[i])

    print(f"Abnormal security event:\n{abnormal_security_event}\nsize: {len(abnormal_security_event)}\n")
