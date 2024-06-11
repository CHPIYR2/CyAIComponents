import argparse
import json
import os
import random
import shutil
import torch
import numpy as np
import requests
from datetime import datetime, timedelta
from deepcase.preprocessing import Preprocessor
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
    json_files = []
    for filename in os.listdir(directory):
        if filename.endswith('.json'):
            json_files.append(directory + "/" + filename)
    json_files.sort()
    return json_files

def fetch_wazuh_events_by_ip(wazuh_url, username, password, start_date, end_date, output_dir, increment_hours=3):
    start_dt = datetime.strptime(start_date, "%Y-%m-%d %H:%M:%S")
    end_dt = datetime.strptime(end_date, "%Y-%m-%d %H:%M:%S")
    increment = timedelta(hours=increment_hours)
    current_dt = start_dt

    while current_dt < end_dt:
        gte = (current_dt).strftime("%Y-%m-%dT%H:%M:%S") + "+08:00"
        lte = (current_dt + increment - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%S") + "+08:00"
        output_file = f"{output_dir}/wazuh-{gte}-training.json"
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
                    ]
                }
            },
            "size": 10000
        }
        response = requests.get(wazuh_url, auth=(username, password), headers={'Content-Type': 'application/json'}, json=query, verify=False)
        if response.status_code == 200:
            with open(output_file, 'w') as f:
                json.dump(response.json(), f, indent=4)
            print(f"Data saved to {output_file}")
        else:
            print(f"Failed to fetch data for {gte} to {lte}: {response.status_code} {response.text}")
        current_dt += increment

class EventIDExtractor:
    def extract_event_ids(input_file_path, output_file_path):
        file_names = sorted([f for f in os.listdir(input_file_path) if f.endswith('.json')])
        with open(output_file_path, 'w', encoding='utf-8') as output_file:
            for file_name in file_names:
                file_path = os.path.join(input_file_path, file_name)
                with open(file_path, 'r', encoding='utf-8') as file:
                    data = json.load(file)
                    event_ids = [str(item['_source']['winlog']['event_id']) for item in data['hits']['hits'] if 'event_id' in item['_source']['winlog']]
                    output_file.write(' '.join(event_ids) + '\n')
        print(f'所有 Event IDs 已成功儲存到 "{output_file_path}"。')

    def extract_rule_ids(input_file_path, output_file_path):
        with open(input_file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
            event_ids = [str(item['_source']['rule']['id']) for item in data['hits']['hits'] if 'rule' in item['_source'] and 'id' in item['_source']['rule'] and item['_source']['rule'].get('level', 0) >= 0]
        with open(output_file_path, 'w', encoding='utf-8') as output_file:
            output_file.write(' '.join(event_ids) + '\n')
        print(f'所有 Rule ID 已成功儲存到 "{output_file_path}"。')

    def extract_SEIDS(input_file_path, output_file_path):
        with open(input_file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
            event_ids = [str(item['_source']['id']) for item in data['hits']['hits'] if 'id' in item['_source'] and 'rule' in item['_source'] and item['_source']['rule'].get('level', 0) >= 0]
        with open(output_file_path, 'w', encoding='utf-8') as output_file:
            output_file.write(' '.join(event_ids) + '\n')
        print(f'所有 Security Event ID 已成功儲存到 "{output_file_path}"。')

    def clean_and_save(output_file_path):
        with open(output_file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()
        cleaned_lines = [line for line in lines if line.strip() != '']
        with open(output_file_path, 'w', encoding='utf-8') as file:
            file.writelines(cleaned_lines)
        print(f'已整理檔案並儲存到 {output_file_path}')

    def delete_empty_file(output_file_path):
        with open(output_file_path, 'r', encoding='utf-8') as file:
            content = file.read().strip()
        if not content:
            os.remove(output_file_path)
            print(f'空白或僅包含換行符號的檔案 "{output_file_path}" 已被刪除。')
        else:
            print(f'檔案 "{output_file_path}" 不是空白的。')

    def merge_data(directory, output_file):
        files = sorted([f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f)) and '.' not in f])
        with open(output_file, 'w', encoding='utf-8') as outfile:
            for filename in files:
                file_path = os.path.join(directory, filename)
                with open(file_path, 'r', encoding='utf-8') as infile:
                    content = infile.read()
                    outfile.write(content + '\n')
                os.remove(file_path)
                print(f'已刪除檔案: {file_path}')
        print(f'所有檔案已成功合併到 "{output_file}" 並刪除原始檔案。')

    def delete_all_files_in_directory(directory_path):
        if os.path.exists(directory_path) and os.path.isdir(directory_path):
            for filename in os.listdir(directory_path):
                file_path = os.path.join(directory_path, filename)
                try:
                    if os.path.isfile(file_path) or os.path.islink(file_path):
                        os.unlink(file_path)
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                except Exception as e:
                    print(f'刪除 {file_path} 時發生錯誤: {e}')
        else:
            print(f"路徑 {directory_path} 不存在或不是一個目錄。")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch Wazuh events and preprocess data.")
    parser.add_argument("start_date", type=str, help="The start date in 'YYYY-MM-DD HH:MM:SS' format")
    parser.add_argument("end_date", type=str, help="The end date in 'YYYY-MM-DD HH:MM:SS' format")
    args = parser.parse_args()

    # 獲取當前 Python 檔案的路徑
    current_file_path = os.path.abspath(__file__)
    # 獲取當前 Python 檔案所在的目錄
    current_directory = os.path.dirname(current_file_path)
    with open(current_directory + '/config.json', 'r') as config_file:
        config = json.load(config_file)
    data_path = config["data_path"]

    EventIDExtractor.delete_all_files_in_directory(data_path + "/wazuh-trainingData")
    fetch_wazuh_events_by_ip(
        wazuh_url=config['wazuh_url'],
        username=config['username'],
        password=config['password'],
        start_date=args.start_date,
        end_date=args.end_date,
        output_dir=data_path + "/wazuh-trainingData",
        increment_hours=3,
    )

    filefolder_path = data_path + "/wazuh-trainingData"
    input_file_path = get_json_filefolder(filefolder_path)
    head, sep, tail = filefolder_path.rpartition('/')
    foldername = tail
    output_folder_path = data_path + '/convertDataTraining/'
    output_file_path = output_folder_path + foldername
    EventIDExtractor.delete_all_files_in_directory(output_folder_path)

    for i in range(len(input_file_path)):
        head, sep, tail = input_file_path[i].rpartition('/')
        filename = tail[:-5]
        outputFileName = output_file_path + "-" + filename + "-ruleID"
        EventIDExtractor.extract_rule_ids(input_file_path[i], outputFileName)
        EventIDExtractor.delete_empty_file(outputFileName)

    filefolder_path = data_path + "/convertDataTraining"
    output_file_path = data_path + '/convertDataTraining/' + "wazuh_training_data"
    EventIDExtractor.merge_data(filefolder_path, output_file_path)
    EventIDExtractor.clean_and_save(output_file_path)

    preprocessor = Preprocessor(
        length=10,
        timeout=86400,
    )

    context_train, events_train, labels_train, mapping_train = preprocessor.text(
        path=data_path + '/convertDataTraining/wazuh_training_data',
        verbose=True,
    )
    print(f"mapping_train:\n{mapping_train}\n")

    if labels_train is None:
        labels_train = np.full(events_train.shape[0], -1, dtype=int)

    if torch.cuda.is_available():
        events_train = events_train.to('cuda')
        context_train = context_train.to('cuda')

    context_builder = ContextBuilder(
        input_size=40,
        output_size=40,
        hidden_size=128,
        max_length=10,
    )

    if torch.cuda.is_available():
        context_builder = context_builder.to('cuda')

    context_builder.fit(
        X=context_train,
        y=events_train.reshape(-1, 1),
        epochs=10,
        batch_size=128,
        learning_rate=0.01,
        verbose=True,
    )

    model_path = config["model_path"]
    torch.save(context_builder.state_dict(), model_path)
    print(f"Model saved to {model_path}")
