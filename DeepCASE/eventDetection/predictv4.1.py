# Other imports
import glob
from sklearn.metrics import classification_report
import numpy as np
import torch
import random
import os
import requests
import json
from datetime import datetime, timedelta, timezone
import shutil
import requests
from requests.auth import HTTPBasicAuth
import argparse
from urllib.parse import urljoin


# DeepCASE Imports
from deepcase.preprocessing import Preprocessor
from deepcase.context_builder import ContextBuilder
import urllib3

# 禁用https警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

def get_agents_in_group(api_url, username, password, group_name):
    # 獲取 Bearer Token 的 API 路徑
    token_url = f"{api_url}/security/user/authenticate"

    # 發送 POST 請求獲取 Token
    response = requests.post(token_url, auth=(username, password), verify=False)

    # 檢查請求狀態碼
    if response.status_code == 200:
        token = response.json()['data']['token']
        
        # 設定查詢屬於指定組的 API 路徑
        url = f"{api_url}/groups/{group_name}/agents"
        
        # 設定標頭資訊
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        # 發送 GET 請求
        response = requests.get(url, headers=headers, verify=False)
        
        # 檢查請求狀態碼
        if response.status_code == 200:
            agents = response.json()['data']['affected_items']
            agent_names = [agent['name'] for agent in agents]
            return agent_names
        else:
            print(f"Failed to retrieve agents. Status code: {response.status_code}, Response: {response.text}")
            return []
    else:
        print(f"Failed to retrieve token. Status code: {response.status_code}, Response: {response.text}")
        return []

def get_api_token(wazuh_url, api_user, api_password):
    try:
        response = requests.get(f'{wazuh_url}/security/user/authenticate', auth=HTTPBasicAuth(api_user, api_password), verify=False)
        response.raise_for_status()
        return response.json()['data']['token']
    except requests.exceptions.RequestException as e:
        print(f'獲取 API token 失敗: {e}')
        return None

def get_agent_ip_by_name(wazuh_url, api_token, agent_name):
    try:
        headers = {
            'Authorization': f'Bearer {api_token}',
            'Content-Type': 'application/json'
        }

        # 列出所有代理並找到匹配的代理名稱
        response = requests.get(f'{wazuh_url}/agents', headers=headers, verify=False)
        response.raise_for_status()

        agents_info = response.json()
        for agent in agents_info['data']['affected_items']:
            if agent['name'] == agent_name:
                return agent.get('ip', '無法找到代理的 IP 地址。')
        
        return '無法找到指定的代理名稱。'
    except requests.exceptions.RequestException as e:
        return f'請求失敗: {e}'

def get_agent_ip(wazuh_url, api_user, api_password, agent_name):
    api_token = get_api_token(wazuh_url, api_user, api_password)
    if api_token:
        return get_agent_ip_by_name(wazuh_url, api_token, agent_name)
    else:
        return '獲取 API token 失敗。'

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

def load_config(file_path):
    with open(file_path, 'r') as file:
        config = json.load(file)
    return config

def fetch_wazuh_events_by_ip(wazuh_url, username, password, start_date, end_date, agent_name, output_dir, increment_hours):
    """
    Fetch Wazuh events by each IP within a specified date range and save the results as JSON files.

    Parameters:
    - wazuh_url: str, The base URL for the Wazuh API
    - username: str, The username for the Wazuh API
    - password: str, The password for the Wazuh API
    - start_date: str, The start date in "YYYY-MM-DDTHH:MM:SS+TZ" format
    - end_date: str, The end date in "YYYY-MM-DDTHH:MM:SS+TZ" format
    - agent_name: str, The name of the agent to filter the events
    - increment_hours: int, The number of hours for each time window increment (default: 3)
    - output_dir: str, The directory to save the output JSON files (default: current directory)
    """
    
    # 轉換為datetime對象
    start_dt = datetime.strptime(start_date, "%Y-%m-%dT%H:%M:%S%z")
    end_dt = datetime.strptime(end_date, "%Y-%m-%dT%H:%M:%S%z")

    # 每次增加的秒數（小時）
    increment = timedelta(hours=increment_hours)

    # 從開始日期到結束日期循環
    current_dt = start_dt
    while current_dt < end_dt:
        # 計算當前窗口的開始時間
        gte = current_dt.isoformat()
        # 計算當前窗口的結束時間
        lte = (current_dt + increment - timedelta(seconds=1)).isoformat()
        
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

    return output_file


class EventIDExtractor:
    # 提取事件ID並寫入檔案
    @staticmethod
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
    @staticmethod
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
    @staticmethod
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
    @staticmethod
    def clean_and_save(output_file_path):
        with open(output_file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()
        cleaned_lines = [line for line in lines if line.strip() != '']
        with open(output_file_path, 'w', encoding='utf-8') as file:
            file.writelines(cleaned_lines)
        print(f'已整理檔案並儲存到 {output_file_path}')

    # 刪除僅包含換行符號的檔案
    @staticmethod
    def delete_empty_file(output_file_path):
        with open(output_file_path, 'r', encoding='utf-8') as file:
            content = file.read().strip()
        
        if not content:
            os.remove(output_file_path)
            print(f'空白或僅包含換行符號的檔案 "{output_file_path}" 已被刪除。')
            return True
        else:
            print(f'檔案 "{output_file_path}" 不是空白的。')
            return False

    @staticmethod
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

    @staticmethod
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

def main(config, debug=False):
    # 獲取當前時間，並設置為整點
    # 手動設置開始時間和結束時間
    manual_start_time = "2024-06-26T03:00:00"  # 例如，2024年6月4日下午2點
    manual_end_time   = "2024-06-26T03:59:00"  # 例如，2024年6月4日下午3點

    # 解析手動設置的時間
    start_date = datetime.strptime(manual_start_time, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone(timedelta(hours=8))).strftime("%Y-%m-%dT%H:%M:%S") + "+08:00"
    end_date = datetime.strptime(manual_end_time, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone(timedelta(hours=8))).strftime("%Y-%m-%dT%H:%M:%S") + "+08:00"

    data_path = config["data_path"]
    
    agent_list = get_agents_in_group(config["wazuh_api_url"], config["username_api"], config["password_api"], group_name)

    for agent_name in agent_list:
        '''
        EventIDExtractor.delete_all_files_in_directory(data_path + "/convertData/ruleID/")
        EventIDExtractor.delete_all_files_in_directory(data_path + "/convertData/SEID/")
        EventIDExtractor.delete_all_files_in_directory(data_path + "/testData")
        '''
        origianFilePath = fetch_wazuh_events_by_ip(
            wazuh_url=config["wazuh_url"],
            username=config["username"],
            password=config["password"],
            start_date=start_date,
            end_date=end_date,
            agent_name=agent_name,
            output_dir=data_path + "/testData",
            increment_hours = config["increment_hours"]
        )

        # 萃取資料
        filefolder_path = data_path + "/testData"
        head, sep, tail = filefolder_path.rpartition('/')
        foldername = tail
        ruleID_output_file_path = data_path + '/convertData/ruleID/' + foldername
        SEID_output_file_path = data_path + '/convertData/SEID/' + foldername

        head, sep, tail = origianFilePath.rpartition('/')
        filename = tail[:-5]

        outputFilePathRule = ruleID_output_file_path + "-" + filename + "-ruleID"
        EventIDExtractor.extract_rule_ids(origianFilePath, outputFilePathRule)
        noFile = EventIDExtractor.delete_empty_file(outputFilePathRule)

        outputFilePathSE = SEID_output_file_path + "-" + filename + "-SEID"
        EventIDExtractor.extract_SEIDS(origianFilePath, outputFilePathSE)
        EventIDExtractor.delete_empty_file(outputFilePathSE)

        if noFile:
            print(f"No ruleID files found for agent {agent_name}.")
            agent_ip = get_agent_ip(config["wazuh_api_url"], config["username_api"], config["password_api"], agent_name)
            custom_json = {
                "timestamp": start_date,
                "agent_ip": agent_ip,
                "abnormal_rate": None,
                "agent_name": agent_name,
                "abnormal_count": None,
                "abnormal_security_event": None,
                "abnormal_sequence": None,
            }
            formatted_json = json.dumps(custom_json, indent=4)
            if debug:
                print("Formatted JSON:")
                print(formatted_json)

            headers = {'Content-Type': 'application/json'}
            response = requests.post(es_url, headers=headers, data=formatted_json)

            if response.status_code == 201:
                print("Data successfully written to Elasticsearch")
            else:
                print(f"Failed to write data to Elasticsearch: {response.status_code} {response.text}")
            continue

        # Create preprocessor
        preprocessor = Preprocessor(
            length=10,    # 10 events in context
            timeout=86400, # Ignore events older than 1 day (60*60*24 = 86400 seconds)
        )

        # Load training data from file
        context_train, events_train, labels_train, mapping_train = preprocessor.text(
            path=data_path + '/convertDataTraining/wazuh_training_data',
            verbose=debug,
        )
        if debug:
            print(f"mapping_train:\n{mapping_train}\n")

        # Load test data from file
        context_test, events_test, labels_test, mapping_test = preprocessor.text(
            path = outputFilePathRule,
            verbose=debug,
        )
        if debug:
            print(f"mapping_test:\n{mapping_test}\n")

        # Load the saved model
        context_builder = ContextBuilder(
            input_size=40,
            output_size=40,
            hidden_size=128,
            max_length=10,
        )

        # Cast to cuda if available
        if torch.cuda.is_available():
            context_builder = context_builder.to('cuda')

        model_path = config["model_path"]
        context_builder.load_state_dict(torch.load(model_path))
        if debug:
            print("Model loaded successfully")

        # Use context builder to predict confidence
        confidence, _ = context_builder.predict(
            X=context_test
        )

        # Get confidence of the next step, seq_len 0 (n_samples, seq_len, output_size)
        confidence = confidence[:, 0]
        # Get confidence from log confidence
        confidence = confidence.exp()
        # Get prediction as maximum confidence
        y_pred = confidence.argmax(dim=1)

        # Get test and prediction as numpy array
        y_test = events_test.cpu().numpy()
        y_pred = y_pred.cpu().numpy()

        y_test = y_test.tolist()
        y_pred = y_pred.tolist()

        # 使用 mapping 進行轉換
        y_test = [mapping_test[key] for key in y_test]
        y_pred = [mapping_train[key] for key in y_pred]

        result = []
        abnormal_list = []
        for i in range(len(y_test)):
            if int(y_test[i]) == int(y_pred[i]):
                result.append(0)
            else:
                result.append(1)
                abnormal_list.append(i)

        # Calculate abnormal rate
        num_of_one = result.count(1)
        event_total = len(result)
        abnormal_rate = num_of_one / event_total

        if debug:
            print(f"\n異常量：{num_of_one}\n異常率：{abnormal_rate:.2f}\n")
            print(f"偵測結果：\n{result}\nsize: {len(result)}\n\n異常序列：\n{abnormal_list}\nsize: {len(abnormal_list)}\n")

        # 讀取SEID檔案內容
        SEID_file_path = outputFilePathSE
        with open(SEID_file_path, 'r') as file:
            data = file.read()

        # 根據空格分割數據並存儲在列表中
        SEID_list = data.split()

        abnormal_security_event = [SEID_list[i] for i in abnormal_list]

        if debug:
            print(f"Abnormal security event:\n{abnormal_security_event}\nsize: {len(abnormal_security_event)}\n")

        agent_ip = get_agent_ip(config["wazuh_api_url"], config["username_api"], config["password_api"], agent_name)

        start_date_utc = datetime.strptime(start_date, "%Y-%m-%dT%H:%M:%S%z").astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        # 寫入 Elasticsearch
        custom_json = {
            "timestamp": start_date_utc,
            "agent_name": agent_name,
            "agent_ip": agent_ip,
            "score": abnormal_rate,
            "event.total": event_total,
            "event.abnormal.count": num_of_one,
            "event.all.id": SEID_list,
            "event.abnormal.id": abnormal_security_event
        }

        formatted_json = json.dumps(custom_json, indent=4)
        if debug:
            print("Formatted JSON:")
            print(formatted_json)

        headers = {'Content-Type': 'application/json'}
        response = requests.post(es_url, headers=headers, data=formatted_json)

        if response.status_code == 201:
            print("Data successfully written to Elasticsearch")
        else:
            print(f"Failed to write data to Elasticsearch: {response.status_code} {response.text}")


    return formatted_json

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="choose the elk index")
    parser.add_argument("elkIndex", type=str, help="choose the elk index in str")
    parser.add_argument("group", type=str, help="choose the wazuh group in str")
    parsed_args = parser.parse_args()
    es_index = parsed_args.elkIndex
    group_name = parsed_args.group
    
    # 獲取當前 Python 檔案的路徑
    current_file_path = os.path.abspath(__file__)
    # 獲取當前 Python 檔案所在的目錄
    current_directory = os.path.dirname(current_file_path)
    config = load_config(current_directory + '/config.json')
    base_url = config["elasticsearch_url"]
    es_url = urljoin(base_url, f"{es_index}/_doc/")
    debug_mode = True
    results = main(config, debug=debug_mode)