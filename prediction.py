import os
import json
import joblib
import datetime
import pandas as pd

from collections import OrderedDict


class ML:
    def __init__(self):
        self.csv_data = pd.read_csv(os.path.abspath("PhishingURL/Logistic/fdasdfsadfasdfasfasdfasdfs.csv"))
        self.x = self.csv_data[['hostname_length',
                                'path_length', 'fd_length', 'tld_length', 'count-', 'count-@', 'count-?',
                                'count%', 'count.', 'count=', 'count-http', 'count-https', 'count-www', 'count-digit',
                                'count-letter', 'count_dir', 'use_of_ip']]

    def TrainTest(self):
        prediction = joblib.load("PhishingURL/Logistic/forest_model.pkl")
        model_finally = prediction.predict_proba(self.x)
        return model_finally

    def DecisionPrediction(self):
        prediction = joblib.load("PhishingURL/Logistic/forest_model.pkl")
        binary_prediction = prediction.predict(self.x)
        return binary_prediction

    def PredictionData(self):
        web = [site for site in self.csv_data["url"]]
        predict_list = []
        for value in self.TrainTest():
            if value[0] > value[1]:
                predict_list.append("{}%".format(int(value[0] * 100)))
            else:
                predict_list.append("{}%".format(int(value[1] * 100)))

        making_log_data = OrderedDict()
        log_path = "log.json"
        f = open(log_path, "r", encoding="utf-8")
        dict_info = json.loads(f.read())
        making_log_data["Timestamp"] = f"{datetime.datetime.now()}"
        making_log_data["URL"] = f"url sample"
        making_log_data["detection"] = True

        making_log_data["module"] = "ML_PhishingDetected"
        making_log_data["log"] = []

        for i in range(0, len(web)):
            # 실제 하나 당 로그는 이 아래에서
            logdata = {"submodule": 0,
                       "external_url": f"{web[i]}",
                       "result": f'{self.DecisionPrediction()[i]}',
                       "percentage": f"{predict_list[i]}"
                       }
            making_log_data["log"].append(logdata)

            print(json.dumps(making_log_data, ensure_ascii=False, indent="\t"))

            f.close()
            f = open(log_path, "w", encoding="utf8")
            dict_info.append(making_log_data)
            f.write(json.dumps(dict_info, ensure_ascii=False, indent='\t'))


if __name__ == "__main__":
    ML().PredictionData()
