import os
import pandas as pd
import numpy as np
import pickle
import matplotlib.pyplot as plt

from sklearn.manifold import TSNE
from lightgbm import LGBMClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression

# 데이터셋
path = os.path.sep.join(["url_sample.csv"])
data = pd.read_csv(path)

x = data[['hostname_length',
          'path_length', 'fd_length', 'tld_length', 'count-', 'count@', 'count?',
          'count%', 'count.', 'count=', 'count-http', 'count-https', 'count-www', 'count-digits',
          'count-letters', 'count_dir', 'use_of_ip']]
y = data["result"]

print(f"Shape of x --> {x.shape}")
print(f"Shape of y --> {y.shape}")
print("**********************************************")
X_train, X_test, y_train, y_test = train_test_split(x, y, train_size=0.3, random_state=2020)
# decisionTree fit ~ prediction
decision_modal = DecisionTreeClassifier()
decision_modal.fit(X_train, y_train)

decision_prediction = decision_modal.predict(X_test)
print("decision_prediction(일단 100개만) --> {}".format(decision_prediction[:101]))
print("Decision Accuracy Score > %.2f" % accuracy_score(y_test, decision_prediction))
print(f"Decision Confusion_Matrix --->\n"
      f"{confusion_matrix(y_test, decision_prediction)}")
print(f"decision classification report -->\n"
      f"{classification_report(y_test, decision_prediction)}")
print("-----------------------------------------------------")

# Random Forest ~ prediction
forest_model = RandomForestClassifier()
forest_model.fit(X_train, y_train)
forest_model_save = pickle.dumps(forest_model)

forest_prediction = forest_model.predict(X_test)
print("forest_prediction(일단 100개만) --> {}".format(forest_prediction[:101]))
print("Forest Accuracy Score > %2f" % accuracy_score(y_test, forest_prediction))
print(f"Forest Confusion_Matrix --->\n"
      f"{confusion_matrix(y_test, forest_prediction)}")
print(f"forest classification report -->\n"
      f"{classification_report(y_test, forest_prediction)}")
print("-----------------------------------------------------")

# Logistic ~ prediction
logit_model = LogisticRegression(max_iter=10000)
logit_model.fit(X_train, y_train)

logit_prediction = logit_model.predict(X_test)
print("logit_prediction(일단 100개만) --> {}".format(logit_prediction[:101]))
print(f"Logistic Accuracy Score > %2f" % accuracy_score(y_test, logit_prediction))
print(f"Logistic Confusion_Matrix --->\n"
      f"{confusion_matrix(y_test, logit_prediction)}")
print(f"logit classification report -->\n"
      f"{classification_report(y_test, logit_prediction)}")
print("-----------------------------------------------------")

# ensemble
collection_model = np.array([decision_prediction, forest_prediction, logit_prediction])
print(f"collection model shape --> {collection_model.shape}")
T_model = np.transpose(collection_model)
print(f"transpose Shape of data --> {T_model.shape}")

lgbm = LGBMClassifier()
lgbm.fit(T_model, y_test)
lgbm_prediction = lgbm.predict(T_model)

print("lgbm_prediction(일단 100개만) --> {}".format(lgbm_prediction[:101]))
print("ACC of lgbm --> %2f " % accuracy_score(y_test, lgbm_prediction))
print(f"lgbm classification report -->\n"
      f"{classification_report(y_test, lgbm_prediction)}")
