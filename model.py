import os
import pandas as pd
import joblib
import pickle

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression

# 데이터셋
path = os.path.sep.join(["phishing_preprocessing111.csv"])
data = pd.read_csv(path)
print(data.columns)
x = data[['entropy', 'pathentropy', 'hostname_length', 'path_length',
          'tld_length', 'special_chacter', 'count-', 'count-@', 'count-http',
          'count-https', 'count-www', 'count-digit', 'count-letter', 'count_dir',
          'url_length', 'HavingIp', 'Iframe', 'SubmittingToEmail', 'Redirection',
          'google_index', 'UrlScript', 'UrlAtag', 'DomainRegistrationLength',
          'sfh', 'short_url_service', 'favicon']]
y = data["label"]

print(f"Shape of x --> {x.shape}")
print(f"Shape of y --> {y.shape}")
print("**********************************************")
X_train, X_test, y_train, y_test = train_test_split(x, y, test_size=0.3, random_state=777, shuffle=True, stratify=y)
# decisionTree fit ~ prediction
decision_modal = DecisionTreeClassifier()
decision_modal.fit(X_train, y_train)
joblib.dump(decision_modal, "../entropy_model/decision_model_requestVer2.pkl")
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
joblib.dump(forest_model, "forest_model_requestVer2.pkl")
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
logit_model_save = pickle.dumps(logit_model)
joblib.dump(logit_model, "../entropy_model/logit_model_requestVer2.pkl")
logit_prediction = logit_model.predict(X_test)
print("logit_prediction(일단 100개만) --> {}".format(logit_prediction[:101]))
print(f"Logistic Accuracy Score > %2f" % accuracy_score(y_test, logit_prediction))
print(f"Logistic Confusion_Matrix --->\n"
      f"{confusion_matrix(y_test, logit_prediction)}")
print(f"logit classification report -->\n"
      f"{classification_report(y_test, logit_prediction)}")
print("-----------------------------------------------------")
