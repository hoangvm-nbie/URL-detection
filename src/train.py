import pandas as pd
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import classification_report
from sklearn.metrics import precision_recall_fscore_support, accuracy_score
import matplotlib.pyplot as plt
from sklearn.metrics import ConfusionMatrixDisplay
import joblib
import os

# --- ĐỊNH NGHĨA THƯ MỤC LƯU TRỮ MỚI ---

BASE_DIR = r"D:\Downsload+\Train Ai"

# 1. Nạp dữ liệu từ đường dẫn mới
df = pd.read_csv(os.path.join(BASE_DIR, 'traindata.csv'))
X = df.drop(['url', 'status'], axis=1)
y = df['status'].replace(-1, 0) # Chuyển -1 thành 0 cho chuẩn

# 2. Chia Train/Test (8:2)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 3. Chạy SMOTE
sm = SMOTE(random_state=42)
X_res, y_res = sm.fit_resample(X_train, y_train)

# 4. Train 2 mô hình
nb_model = GaussianNB().fit(X_res, y_res)
rf_model = RandomForestClassifier(n_estimators=100, random_state=42).fit(X_res, y_res)

# 5. Xuất kết quả để so sánh 
print("--- Naive Bayes ---")
print(classification_report(y_test, nb_model.predict(X_test)))
print("--- Random Forest ---")
print(classification_report(y_test, rf_model.predict(X_test)))

# 6. 
joblib.dump(nb_model, 'naive_bayes_model.pkl')
joblib.dump(rf_model, 'random_forest_model.pkl')

# 7. Lấy Top 10 đặc trưng quan trọng 
importances = rf_model.feature_importances_
feat_importances = pd.Series(importances, index=X.columns)
print("\nTop 10 Đặc trưng quan trọng nhất:")
print(feat_importances.nlargest(10))

###-----------------------------------#####
# --- I. TÍNH TOÁN VÀ XUẤT FILE CSV SO SÁNH ---
y_pred_nb = nb_model.predict(X_test)
y_pred_rf = rf_model.predict(X_test)

nb_acc = accuracy_score(y_test, y_pred_nb)
nb_prec, nb_rec, nb_f1, _ = precision_recall_fscore_support(y_test, y_pred_nb, average='binary')

rf_acc = accuracy_score(y_test, y_pred_rf)
rf_prec, rf_rec, rf_f1, _ = precision_recall_fscore_support(y_test, y_pred_rf, average='binary')

results = pd.DataFrame({
    'Thuật toán': ['Naive Bayes', 'Random Forest'],
    'Accuracy': [nb_acc, rf_acc],
    'Precision': [nb_prec, rf_prec],
    'Recall': [nb_rec, rf_rec],
    'F1-Score': [nb_f1, rf_f1]
})
results.to_csv(os.path.join(BASE_DIR, 'ket_qua_so_sanh.csv'), index=False, encoding='utf-8-sig')

# --- II. VẼ VÀ LƯU BIỂU ĐỒ TẦM QUAN TRỌNG (Feature Importance) ---
plt.figure(figsize=(10, 6))
feat_importances.nlargest(10).sort_values(ascending=True).plot(kind='barh', color='orange')
plt.title('Top 10 Đặc trưng quan trọng nhất (Phát hiện bởi Random Forest)')
plt.xlabel('Mức độ ảnh hưởng')
plt.tight_layout()
plt.savefig(os.path.join(BASE_DIR, 'bieu_do_dac_trung.png'))
plt.close()

# --- III. VẼ VÀ LƯU MA TRẬN NHẦM LẪN (Confusion Matrix) ---

# 1. Ma trận cho Random Forest
plt.figure(figsize=(6, 5))
ConfusionMatrixDisplay.from_estimator(rf_model, X_test, y_test, display_labels=['Độc hại', 'An toàn'], cmap='Blues')
plt.title('Ma trận nhầm lẫn - Random Forest')
plt.tight_layout()
plt.savefig(os.path.join(BASE_DIR, 'ma_tran_nham_lan_rf.png'), dpi=300)
plt.close()

# 2. Ma trận cho Naive Bayes 
plt.figure(figsize=(6, 5))
ConfusionMatrixDisplay.from_estimator(nb_model, X_test, y_test, display_labels=['Độc hại', 'An toàn'], cmap='Oranges')
plt.title('Ma trận nhầm lẫn - Naive Bayes')
plt.tight_layout()
plt.savefig(os.path.join(BASE_DIR, 'ma_tran_nham_lan_nb.png'), dpi=300)
plt.close()

print(f" Hãy kiểm tra thư mục '{BASE_DIR}' để thấy 1 file CSV và 3 file ảnh .")